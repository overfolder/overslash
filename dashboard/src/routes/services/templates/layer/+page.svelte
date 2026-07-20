<script lang="ts">
	import { goto } from '$app/navigation';
	import { ApiError } from '$lib/session';
	import { createTemplate, updateTemplate, deleteTemplate, validateDelta } from '$lib/api/services';
	import type {
		Delta,
		InstanceDefaults,
		ValidationResult,
		ActionSummary,
		InstanceConfigParam
	} from '$lib/types';
	import ConfirmDialog from '$lib/components/services/ConfirmDialog.svelte';
	import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';

	let { data } = $props();

	// Page data is stable for the lifetime of this route render (a fresh load
	// runs on navigation), so capturing it once is intentional.
	/* eslint-disable svelte/no-state-referenced-locally */
	// svelte-ignore state_referenced_locally
	const base = data.base;
	// svelte-ignore state_referenced_locally
	const baseKey = data.baseKey;
	// svelte-ignore state_referenced_locally
	const editing = !!data.layer;
	// svelte-ignore state_referenced_locally
	const existingId = data.layer?.id;
	// svelte-ignore state_referenced_locally
	const existingDelta: Delta = data.layer?.delta ?? {};

	// Base action list (the effective surface we mask over).
	const baseActions: ActionSummary[] = base?.actions ?? [];

	// ── Editable state, seeded from the existing delta when editing ──────────
	// svelte-ignore state_referenced_locally
	let layerKey = $state(data.layer?.key ?? baseKey);
	// The key is only editable while creating; it's part of the title with an
	// inline pencil rather than a form field.
	let keyEditing = $state(false);
	// svelte-ignore state_referenced_locally
	let displayName = $state(data.layer?.display_name ?? base?.display_name ?? '');
	// Seeded from the layer's own tier when editing, so live validation folds
	// over the same base the save will — and so an existing user layer isn't
	// offered org-only controls.
	// svelte-ignore state_referenced_locally
	let scope = $state<'org' | 'user'>(data.layer?.tier === 'user' ? 'user' : 'org');

	// Catalog visibility (`delta.hidden`) is now managed from the catalog admin
	// view, not this editor. Carry any existing value forward so saving the
	// delta here never silently un-hides a layer.
	const inheritedHidden = existingDelta.hidden ?? false;

	// Allowed action keys. Seed: an existing allowlist, else all base actions
	// minus any denylist. Toggling a checkbox off excludes the action.
	function seedAllowed(): Set<string> {
		const all = baseActions.map((a) => a.key);
		if (existingDelta.allowlist) return new Set(existingDelta.allowlist);
		const deny = new Set(existingDelta.denylist ?? []);
		return new Set(all.filter((k) => !deny.has(k)));
	}
	// svelte-ignore state_referenced_locally
	let allowed = $state<Set<string>>(seedAllowed());

	// Per-action risk clamp (inherit | write | delete).
	function seedRisk(): Record<string, string> {
		const out: Record<string, string> = {};
		for (const [k, patch] of Object.entries(existingDelta.action_patch ?? {})) {
			if (patch?.risk) out[k] = patch.risk;
		}
		return out;
	}
	// svelte-ignore state_referenced_locally
	let riskOverride = $state<Record<string, string>>(seedRisk());

	// ── Instance defaults (org layers only) ─────────────────────────────────
	// Params the base declares `x-overslash-instance-config` — one row each, so
	// an admin can pre-fill what would otherwise be per-user typing.
	const pinnableParams: InstanceConfigParam[] = base?.instance_config_params ?? [];
	// svelte-ignore state_referenced_locally
	let defaultUrl = $state(existingDelta.instance_defaults?.url ?? '');
	// svelte-ignore state_referenced_locally
	let defaultConfig = $state<Record<string, string>>({
		...(existingDelta.instance_defaults?.config ?? {})
	});
	// The endpoint field only makes sense where the endpoint is a per-deployment
	// concern in the first place — the same signal the instance form uses.
	const showDefaultUrl = base?.configurable_url === true;
	const canSetDefaults = $derived(scope === 'org' && (showDefaultUrl || pinnableParams.length > 0));

	// Advanced escape hatch: raw extensions JSON (actions + hosts).
	// svelte-ignore state_referenced_locally
	let extensionsText = $state(
		existingDelta.extensions ? JSON.stringify(existingDelta.extensions, null, 2) : ''
	);
	let showAdvanced = $state(false);

	let saving = $state(false);
	let error = $state<string | null>(null);
	let success = $state<string | null>(null);
	let validation = $state<ValidationResult | null>(null);
	let pendingDelete = $state(false);

	function toggleAction(key: string, on: boolean) {
		const next = new Set(allowed);
		if (on) next.add(key);
		else next.delete(key);
		allowed = next;
	}

	// Rank so a clamp-up dropdown only offers >= the base risk.
	const RISK_RANK: Record<string, number> = { read: 0, write: 1, delete: 2 };
	function clampOptions(baseRisk: string): string[] {
		const floor = RISK_RANK[baseRisk] ?? 0;
		return ['read', 'write', 'delete'].filter((r) => RISK_RANK[r] >= floor);
	}

	/** Build the delta from the current form state. */
	function buildDelta(): Delta {
		const delta: Delta = {};
		const allKeys = baseActions.map((a) => a.key);
		const allowedCount = allKeys.filter((k) => allowed.has(k)).length;
		// Only emit an allowlist when the admin has actually trimmed something —
		// otherwise inherit the full (live) base surface.
		if (allowedCount < allKeys.length) {
			delta.allowlist = allKeys.filter((k) => allowed.has(k));
		}
		// action_patch: risk clamp-ups only (must be >= base risk).
		const patch: Record<string, { risk?: 'read' | 'write' | 'delete' }> = {};
		for (const a of baseActions) {
			const ov = riskOverride[a.key];
			if (ov && ov !== a.risk && (RISK_RANK[ov] ?? 0) > (RISK_RANK[a.risk] ?? 0)) {
				patch[a.key] = { risk: ov as 'read' | 'write' | 'delete' };
			}
		}
		if (Object.keys(patch).length) delta.action_patch = patch;
		// Visibility is toggled from the catalog; preserve any existing value.
		if (inheritedHidden) delta.hidden = true;
		if (displayName && displayName !== base?.display_name) delta.display_name = displayName;
		if (extensionsText.trim()) {
			delta.extensions = JSON.parse(extensionsText);
		}
		// A PUT replaces the whole delta, so anything this form does not render
		// must be carried forward explicitly or it is destroyed on save. When the
		// section is hidden (user scope, or a base with nothing to default) that
		// means passing any existing value through untouched.
		if (canSetDefaults) {
			const defaults: InstanceDefaults = {};
			if (defaultUrl.trim()) defaults.url = defaultUrl.trim();
			const config: Record<string, string> = {};
			for (const p of pinnableParams) {
				const v = defaultConfig[p.name]?.trim();
				if (v) config[p.name] = v;
			}
			if (Object.keys(config).length) defaults.config = config;
			if (defaults.url || defaults.config) delta.instance_defaults = defaults;
		} else if (existingDelta.instance_defaults) {
			delta.instance_defaults = existingDelta.instance_defaults;
		}
		return delta;
	}

	// Debounced live validation.
	let validateTimer: ReturnType<typeof setTimeout> | undefined;
	$effect(() => {
		// Track the inputs so this re-runs on change.
		void allowed;
		void riskOverride;
		void displayName;
		void extensionsText;
		void scope;
		void defaultUrl;
		void defaultConfig;
		clearTimeout(validateTimer);
		validateTimer = setTimeout(async () => {
			try {
				const delta = buildDelta();
				validation = await validateDelta(baseKey, delta, scope === 'user');
			} catch {
				validation = {
					valid: false,
					errors: [{ message: 'Advanced extensions JSON is not valid JSON', path: 'extensions' }],
					warnings: []
				};
			}
		}, 300);
		return () => clearTimeout(validateTimer);
	});

	async function save() {
		saving = true;
		error = null;
		success = null;
		let delta: Delta;
		try {
			delta = buildDelta();
		} catch {
			error = 'Advanced extensions JSON is not valid JSON.';
			saving = false;
			return;
		}
		try {
			if (editing && existingId) {
				await updateTemplate(existingId, { delta });
				success = 'Layer saved.';
			} else {
				const created = await createTemplate({
					extends: baseKey,
					delta,
					key: layerKey,
					display_name: displayName || undefined,
					user_level: scope === 'user'
				});
				await goto(`/services/templates/layer?edit=${encodeURIComponent(created.key)}`, {
					invalidateAll: true
				});
				return;
			}
			setTimeout(() => (success = null), 3000);
		} catch (e) {
			error = extractError(e);
		} finally {
			saving = false;
		}
	}

	function extractError(e: unknown): string {
		if (e instanceof ApiError) {
			const report = (e as any).body?.report;
			if (report?.errors?.length) {
				return report.errors.map((x: any) => `${x.path ?? ''} ${x.message ?? ''}`.trim()).join('; ');
			}
			return (e as any).body?.error ?? `Request failed (${e.status})`;
		}
		return 'Failed to save layer';
	}

	async function confirmDelete() {
		if (!existingId) return;
		pendingDelete = false;
		try {
			await deleteTemplate(existingId);
			await goto('/services?tab=catalog');
		} catch (e) {
			error = extractError(e);
		}
	}
</script>

<svelte:head><title>{editing ? 'Edit' : 'New'} layer — Overslash</title></svelte:head>

<div class="page">
	<header class="page-head">
		<div class="breadcrumb">
			<a href="/services?tab=catalog" class="back">Catalog</a>
			<span class="sep">/</span>
			<span>{editing ? 'Edit layer' : 'Customize'}: {base?.display_name ?? baseKey}</span>
		</div>
		<div class="title-row">
			{#if keyEditing}
				<input
					class="key-input"
					type="text"
					bind:value={layerKey}
					placeholder={baseKey}
					onblur={() => (keyEditing = false)}
					onkeydown={(e) => {
						if (e.key === 'Enter' || e.key === 'Escape') keyEditing = false;
					}}
				/>
			{:else}
				<h1 class="layer-key">{layerKey}</h1>
				{#if !editing}
					<button
						type="button"
						class="key-edit"
						title="Edit key"
						aria-label="Edit layer key"
						onclick={() => (keyEditing = true)}
					>
						✎
					</button>
				{/if}
			{/if}
		</div>
		<p class="subtitle">
			A <strong>layer</strong> curates its base
			(<code>{baseKey}</code>) while tracking upstream updates. Trim actions, raise
			risk, or relabel — the base is never copied.
		</p>
	</header>

	{#if !base}
		<div class="error">No base template. Open this editor from a catalog template's “Customize”.</div>
	{:else}
		{#if error}<div class="error">{error}</div>{/if}
		{#if success}<div class="success">{success}</div>{/if}

		<section class="card">
			<div class="field-row">
				<label class="field">
					<span class="lbl">Display name</span>
					<input type="text" bind:value={displayName} placeholder={base.display_name} />
				</label>
				{#if !editing}
					<label class="field narrow">
						<span class="lbl">Scope</span>
						<select bind:value={scope}>
							<option value="org">Org (admin)</option>
							<option value="user">Just me</option>
						</select>
					</label>
				{/if}
			</div>
		</section>

		<section class="card">
			<div class="card-head">
				<h2>Actions</h2>
				<div class="bulk">
					<button type="button" class="link" onclick={() => (allowed = new Set(baseActions.map((a) => a.key)))}>Select all</button>
					<button type="button" class="link" onclick={() => (allowed = new Set())}>Select none</button>
				</div>
			</div>
			<p class="card-desc">
				Actions toggled off are removed from the effective template — they vanish
				from discovery <em>and</em> execution. New tools an autodiscovered base adds
				later stay excluded until you allow them.
			</p>
			<ul class="action-list">
				{#each baseActions as a (a.key)}
					<li class="action-row" class:excluded={!allowed.has(a.key)}>
						<div class="action-main">
							<ToggleSwitch
								checked={allowed.has(a.key)}
								onchange={(next) => toggleAction(a.key, next)}
								size="sm"
								label={`Include ${a.key}`}
							/>
							<span class="action-key">{a.key}</span>
							<!-- Short label in the row; the long agent-facing text on hover. -->
							<span class="action-desc" title={a.summary ? a.description : undefined}
								>{a.summary ?? a.description}</span
							>
						</div>
						<div class="action-risk">
							<span class="base-risk risk-{a.risk}">{a.risk}</span>
							{#if allowed.has(a.key) && clampOptions(a.risk).length > 1}
								<select
									value={riskOverride[a.key] ?? a.risk}
									onchange={(e) =>
										(riskOverride = {
											...riskOverride,
											[a.key]: (e.currentTarget as HTMLSelectElement).value
										})}
									title="Raise risk (adds approvals). Cannot lower."
								>
									{#each clampOptions(a.risk) as r}
										<option value={r}>{r}</option>
									{/each}
								</select>
							{/if}
						</div>
					</li>
				{/each}
			</ul>
		</section>

		{#if canSetDefaults}
			<section class="card">
				<div class="card-head"><h2>Instance defaults</h2></div>
				<p class="card-desc">
					Pre-fill what every service created from this layer would otherwise be
					asked for. A service that sets its own value still wins, so one person
					can point at a different deployment without affecting anyone else.
				</p>
				{#if showDefaultUrl}
					<label class="field">
						<span class="lbl">Endpoint URL</span>
						<input
							type="url"
							bind:value={defaultUrl}
							placeholder={base?.hosts?.[0] ? `https://${base.hosts[0]}` : 'https://gateway.example.com'}
						/>
						<span class="hint">
							Your org's own deployment. Leave blank to use the template's default.
						</span>
					</label>
				{/if}
				{#each pinnableParams as p (p.name)}
					<label class="field">
						<span class="lbl">{p.name}</span>
						<input
							type="text"
							value={defaultConfig[p.name] ?? ''}
							oninput={(e) =>
								(defaultConfig = {
									...defaultConfig,
									[p.name]: (e.currentTarget as HTMLInputElement).value
								})}
						/>
						{#if p.description}<span class="hint">{p.description}</span>{/if}
					</label>
				{/each}
			</section>
		{/if}

		<section class="card">
			<button type="button" class="advanced-toggle" onclick={() => (showAdvanced = !showAdvanced)}>
				{showAdvanced ? '▾' : '▸'} Advanced — extensions (add actions / hosts)
			</button>
			{#if showAdvanced}
				<p class="card-desc">
					Add new actions and hosts as an OpenAPI-fragment JSON delta
					(<code>extensions</code>). Extensions may only add keys — they cannot
					change auth or rebind a base action.
				</p>
				<textarea
					class="ext-editor"
					bind:value={extensionsText}
					spellcheck="false"
					placeholder={'{\n  "actions": {\n    "archive_repo": { "method": "POST", "path": "/repos/archive", "operation": { "description": "Archive", "x-overslash-risk": "write" } }\n  },\n  "hosts": ["ghe.acme.internal"]\n}'}
				></textarea>
			{/if}
		</section>

		{#if validation && (validation.errors.length || validation.warnings.length)}
			<section class="card report">
				{#each validation.errors as m}
					<div class="msg err"><span class="code">{m.code ?? 'error'}</span> {m.message}</div>
				{/each}
				{#each validation.warnings as m}
					<div class="msg warn"><span class="code">{m.code ?? 'warning'}</span> {m.message}</div>
				{/each}
			</section>
		{/if}

		<footer class="editor-footer">
			{#if editing}
				<button type="button" class="btn danger" onclick={() => (pendingDelete = true)}>Delete</button>
			{/if}
			<div class="footer-right">
				<button
					type="button"
					class="btn primary"
					onclick={save}
					disabled={saving || (!!validation && !validation.valid)}
				>
					{saving ? 'Saving…' : editing ? 'Save layer' : 'Create layer'}
				</button>
			</div>
		</footer>
	{/if}
</div>

<ConfirmDialog
	open={pendingDelete}
	title="Delete layer?"
	message="Delete this layer? Instances derived from it lose their customization. This cannot be undone."
	confirmLabel="Delete"
	danger
	onconfirm={confirmDelete}
	oncancel={() => (pendingDelete = false)}
/>

<style>
	.page {
		max-width: 860px;
	}
	.page-head {
		margin-bottom: 1rem;
	}
	.breadcrumb {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		font-size: 0.9rem;
		flex-wrap: wrap;
	}
	.back {
		color: var(--color-primary, #6366f1);
		text-decoration: none;
		font-weight: 500;
	}
	.sep {
		color: var(--color-text-muted);
	}
	.title-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-top: 0.4rem;
	}
	.layer-key {
		margin: 0;
		font-family: var(--font-mono, monospace);
		font-size: 1.4rem;
		font-weight: 700;
	}
	.key-edit {
		background: none;
		border: none;
		cursor: pointer;
		font-size: 1rem;
		color: var(--color-text-muted);
		padding: 0.1rem 0.3rem;
		border-radius: 4px;
		line-height: 1;
	}
	.key-edit:hover {
		color: var(--color-primary, #6366f1);
		background: var(--color-bg-muted, rgba(0, 0, 0, 0.04));
	}
	.key-input {
		font-family: var(--font-mono, monospace);
		font-size: 1.3rem;
		font-weight: 700;
		padding: 0.15rem 0.4rem;
		border: 1px solid var(--color-primary, #6366f1);
		border-radius: 5px;
		background: var(--color-bg, #fff);
		color: inherit;
		min-width: 12rem;
	}
	.subtitle {
		margin: 0.5rem 0 0;
		font-size: 0.82rem;
		color: var(--color-text-muted);
	}
	code {
		font-size: 0.78rem;
		background: var(--color-bg-muted, rgba(0, 0, 0, 0.04));
		padding: 0 0.3em;
		border-radius: 3px;
	}
	.card {
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 1rem;
		margin-bottom: 1rem;
		background: var(--color-surface, transparent);
	}
	.card-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.card-head h2 {
		margin: 0;
		font-size: 1rem;
	}
	.card-desc {
		margin: 0.35rem 0 0.75rem;
		font-size: 0.8rem;
		color: var(--color-text-muted);
	}
	.field-row {
		display: flex;
		gap: 1rem;
		flex-wrap: wrap;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
		flex: 1;
		min-width: 220px;
	}
	.field.narrow {
		flex: 0 0 160px;
		min-width: 160px;
	}
	.field + .field {
		margin-top: 0.75rem;
	}
	.hint {
		font-size: 0.75rem;
		color: var(--color-text-muted);
	}
	.lbl {
		font-size: 0.8rem;
		font-weight: 600;
	}
	.field input,
	.field select,
	.action-risk select {
		padding: 0.4rem 0.55rem;
		border: 1px solid var(--color-border);
		border-radius: 5px;
		font: inherit;
		font-size: 0.85rem;
		background: var(--color-bg, #fff);
		color: inherit;
	}
	.field input:disabled {
		opacity: 0.6;
	}
	.bulk {
		display: flex;
		gap: 0.6rem;
	}
	.link {
		background: none;
		border: none;
		color: var(--color-primary, #6366f1);
		cursor: pointer;
		font: inherit;
		font-size: 0.8rem;
		padding: 0;
	}
	.action-list {
		list-style: none;
		margin: 0;
		padding: 0;
		border: 1px solid var(--color-border);
		border-radius: 6px;
	}
	.action-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
		padding: 0.5rem 0.7rem;
		border-bottom: 1px solid var(--color-border);
	}
	.action-row:last-child {
		border-bottom: none;
	}
	.action-row.excluded {
		opacity: 0.5;
	}
	.action-main {
		display: flex;
		align-items: baseline;
		gap: 0.55rem;
		cursor: pointer;
		min-width: 0;
		flex: 1;
	}
	.action-key {
		font-family: var(--font-mono, monospace);
		font-size: 0.82rem;
		font-weight: 600;
		white-space: nowrap;
	}
	.action-desc {
		font-size: 0.78rem;
		color: var(--color-text-muted);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.action-risk {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		flex-shrink: 0;
	}
	.base-risk {
		font-size: 0.68rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		padding: 0.1rem 0.35rem;
		border-radius: 4px;
		border: 1px solid var(--color-border);
	}
	.risk-write {
		color: #b45309;
		border-color: rgba(180, 83, 9, 0.35);
	}
	.risk-delete {
		color: #b91c1c;
		border-color: rgba(185, 28, 28, 0.35);
	}
	.advanced-toggle {
		background: none;
		border: none;
		font: inherit;
		font-size: 0.85rem;
		font-weight: 600;
		cursor: pointer;
		color: inherit;
		padding: 0;
	}
	.ext-editor {
		width: 100%;
		min-height: 160px;
		margin-top: 0.6rem;
		font-family: var(--font-mono, monospace);
		font-size: 0.8rem;
		padding: 0.6rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-bg, #fff);
		color: inherit;
		resize: vertical;
	}
	.report .msg {
		font-size: 0.8rem;
		padding: 0.35rem 0;
	}
	.report .code {
		font-family: var(--font-mono, monospace);
		font-size: 0.72rem;
		padding: 0.05rem 0.3rem;
		border-radius: 3px;
		margin-right: 0.4rem;
	}
	.msg.err {
		color: #b91c1c;
	}
	.msg.err .code {
		background: rgba(185, 28, 28, 0.12);
	}
	.msg.warn {
		color: #b45309;
	}
	.msg.warn .code {
		background: rgba(180, 83, 9, 0.12);
	}
	.editor-footer {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-top: 0.5rem;
	}
	.footer-right {
		margin-left: auto;
	}
	.btn {
		padding: 0.5rem 1rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: var(--color-text);
		cursor: pointer;
		font: inherit;
		font-size: 0.85rem;
	}
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn.primary {
		background: var(--color-primary, #6366f1);
		color: white;
		border-color: var(--color-primary, #6366f1);
	}
	.btn.danger {
		color: #b91c1c;
		border-color: rgba(220, 38, 38, 0.35);
	}
	.error {
		background: rgba(220, 38, 38, 0.08);
		border: 1px solid rgba(220, 38, 38, 0.3);
		color: #b91c1c;
		border-radius: 6px;
		padding: 0.6rem 0.9rem;
		margin-bottom: 1rem;
		font-size: 0.85rem;
	}
	.success {
		background: rgba(34, 197, 94, 0.08);
		border: 1px solid rgba(34, 197, 94, 0.3);
		color: #15803d;
		border-radius: 6px;
		padding: 0.6rem 0.9rem;
		margin-bottom: 1rem;
		font-size: 0.85rem;
	}
</style>

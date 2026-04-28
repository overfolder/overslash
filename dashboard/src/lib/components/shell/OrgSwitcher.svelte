<script lang="ts">
	import { ApiError, session, type MembershipSummary } from '$lib/session';

	function errorCode(e: unknown): string {
		if (e instanceof ApiError) {
			const body = e.body as { error?: string; message?: string } | undefined;
			return body?.error ?? body?.message ?? `http_${e.status}`;
		}
		return e instanceof Error ? e.message : 'unknown_error';
	}

	type Props = {
		memberships: MembershipSummary[];
		currentOrgId: string;
		collapsed?: boolean;
	};

	let { memberships, currentOrgId, collapsed = false }: Props = $props();

	let open = $state(false);
	let switching = $state(false);
	let error: string | null = $state(null);

	let createOpen = $state(false);
	let createName = $state('');
	let createSlug = $state('');
	let createSlugTouched = $state(false);
	let creating = $state(false);
	let createError: string | null = $state(null);

	type SlugCheck =
		| { kind: 'idle' }
		| { kind: 'checking' }
		| { kind: 'available' }
		| { kind: 'invalid'; reason: string };
	let slugCheck = $state<SlugCheck>({ kind: 'idle' });
	let slugCheckTimer: ReturnType<typeof setTimeout> | null = null;
	let slugCheckSeq = 0;

	const SLUG_REASONS: Record<string, string> = {
		slug_too_short: 'Slug must be at least 2 characters.',
		slug_too_long: 'Slug must be at most 63 characters.',
		slug_invalid_chars: 'Only lowercase letters, digits, and hyphens.',
		slug_leading_or_trailing_hyphen: 'No leading or trailing hyphens.',
		slug_reserved: 'This slug is reserved.',
		slug_taken: 'Already taken.',
		lookup_failed: 'Could not verify slug — try again.'
	};

	function describeSlugReason(code: string): string {
		return SLUG_REASONS[code] ?? code;
	}

	const current = $derived(memberships.find((m) => m.org_id === currentOrgId));
	const personalMemberships = $derived(memberships.filter((m) => m.is_personal));
	const orgMemberships = $derived(memberships.filter((m) => !m.is_personal));

	async function selectOrg(orgId: string) {
		if (orgId === currentOrgId || switching) return;
		switching = true;
		error = null;
		try {
			const res = await session.post<{ redirect_to?: string }>('/auth/switch-org', {
				org_id: orgId
			});
			// Hard-reload on the returned URL (different subdomain for corp orgs).
			// If the server didn't give one (self-hosted single-host), just reload
			// the current page to pick up the new session cookie.
			if (res?.redirect_to) {
				window.location.href = res.redirect_to;
			} else {
				window.location.reload();
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to switch org';
			switching = false;
		}
	}

	function toggle() {
		open = !open;
	}

	function slugify(raw: string): string {
		return raw
			.toLowerCase()
			.replace(/[^a-z0-9-]+/g, '-')
			.replace(/^-+|-+$/g, '')
			.slice(0, 63);
	}

	function scheduleSlugCheck(slug: string) {
		if (slugCheckTimer) clearTimeout(slugCheckTimer);
		if (!slug) {
			slugCheck = { kind: 'idle' };
			return;
		}
		slugCheck = { kind: 'checking' };
		const seq = ++slugCheckSeq;
		slugCheckTimer = setTimeout(async () => {
			try {
				const res = await session.get<{ available: boolean; reason?: string }>(
					`/v1/orgs/check-slug?slug=${encodeURIComponent(slug)}`
				);
				if (seq !== slugCheckSeq) return;
				slugCheck = res.available
					? { kind: 'available' }
					: { kind: 'invalid', reason: res.reason ?? 'slug_invalid' };
			} catch {
				if (seq !== slugCheckSeq) return;
				slugCheck = { kind: 'invalid', reason: 'lookup_failed' };
			}
		}, 300);
	}

	function onNameInput(e: Event) {
		const value = (e.currentTarget as HTMLInputElement).value;
		createName = value;
		if (!createSlugTouched) {
			createSlug = slugify(value);
			scheduleSlugCheck(createSlug);
		}
	}

	function onSlugInput(e: Event) {
		createSlug = (e.currentTarget as HTMLInputElement).value;
		createSlugTouched = true;
		scheduleSlugCheck(createSlug);
	}

	// If the user wiped the slug and tabs away, re-enable autogen from the
	// current name so the field doesn't stay blank when they expected it to
	// re-sync.
	function onSlugBlur() {
		if (createSlug.trim() === '') {
			createSlugTouched = false;
			createSlug = slugify(createName);
			scheduleSlugCheck(createSlug);
		}
	}

	function openCreate() {
		open = false;
		createName = '';
		createSlug = '';
		createSlugTouched = false;
		createError = null;
		slugCheck = { kind: 'idle' };
		createOpen = true;
	}

	function closeCreate() {
		if (creating) return;
		if (slugCheckTimer) clearTimeout(slugCheckTimer);
		createOpen = false;
	}

	const canSubmit = $derived(
		!creating &&
			createName.trim() !== '' &&
			createSlug.trim() !== '' &&
			slugCheck.kind === 'available'
	);

	async function submitCreate(e: Event) {
		e.preventDefault();
		if (!canSubmit) return;
		const name = createName.trim();
		const slug = createSlug.trim();
		creating = true;
		createError = null;
		try {
			const res = await session.post<{ redirect_to?: string }>('/v1/orgs', { name, slug });
			if (res?.redirect_to) {
				window.location.href = res.redirect_to;
			} else {
				window.location.reload();
			}
		} catch (e) {
			// Surface the backend's error code (e.g. `slug_taken`,
			// `org_creation_disabled`). If it's slug-shaped, re-sync the live
			// slug indicator so the user sees it on the field too.
			const code = errorCode(e);
			if (code === 'slug_taken' || code.startsWith('slug_')) {
				slugCheck = { kind: 'invalid', reason: code };
				createError = describeSlugReason(code);
			} else if (code === 'org_creation_disabled') {
				createError = 'Org creation is disabled on this deployment.';
			} else if (code === 'team_org_requires_subscription') {
				window.location.href = '/billing/new-team';
				return;
			} else if (code.startsWith('http_')) {
				createError = `Could not create org (${code.slice(5)}). Try again.`;
			} else {
				createError = describeSlugReason(code) === code ? code : describeSlugReason(code);
			}
			creating = false;
		}
	}
</script>

<div class="switcher" class:collapsed>
	<button
		class="trigger"
		type="button"
		onclick={toggle}
		aria-haspopup="listbox"
		aria-expanded={open}
	>
		{#if current}
			<span class="name">{collapsed ? current.slug.charAt(0).toUpperCase() : current.name}</span>
		{:else}
			<span class="name">{collapsed ? '?' : 'No org'}</span>
		{/if}
		{#if !collapsed}
			<span class="chev" aria-hidden="true">▾</span>
		{/if}
	</button>

	{#if open && !collapsed}
		<div class="menu" role="listbox">
			{#if personalMemberships.length > 0}
				<div class="group-label">Personal</div>
				{#each personalMemberships as m (m.org_id)}
					<button
						class="item"
						class:active={m.org_id === currentOrgId}
						type="button"
						role="option"
						aria-selected={m.org_id === currentOrgId}
						disabled={switching}
						onclick={() => selectOrg(m.org_id)}
					>
						<span class="item-name">{m.name}</span>
					</button>
				{/each}
			{/if}

			{#if orgMemberships.length > 0}
				<div class="group-label">Orgs</div>
				{#each orgMemberships as m (m.org_id)}
					<button
						class="item"
						class:active={m.org_id === currentOrgId}
						type="button"
						role="option"
						aria-selected={m.org_id === currentOrgId}
						disabled={switching}
						onclick={() => selectOrg(m.org_id)}
					>
						<span class="item-name">{m.name}</span>
					</button>
				{/each}
			{/if}

			<div class="sep" role="separator"></div>
			<button class="item new" type="button" onclick={openCreate}>
				<span class="item-name">+ New organization</span>
			</button>

			{#if error}
				<div class="error">{error}</div>
			{/if}
		</div>
	{/if}
</div>

<svelte:window onkeydown={(e) => createOpen && e.key === 'Escape' && closeCreate()} />

{#if createOpen}
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div
		class="backdrop"
		role="dialog"
		aria-modal="true"
		aria-labelledby="create-org-title"
		tabindex="-1"
		onclick={(e) => {
			if (e.target === e.currentTarget) closeCreate();
		}}
	>
		<form class="card" onsubmit={submitCreate}>
			<h2 id="create-org-title">New organization</h2>
			<label>
				<span>Name</span>
				<!-- svelte-ignore a11y_autofocus -->
				<input
					type="text"
					value={createName}
					oninput={onNameInput}
					placeholder="Acme Inc."
					required
					disabled={creating}
					autofocus
				/>
			</label>
			<label>
				<span>Slug</span>
				<input
					type="text"
					value={createSlug}
					oninput={onSlugInput}
					onblur={onSlugBlur}
					placeholder="acme"
					pattern="[a-z0-9-]+"
					required
					disabled={creating}
					aria-invalid={slugCheck.kind === 'invalid'}
				/>
				{#if slugCheck.kind === 'checking'}
					<span class="slug-status checking">Checking…</span>
				{:else if slugCheck.kind === 'available'}
					<span class="slug-status ok">✓ Available</span>
				{:else if slugCheck.kind === 'invalid'}
					<span class="slug-status bad">{describeSlugReason(slugCheck.reason)}</span>
				{:else}
					<span class="hint">Used in the org's subdomain. Lowercase letters, digits, hyphens.</span>
				{/if}
			</label>
			{#if createError}
				<div class="error">{createError}</div>
			{/if}
			<div class="actions">
				<button type="button" class="btn" disabled={creating} onclick={closeCreate}>Cancel</button>
				<button type="submit" class="btn btn-primary" disabled={!canSubmit}>
					{creating ? 'Creating…' : 'Create'}
				</button>
			</div>
		</form>
	</div>
{/if}

<style>
	.switcher {
		position: relative;
	}
	.trigger {
		width: 100%;
		display: flex;
		align-items: center;
		gap: 0.4rem;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 6px;
		padding: 0.4rem 0.5rem;
		cursor: pointer;
		color: var(--color-text);
		font-size: 0.875rem;
		text-align: left;
	}
	.trigger:hover:not(:disabled) {
		background: var(--color-neutral-100, var(--color-border));
	}
	.trigger:disabled {
		cursor: default;
		opacity: 0.9;
	}
	.name {
		flex: 1;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
	.chev {
		color: var(--color-text-muted);
		font-size: 0.7rem;
	}
	.menu {
		position: absolute;
		bottom: calc(100% + 4px);
		left: 0;
		right: 0;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 6px;
		padding: 0.25rem;
		z-index: 20;
		box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
		max-height: 360px;
		overflow-y: auto;
	}
	.group-label {
		font-size: 0.65rem;
		font-weight: 600;
		letter-spacing: 0.06em;
		color: var(--color-text-muted);
		padding: 0.35rem 0.5rem 0.15rem;
		text-transform: uppercase;
	}
	.item {
		width: 100%;
		display: flex;
		align-items: center;
		gap: 0.4rem;
		background: transparent;
		border: none;
		padding: 0.4rem 0.5rem;
		text-align: left;
		color: var(--color-text);
		cursor: pointer;
		border-radius: 4px;
		font-size: 0.85rem;
	}
	.item:hover:not(:disabled) {
		background: var(--color-neutral-100, var(--color-border));
	}
	.item.active {
		background: var(--color-neutral-100, var(--color-border));
		font-weight: 600;
	}
	.item-name {
		flex: 1;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
	.error {
		padding: 0.4rem 0.5rem;
		color: var(--color-danger, #b00020);
		font-size: 0.8rem;
	}
	.switcher.collapsed .trigger {
		justify-content: center;
		padding: 0.4rem;
	}
	.switcher.collapsed .name {
		flex: initial;
	}
	.sep {
		height: 1px;
		background: var(--color-border);
		margin: 0.3rem 0;
	}
	.item.new {
		color: var(--color-primary, var(--color-text));
		font-weight: 500;
	}
	.backdrop {
		position: fixed;
		inset: 0;
		background: rgba(23, 25, 28, 0.45);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
		padding: 1rem;
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 12px;
		padding: 1.25rem 1.5rem;
		max-width: 420px;
		width: 100%;
		box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
		display: flex;
		flex-direction: column;
		gap: 0.9rem;
	}
	.card h2 {
		margin: 0;
		font-size: 1rem;
		font-weight: 600;
		color: var(--color-text-heading, var(--color-text));
	}
	.card label {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
		font-size: 0.85rem;
		color: var(--color-text);
	}
	.card input {
		padding: 0.45rem 0.6rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-surface);
		color: var(--color-text);
		font-size: 0.9rem;
	}
	.card input:disabled {
		opacity: 0.6;
	}
	.card .hint {
		font-size: 0.75rem;
		color: var(--color-text-muted);
	}
	.slug-status {
		font-size: 0.75rem;
	}
	.slug-status.checking {
		color: var(--color-text-muted);
	}
	.slug-status.ok {
		color: var(--color-success, #1b8a3a);
	}
	.slug-status.bad {
		color: var(--color-danger, #b00020);
	}
	.card input[aria-invalid='true'] {
		border-color: var(--color-danger, #b00020);
	}
	.actions {
		display: flex;
		gap: 0.5rem;
		justify-content: flex-end;
		margin-top: 0.25rem;
	}
	.btn {
		padding: 0.45rem 0.9rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
		font-size: 0.85rem;
		cursor: pointer;
	}
	.btn:hover:not(:disabled) {
		background: var(--color-neutral-100, var(--color-border));
	}
	.btn:disabled {
		opacity: 0.6;
		cursor: default;
	}
	.btn-primary {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: #fff;
	}
	.btn-primary:hover:not(:disabled) {
		filter: brightness(1.05);
	}
</style>

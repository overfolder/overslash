<script lang="ts">
	import { onMount, untrack } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { ApiError } from '$lib/session';
	import { listServices, listConnections, getServiceActions } from '$lib/api/services';
	import { executeAction, getTemplateActionDetail } from '$lib/api/actions';
	import type {
		ActionDetail,
		ActionSummary,
		ConnectionSummary,
		ExecuteRequest,
		ExecuteResponse,
		SecretRef,
		ServiceInstanceSummary
	} from '$lib/types';
	import ModePill, { type ExplorerMode } from './ModePill.svelte';
	import ServicePicker from './ServicePicker.svelte';
	import ActionPicker from './ActionPicker.svelte';
	import ParamForm from './ParamForm.svelte';
	import RawHttpEditor from './RawHttpEditor.svelte';
	import ResponsePanel from './ResponsePanel.svelte';

	let { initialService }: { initialService?: string | null } = $props();

	let mode = $state<ExplorerMode>('service_action');
	let services = $state<ServiceInstanceSummary[]>([]);
	let connections = $state<ConnectionSummary[]>([]);
	let loadingServices = $state(true);
	let loadError = $state<string | null>(null);

	let selectedService = $state<string | null>(null);

	// Sync parent-provided initialService into local state on mount and whenever
	// the parent swaps it (e.g., user clicks "Try it" on another row while this
	// component is already mounted).
	$effect(() => {
		const next = initialService;
		untrack(() => {
			if (next && next !== selectedService) selectedService = next;
		});
	});
	let actions = $state<ActionSummary[]>([]);
	let loadingActions = $state(false);
	let selectedAction = $state<string | null>(null);

	let actionDetail = $state<ActionDetail | null>(null);
	let loadingDetail = $state(false);

	let paramValues = $state<Record<string, string>>({});

	let rawMethod = $state('GET');
	let rawUrl = $state('');
	let rawHeaders = $state('');
	let rawBody = $state('');

	let running = $state(false);
	let response = $state<ExecuteResponse | null>(null);
	let runError = $state<string | null>(null);
	let elapsedMs = $state<number | null>(null);

	const selectedServiceRow = $derived(
		services.find((s) => s.name === selectedService) ?? null
	);

	onMount(async () => {
		try {
			const [s, c] = await Promise.all([listServices(), listConnections()]);
			services = s;
			connections = c;
		} catch (e) {
			loadError =
				e instanceof ApiError
					? `Failed to load services (${e.status})`
					: 'Failed to load services';
		} finally {
			loadingServices = false;
		}
	});

	$effect(() => {
		const svc = selectedService;
		untrack(() => {
			if (!svc) {
				actions = [];
				selectedAction = null;
				actionDetail = null;
				return;
			}
			loadingActions = true;
			actions = [];
			selectedAction = null;
			actionDetail = null;
			getServiceActions(svc)
				.then((a) => {
					actions = a;
				})
				.catch((e) => {
					loadError =
						e instanceof ApiError ? `Failed to load actions (${e.status})` : 'Failed to load actions';
				})
				.finally(() => {
					loadingActions = false;
				});
		});
	});

	$effect(() => {
		const actKey = selectedAction;
		const row = selectedServiceRow;
		untrack(() => {
			if (!actKey || !row) {
				actionDetail = null;
				paramValues = {};
				return;
			}
			loadingDetail = true;
			getTemplateActionDetail(row.template_key, actKey)
				.then((d) => {
					actionDetail = d;
					const next: Record<string, string> = {};
					for (const [name, p] of Object.entries(d.params)) {
						if (p.default !== undefined && p.default !== null) {
							next[name] = String(p.default);
						}
					}
					paramValues = next;
				})
				.catch((e) => {
					loadError =
						e instanceof ApiError
							? `Failed to load action schema (${e.status})`
							: 'Failed to load action schema';
				})
				.finally(() => {
					loadingDetail = false;
				});
		});
	});

	function handleServiceChange(v: string) {
		selectedService = v;
		const url = new URL($page.url);
		if (v) url.searchParams.set('service', v);
		else url.searchParams.delete('service');
		goto(`${url.pathname}${url.search}`, { replaceState: true, keepFocus: true, noScroll: true });
	}

	function parseHeaders(text: string): { literal: Record<string, string>; secrets: SecretRef[] } {
		const literal: Record<string, string> = {};
		const secretRefs: SecretRef[] = [];
		for (const raw of text.split('\n')) {
			const line = raw.trim();
			if (!line || line.startsWith('#')) continue;
			const idx = line.indexOf(':');
			if (idx < 0) continue;
			const name = line.slice(0, idx).trim();
			const value = line.slice(idx + 1).trim();
			if (!name) continue;
			const match = value.match(/^(.*?)\{\{([A-Za-z0-9_]+)\}\}(.*)$/);
			if (match && !match[3]) {
				secretRefs.push({
					name: match[2],
					inject_as: 'header',
					header_name: name,
					prefix: match[1] || undefined
				});
			} else {
				literal[name] = value;
			}
		}
		return { literal, secrets: secretRefs };
	}

	function paramToValue(raw: string, type: string): unknown {
		if (raw === '') return undefined;
		if (type === 'integer' || type === 'number') {
			const n = Number(raw);
			return Number.isFinite(n) ? n : raw;
		}
		if (type === 'object' || type === 'array') {
			try {
				return JSON.parse(raw);
			} catch {
				return raw;
			}
		}
		if (type === 'boolean') return raw === 'true';
		return raw;
	}

	function buildServiceActionRequest(): ExecuteRequest | null {
		if (!selectedService || !selectedAction || !actionDetail) return null;
		const params: Record<string, unknown> = {};
		for (const [name, p] of Object.entries(actionDetail.params)) {
			const raw = paramValues[name];
			if (raw === undefined || raw === '') continue;
			params[name] = paramToValue(raw, p.type);
		}
		return {
			service: selectedService,
			action: selectedAction,
			params
		};
	}

	function buildRawHttpRequest(): ExecuteRequest | null {
		if (!rawUrl.trim()) return null;
		const { literal, secrets: parsedSecrets } = parseHeaders(rawHeaders);
		return {
			method: rawMethod,
			url: rawUrl.trim(),
			headers: literal,
			secrets: parsedSecrets,
			body: rawBody.trim() ? rawBody : undefined
		};
	}

	async function run() {
		runError = null;
		response = null;
		const req = mode === 'service_action' ? buildServiceActionRequest() : buildRawHttpRequest();
		if (!req) {
			runError =
				mode === 'service_action'
					? 'Pick a service and action first.'
					: 'Enter a URL.';
			return;
		}
		running = true;
		const start = performance.now();
		try {
			response = await executeAction(req);
		} catch (e) {
			runError = e instanceof ApiError ? `${e.status}: ${e.message}` : String(e);
		} finally {
			elapsedMs = performance.now() - start;
			running = false;
		}
	}

	const canRun = $derived.by(() => {
		if (running) return false;
		if (mode === 'service_action') return Boolean(selectedService && selectedAction);
		return rawUrl.trim().length > 0;
	});
</script>

<div class="explorer">
	<header class="top">
		<ModePill {mode} onchange={(m) => (mode = m)} />
	</header>

	{#if loadError}
		<div class="error">{loadError}</div>
	{/if}

	<div class="layout">
		<section class="card request" aria-label="Request">
			<h2>Request</h2>

			{#if mode === 'service_action'}
				<div class="fields">
					<ServicePicker
						{services}
						{connections}
						value={selectedService}
						onchange={handleServiceChange}
					/>
					<ActionPicker
						{actions}
						value={selectedAction}
						loading={loadingActions}
						onchange={(v) => (selectedAction = v)}
					/>

					{#if selectedAction}
						<div class="params">
							<h3>Parameters</h3>
							{#if loadingDetail}
								<p class="muted">Loading schema…</p>
							{:else if actionDetail}
								<ParamForm
									detail={actionDetail}
									values={paramValues}
									onchange={(name, val) => (paramValues = { ...paramValues, [name]: val })}
								/>
							{/if}
						</div>
					{:else if !loadingServices && services.length === 0}
						<p class="muted">No services yet. Create one from the <a href="/services/new">Services page</a>.</p>
					{/if}
				</div>
			{:else}
				<RawHttpEditor
					method={rawMethod}
					url={rawUrl}
					headers={rawHeaders}
					body={rawBody}
					onmethod={(v) => (rawMethod = v)}
					onurl={(v) => (rawUrl = v)}
					onheaders={(v) => (rawHeaders = v)}
					onbody={(v) => (rawBody = v)}
				/>
			{/if}

			<div class="actions">
				<button type="button" class="btn primary" disabled={!canRun} onclick={run}>
					{running ? 'Executing…' : 'Execute'}
				</button>
			</div>
		</section>

		<ResponsePanel {response} error={runError} {running} {elapsedMs} />
	</div>
</div>

<style>
	.explorer {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}
	.top {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}
	.layout {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: 1rem;
	}
	@media (min-width: 1024px) {
		.layout {
			grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
		}
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
		padding: 1.25rem;
	}
	.request h2 {
		font: var(--text-h3);
		margin: 0 0 1rem;
		color: var(--color-text-heading);
	}
	.fields {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}
	.params h3 {
		font: var(--text-label);
		color: var(--color-text-heading);
		text-transform: none;
		margin: 0 0 0.6rem;
	}
	.actions {
		margin-top: 1rem;
		display: flex;
		justify-content: flex-start;
	}
	.btn {
		padding: 0.55rem 1.1rem;
		border-radius: var(--radius-md);
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: var(--color-text);
		cursor: pointer;
		font: inherit;
		font-size: 0.88rem;
	}
	.btn.primary {
		background: var(--color-primary);
		color: #fff;
		border-color: var(--color-primary);
	}
	.btn:disabled {
		opacity: 0.55;
		cursor: not-allowed;
	}
	.error {
		background: var(--badge-bg-danger);
		color: var(--error-500);
		border: 1px solid rgba(229, 56, 54, 0.25);
		border-radius: var(--radius-md);
		padding: 0.6rem 0.9rem;
		font-size: 0.85rem;
	}
	.muted {
		color: var(--color-text-muted);
		font-size: 0.85rem;
	}
</style>

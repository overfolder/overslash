<!--
	"Finish setting up <service>" — the page an agent's setup link opens.

	The sibling of `/secrets/provide/[req_id]`, and the same handshake: a
	signed, single-use capability in the URL, a value the visitor pastes, and a
	server that binds it. What differs is the framing. The provide page asks
	for a vault key by name, which tells a human nothing about why; this one
	leads with the service, and on submit the instance becomes callable rather
	than merely having a secret stored next to it.

	Submits to `/public/secrets/provide/{req_id}` — the same endpoint, because
	there is one write path and putting the credential-binding step in two
	places is how they drift.
-->
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import ServiceIcon from '$lib/components/ServiceIcon.svelte';
	import SecretValueField from '$lib/components/secrets/SecretValueField.svelte';
	import TestResult from '$lib/components/services/TestResult.svelte';
	import { testService } from '$lib/api/services';
	import { ApiError, apiErrorReason } from '$lib/session';
	import type { ServiceTestResponse } from '$lib/types';

	let { data } = $props();

	let value = $state('');
	let submitting = $state(false);
	let submitted = $state(false);
	let errorMsg = $state<string | null>(null);
	let now = $state(Date.now());

	// What remains after a successful submit. A multi-slot template hands over
	// one link per slot, so finishing this one does not always finish setup.
	let remainingSlots = $state<string[]>([]);

	let testing = $state(false);
	let testResult = $state<ServiceTestResponse | null>(null);

	let timer: ReturnType<typeof setInterval> | undefined;
	onMount(() => {
		timer = setInterval(() => (now = Date.now()), 1000);
	});
	onDestroy(() => {
		if (timer) clearInterval(timer);
	});

	function fmtCountdown(expiresAt: string): string {
		const t = Date.parse(expiresAt);
		if (!Number.isFinite(t)) return expiresAt;
		const ms = t - now;
		if (ms <= 0) return 'expired';
		const s = Math.floor(ms / 1000);
		const m = Math.floor(s / 60);
		return `${m}m ${(s % 60).toString().padStart(2, '0')}s`;
	}

	/** Slots this link does not fill and that nothing has bound yet. */
	const otherUnbound = $derived(
		data.state === 'ready'
			? data.meta.service.slots.filter((s) => s.key !== data.meta.service.slot.key && !s.bound)
			: []
	);

	async function submit() {
		if (data.state !== 'ready' || !value) return;
		submitting = true;
		errorMsg = null;
		try {
			// `same-origin` so the dashboard session cookie travels if the
			// visitor is signed in. The server still validates the URL JWT; the
			// session is a purely additive identity attestation (SPEC §11 User
			// Signed Mode).
			const r = await fetch(`/public/secrets/provide/${encodeURIComponent(data.req_id)}`, {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				credentials: 'same-origin',
				body: JSON.stringify({ token: data.token, value })
			});
			if (!r.ok) {
				const body = await r.json().catch(() => null);
				const code = (body && (body as { error?: string }).error) || `error_${r.status}`;
				if (r.status === 410 && code.includes('already_fulfilled')) {
					errorMsg = 'This request was already fulfilled.';
				} else if (r.status === 410) {
					errorMsg = 'This link has expired.';
				} else if (r.status === 401 && code.includes('user_session_required')) {
					errorMsg = 'This organization requires you to be signed in to provide this secret.';
				} else if (r.status === 400) {
					errorMsg = 'This link is invalid or tampered.';
				} else {
					errorMsg = 'Submission failed. Please try again.';
				}
				return;
			}
			const body = (await r.json()) as {
				service?: { remaining_slots?: string[] };
			};
			remainingSlots = body.service?.remaining_slots ?? [];
			submitted = true;
			value = '';
			// Verify immediately when we can. The point of this page is that the
			// person holding the key finds out here whether it was the right one.
			if (canTest) await runTest();
		} catch {
			errorMsg = 'Network error. Please try again.';
		} finally {
			submitting = false;
		}
	}

	// The probe runs through the authenticated call path, so it needs a session.
	// An anonymous visitor gets a sign-in prompt instead of a dead button.
	const canTest = $derived(
		data.state === 'ready' && !!data.meta.service.test_action && !!data.meta.viewer
	);

	async function runTest() {
		if (data.state !== 'ready') return;
		testing = true;
		testResult = null;
		try {
			testResult = await testService(data.meta.service.id);
		} catch (e) {
			testResult = {
				status: 'failed',
				error: e instanceof ApiError ? apiErrorReason(e) : 'Could not run the test'
			};
		} finally {
			testing = false;
		}
	}

	function loginUrl(): string {
		// Round-trip back to this page after signing in. The visitor's original
		// URL (with token) is already in their tab history, and after login
		// SvelteKit re-runs this load.
		if (typeof window === 'undefined') return '/login';
		return `/login?next=${encodeURIComponent(window.location.pathname + window.location.search)}`;
	}
</script>

<svelte:head>
	<title>Set up service — Overslash</title>
	<meta name="robots" content="noindex, nofollow" />
</svelte:head>

<div class="page">
	<div class="card">
		<div class="brand">Overslash</div>

		{#if data.state === 'missing_token'}
			<h1>Missing token</h1>
			<p>This link is incomplete. Please use the original URL you were sent.</p>
		{:else if data.state === 'server_error'}
			<h1>Something went wrong</h1>
			<p>The server encountered an error. Please try again in a moment.</p>
		{:else if data.state === 'invalid'}
			<h1>Invalid link</h1>
			<p>This link is invalid or has been tampered with.</p>
		{:else if data.state === 'expired'}
			<h1>Link expired</h1>
			<p>This setup link has expired. Ask for a new one.</p>
		{:else if data.state === 'already_fulfilled'}
			<h1>Already set up</h1>
			<p>This credential has already been provided.</p>
		{:else if data.state === 'ready'}
			{@const m = data.meta}
			{@const svc = m.service}

			<div class="service">
				<ServiceIcon src={svc.icon_url} name={svc.display_name} size={40} />
				<div class="service-text">
					<h1>{svc.display_name}</h1>
					<p class="instance">{svc.name}</p>
				</div>
			</div>

			{#if submitted}
				<p class="lead">
					{svc.display_name} is connected.
					{#if remainingSlots.length > 0}
						It still needs {remainingSlots.length} more credential{remainingSlots.length ===
						1
							? ''
							: 's'} — you'll have a separate link for each.
					{/if}
				</p>

				{#if canTest}
					<TestResult result={testResult} running={testing} onRetry={runTest} />
				{:else if svc.test_action}
					<p class="note">
						<a href={loginUrl()}>Sign in</a> to test that this credential works.
					</p>
				{/if}

				<p class="note">You can close this window. The agent has been notified.</p>
			{:else}
				<p class="lead">
					<code>{m.requested_by_label}</code> set this up for you and needs its
					{svc.slot.label.toLowerCase()}.
				</p>

				<div class="meta">
					<div class="row">
						<span class="k">{svc.slot.label}</span>
						<span class="v"><code>{m.secret_name}</code></span>
					</div>
					<div class="row">
						<span class="k">For</span>
						<span class="v">{m.identity_label}</span>
					</div>
					{#if m.reason && m.reason !== svc.slot.label}
						<div class="row">
							<span class="k">Reason</span>
							<span class="v">{m.reason}</span>
						</div>
					{/if}
					{#if otherUnbound.length > 0}
						<div class="row">
							<span class="k">Also needs</span>
							<span class="v">{otherUnbound.map((s) => s.label).join(', ')}</span>
						</div>
					{/if}
				</div>

				{#if svc.slot.description}
					<p class="slot-help">{svc.slot.description}</p>
				{/if}

				{#if m.viewer}
					<div class="viewer-banner">
						Signed in as <strong>{m.viewer.email}</strong>. Your name will be recorded on the
						audit trail for this submission.
					</div>
				{:else if m.require_user_session}
					<!-- Minted under user-signed-required mode but opened without a
					     matching session. GET still succeeds (the metadata is not
					     sensitive) and POST would be rejected server-side, so gate
					     the input rather than letting them paste a value first. -->
					<div class="viewer-banner warn">
						This organization requires you to be signed in to Overslash to provide this
						credential.
						<a href={loginUrl()}>Sign in to continue</a>.
					</div>
				{/if}

				{#if !m.require_user_session || m.viewer}
					<SecretValueField
						bind:value
						label={svc.slot.label}
						placeholder="Paste the value"
						disabled={submitting}
						autofocus
					/>

					{#if errorMsg}
						<div class="error">{errorMsg}</div>
					{/if}

					<div class="actions">
						<button class="btn primary" onclick={submit} disabled={submitting || !value}>
							{submitting ? 'Saving…' : 'Connect'}
						</button>
					</div>
				{/if}

				<p class="footnote">Expires in {fmtCountdown(m.expires_at)}</p>
				<p class="note">
					Providing a credential does not grant the agent permission to use it. A separate
					approval is still required.
				</p>
			{/if}
		{/if}
	</div>
</div>

<style>
	.page {
		min-height: 100vh;
		background: var(--color-bg);
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem;
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 16px;
		padding: 2.5rem;
		max-width: 540px;
		width: 100%;
		box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);
	}
	.brand {
		font-weight: 700;
		font-size: 0.85rem;
		color: var(--color-text-muted);
		letter-spacing: 0.05em;
		text-transform: uppercase;
		margin-bottom: 0.75rem;
	}
	.service {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		margin-bottom: 0.75rem;
	}
	.service-text {
		min-width: 0;
	}
	.instance {
		margin: 0;
		font-family: var(--font-mono);
		font-size: 0.8rem;
		color: var(--color-text-muted);
	}
	h1 {
		margin: 0;
		font-size: 1.4rem;
		color: var(--color-text);
	}
	.lead {
		margin: 0 0 1.25rem;
		color: var(--color-text-muted);
	}
	.lead code,
	.v code {
		font-family: var(--font-mono);
		font-size: 0.9em;
		background: var(--color-bg);
		padding: 0.1rem 0.35rem;
		border-radius: 4px;
	}
	.meta {
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 0.75rem 1rem;
		margin-bottom: 1rem;
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}
	.row {
		display: flex;
		justify-content: space-between;
		gap: 1rem;
		font-size: 0.85rem;
	}
	.k {
		color: var(--color-text-muted);
		flex: none;
	}
	.v {
		color: var(--color-text);
		text-align: right;
		overflow-wrap: anywhere;
	}
	.slot-help {
		margin: 0 0 1rem;
		font-size: 0.82rem;
		color: var(--color-text-muted);
		line-height: 1.45;
	}
	.error {
		background: rgba(230, 56, 54, 0.1);
		color: var(--color-error, #e63836);
		padding: 0.5rem 0.75rem;
		border-radius: 6px;
		font-size: 0.85rem;
		margin-bottom: 0.75rem;
	}
	.viewer-banner {
		background: rgba(60, 140, 90, 0.08);
		border: 1px solid rgba(60, 140, 90, 0.25);
		color: var(--color-text);
		padding: 0.65rem 0.85rem;
		border-radius: 8px;
		font-size: 0.82rem;
		margin-bottom: 1rem;
		line-height: 1.45;
	}
	.viewer-banner.warn {
		background: rgba(235, 170, 50, 0.1);
		border-color: rgba(235, 170, 50, 0.35);
	}
	.viewer-banner a,
	.note a {
		color: var(--color-primary);
		font-weight: 600;
	}
	.actions {
		display: flex;
		gap: 0.75rem;
		margin-bottom: 1rem;
	}
	.btn {
		flex: 1;
		padding: 0.7rem 1rem;
		border-radius: 8px;
		font: inherit;
		font-weight: 600;
		cursor: pointer;
		border: 1px solid transparent;
	}
	.btn.primary {
		background: var(--color-primary);
		color: #fff;
	}
	.btn.primary:hover:not(:disabled) {
		background: var(--color-primary-hover, #4f45c2);
	}
	.btn:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.footnote {
		font-size: 0.78rem;
		color: var(--color-text-muted);
		margin: 1rem 0 0.5rem;
	}
	.note {
		font-size: 0.75rem;
		color: var(--color-text-muted);
		margin: 0.5rem 0 0;
		line-height: 1.4;
	}
</style>

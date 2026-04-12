<script lang="ts">
	import { onMount, onDestroy } from 'svelte';

	let { data } = $props();

	let value = $state('');
	let reveal = $state(false);
	let submitting = $state(false);
	let submitted = $state(false);
	let denied = $state(false);
	let errorMsg = $state<string | null>(null);
	let now = $state(Date.now());

	let timer: ReturnType<typeof setInterval> | undefined;
	onMount(() => {
		timer = setInterval(() => (now = Date.now()), 1000);
	});
	onDestroy(() => {
		if (timer) clearInterval(timer);
	});

	function fmtCountdown(expiresAt: string): string {
		const ms = new Date(expiresAt).getTime() - now;
		if (ms <= 0) return 'expired';
		const s = Math.floor(ms / 1000);
		const m = Math.floor(s / 60);
		return `${m}m ${(s % 60).toString().padStart(2, '0')}s`;
	}

	function fmtRelative(iso: string): string {
		const ms = now - new Date(iso).getTime();
		if (ms < 60_000) return 'just now';
		const m = Math.floor(ms / 60_000);
		if (m < 60) return `${m}m ago`;
		const h = Math.floor(m / 60);
		if (h < 24) return `${h}h ago`;
		return `${Math.floor(h / 24)}d ago`;
	}

	async function submit() {
		if (data.state !== 'ready' || !value) return;
		submitting = true;
		errorMsg = null;
		try {
			// `same-origin` so the dashboard session cookie travels if the
			// visitor is signed in. Server still validates the URL JWT; the
			// session is a purely additive identity attestation (see SPEC §11
			// User Signed Mode).
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
					errorMsg =
						'This organization requires you to be signed in to provide this secret.';
				} else if (r.status === 400) {
					errorMsg = 'This link is invalid or tampered.';
				} else {
					errorMsg = 'Submission failed. Please try again.';
				}
				return;
			}
			submitted = true;
			value = '';
		} catch {
			errorMsg = 'Network error. Please try again.';
		} finally {
			submitting = false;
		}
	}

	function loginUrl(): string {
		// Round-trip back to this page after signing in. We intentionally
		// don't try to preserve the query string via the redirect layer —
		// the visitor's original URL (with token) is already in their tab
		// history, and after login SvelteKit will re-run this load.
		if (typeof window === 'undefined') return '/login';
		return `/login?next=${encodeURIComponent(window.location.pathname + window.location.search)}`;
	}
</script>

<svelte:head>
	<title>Provide Secret — Overslash</title>
	<meta name="robots" content="noindex, nofollow" />
</svelte:head>

<div class="page">
	<div class="card">
		<div class="brand">Overslash</div>

		{#if submitted}
			<h1>Secret stored</h1>
			<p>You can close this window. The agent has been notified.</p>
		{:else if denied}
			<h1>Request denied</h1>
			<p>You declined to provide this secret. You can close this window.</p>
		{:else if data.state === 'missing_token'}
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
			<p>This secret request has expired. Ask the agent to issue a new one.</p>
		{:else if data.state === 'already_fulfilled'}
			<h1>Already fulfilled</h1>
			<p>This secret request has already been fulfilled.</p>
		{:else if data.state === 'ready'}
			{@const m = data.meta}
			<h1>Secret Request</h1>
			<p class="lead">
				<code>{m.requested_by_label}</code> needs a secret:
			</p>

			<div class="meta">
				<div class="row">
					<span class="k">Name</span>
					<span class="v"><code>{m.secret_name}</code></span>
				</div>
				<div class="row">
					<span class="k">For identity</span>
					<span class="v">{m.identity_label}</span>
				</div>
				{#if m.reason}
					<div class="row">
						<span class="k">Reason</span>
						<span class="v">{m.reason}</span>
					</div>
				{/if}
			</div>

			{#if m.viewer}
				<div class="viewer-banner">
					Signed in as <strong>{m.viewer.email}</strong>. Your name will be recorded on the
					audit trail for this submission.
				</div>
			{:else if m.require_user_session}
				<!-- Edge case: the row was minted under user-signed-required mode,
				     but the visitor loaded the page without a matching session.
				     GET still succeeds (metadata is not sensitive), but POST will
				     be rejected server-side. Gate the UI here so the visitor
				     doesn't waste time pasting a value first. -->
				<div class="viewer-banner warn">
					This organization requires you to be signed in to Overslash to provide this secret.
					<a href={loginUrl()}>Sign in to continue</a>.
				</div>
			{/if}

			{#if !m.require_user_session || m.viewer}
				<label class="field">
					<span>Secret value</span>
					<div class="input-wrap">
						<!-- svelte-ignore a11y_autofocus -->
						<input
							type={reveal ? 'text' : 'password'}
							bind:value
							disabled={submitting}
							autocomplete="off"
							spellcheck="false"
							autocapitalize="off"
							autocorrect="off"
							placeholder="Paste secret value"
						/>
						<button
							type="button"
							class="reveal"
							onclick={() => (reveal = !reveal)}
							aria-label={reveal ? 'Hide value' : 'Show value'}
							disabled={submitting}
						>
							{reveal ? 'Hide' : 'Show'}
						</button>
					</div>
				</label>

				{#if errorMsg}
					<div class="error">{errorMsg}</div>
				{/if}

				<div class="actions">
					<button class="btn primary" onclick={submit} disabled={submitting || !value}>
						{submitting ? 'Submitting…' : 'Provide'}
					</button>
					<!-- TODO(secret-request-deny): wire to a backend deny endpoint so the
					     requesting agent gets notified. For now Deny only flips local
					     state — the request row remains pending until it expires. -->
					<button class="btn secondary" onclick={() => (denied = true)} disabled={submitting}>
						Deny
					</button>
				</div>
			{/if}

			<p class="footnote">
				Requested {fmtRelative(m.created_at)} · Expires in {fmtCountdown(m.expires_at)}
			</p>
			<p class="note">
				Providing a secret does not grant the agent permission to use it. A separate approval is
				still required.
			</p>
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
	h1 {
		margin: 0 0 0.5rem;
		font-size: 1.4rem;
		color: var(--color-text);
	}
	.lead {
		margin: 0 0 1.5rem;
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
		margin-bottom: 1.25rem;
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
	}
	.v {
		color: var(--color-text);
		text-align: right;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
		margin-bottom: 1rem;
	}
	.field span {
		font-size: 0.8rem;
		color: var(--color-text-muted);
	}
	.input-wrap {
		display: flex;
		gap: 0.5rem;
	}
	.input-wrap input {
		flex: 1;
		padding: 0.6rem 0.75rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-bg);
		color: var(--color-text);
		font: inherit;
		font-family: var(--font-mono);
	}
	.reveal {
		padding: 0 0.85rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-bg);
		color: var(--color-text-muted);
		cursor: pointer;
		font-size: 0.8rem;
	}
	.reveal:hover:not(:disabled) {
		color: var(--color-text);
	}
	.reveal:disabled {
		cursor: not-allowed;
		opacity: 0.6;
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
	.viewer-banner a {
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
	.btn.secondary {
		background: transparent;
		border-color: var(--color-border);
		color: var(--color-text);
	}
	.btn.secondary:hover:not(:disabled) {
		background: var(--color-border);
	}
	.btn:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.footnote {
		font-size: 0.78rem;
		color: var(--color-text-muted);
		margin: 0 0 0.5rem;
	}
	.note {
		font-size: 0.75rem;
		color: var(--color-text-muted);
		margin: 0;
		line-height: 1.4;
	}
</style>

<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import PublicRequestCard from '$lib/components/secrets/PublicRequestCard.svelte';
	import SecretValueField from '$lib/components/secrets/SecretValueField.svelte';
	import { fmtCountdown, loginUrl, submitErrorMessage } from '$lib/public-request';

	let { data } = $props();

	let value = $state('');
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

	function fmtRelative(iso: string): string {
		const t = Date.parse(iso);
		if (!Number.isFinite(t)) return iso;
		const ms = now - t;
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
				const code = (body && (body as { error?: string }).error) || '';
				errorMsg = submitErrorMessage(r.status, code);
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

</script>

<svelte:head>
	<title>Provide Secret — Overslash</title>
	<meta name="robots" content="noindex, nofollow" />
</svelte:head>

<PublicRequestCard>
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
		<SecretValueField bind:value disabled={submitting} autofocus />

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
		Requested {fmtRelative(m.created_at)} · Expires in {fmtCountdown(m.expires_at, now)}
	</p>
	<p class="note">
		Providing a secret does not grant the agent permission to use it. A separate approval is
		still required.
	</p>
{/if}
</PublicRequestCard>



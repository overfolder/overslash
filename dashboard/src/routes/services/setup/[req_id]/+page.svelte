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
	import PublicRequestCard from '$lib/components/secrets/PublicRequestCard.svelte';
	import RequestIdentityBox from '$lib/components/RequestIdentityBox.svelte';
	import SecretValueField from '$lib/components/secrets/SecretValueField.svelte';
	import TestResult from '$lib/components/services/TestResult.svelte';
	import { runProbe } from '$lib/api/services';
	import { fmtCountdown, loginUrl, submitPublicRequest } from '$lib/public-request';
	import { setupOutcome } from '$lib/setup-outcome';
	import type { ServiceTestResponse } from '$lib/types';

	let { data } = $props();

	let value = $state('');
	let submitting = $state(false);
	let submitted = $state(false);
	let errorMsg = $state<string | null>(null);
	let now = $state(Date.now());

	// What remains after a successful submit. A multi-slot template hands over
	// one link per slot, so finishing this one does not always finish setup.
	//
	// `null` is "not known", which the server sends (as an absent field) when
	// the template would not resolve to answer. Kept distinct from `[]`: the
	// backend goes out of its way to draw that line — degrading rather than
	// failing a committed write — and collapsing it here would put the whole
	// point of that back, announcing a service ready on a shrug.
	let remainingSlots = $state<string[] | null>(null);
	// The secret is in the vault but never reached the service. Rare, and the
	// one post-submit state where there is something for a human to do.
	let bindFailed = $state(false);

	let testing = $state(false);
	let testResult = $state<ServiceTestResponse | null>(null);

	let timer: ReturnType<typeof setInterval> | undefined;
	onMount(() => {
		timer = setInterval(() => (now = Date.now()), 1000);
	});
	onDestroy(() => {
		if (timer) clearInterval(timer);
	});

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
		const outcome = await submitPublicRequest<{
			service?: { bound?: boolean; remaining_slots?: string[] };
		}>(data.req_id, data.token, value);
		submitting = false;
		if (!outcome.ok) {
			errorMsg = outcome.message;
			return;
		}
		const svcOutcome = outcome.body?.service;
		remainingSlots = svcOutcome?.remaining_slots ?? null;
		// The value is saved either way; this says whether it reached the
		// service. `false` is a real outcome, not an error — the server
		// degrades rather than failing a submit it has already committed.
		bindFailed = svcOutcome?.bound === false;
		submitted = true;
		value = '';

		// Verify immediately when we can. The point of this page is that the
		// person holding the key finds out here whether it was the right one.
		//
		// Not while a sibling slot is still unfilled: the probe's answer would
		// be a foregone "no usable credential yet", and the headline would
		// report it over the truer "still needs N more". Same guard the create
		// wizard applies. And not when the server could not say what remains
		// (`remaining_slots` absent) — "not known" is not "none left".
		if (canTest && !bindFailed && remainingSlots?.length === 0) await runTest();
	}

	// The probe runs through the authenticated call path, so it needs a session.
	// An anonymous visitor gets a sign-in prompt instead of a dead button.
	const outcome = $derived(
		setupOutcome({ bindFailed, testing, testResult, remainingSlots })
	);

	const canTest = $derived(
		data.state === 'ready' && !!data.meta.service.test_action && !!data.meta.viewer
	);

	async function runTest() {
		if (data.state !== 'ready') return;
		testing = true;
		testResult = null;
		try {
			// Session-less page: never let a 401 hard-navigate off a burned link.
			testResult = await runProbe(data.meta.service.id, { bounceOnExpiry: false });
		} finally {
			testing = false;
		}
	}

</script>

<svelte:head>
	<title>Set up service — Overslash</title>
	<meta name="robots" content="noindex, nofollow" />
</svelte:head>

<PublicRequestCard>
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
		<!-- Do not say "connected" over a failed probe. The credential is
		     saved either way; whether it *works* is the verdict's to
		     report, and claiming success above a red box is worse than
		     saying less. -->
		<p class="lead">
			{#if outcome === 'bind_failed'}
				Saved, but it could not be attached to {svc.display_name}. The value is
				stored — someone with dashboard access can finish this from the service's
				Credentials tab.
			{:else if outcome === 'testing'}
				<!-- Nothing conclusive to say yet, and "connected" over a panel
				     that is about to turn red is worse than silence. -->
				Saved. Checking it works…
			{:else if outcome === 'rejected'}
				Saved. {svc.display_name} did not accept it — see below.
			{:else if outcome === 'unknown'}
				<!-- The server could not work out what is left. The credential is
				     bound, so the service is most likely ready — but "most
				     likely" is not "is", and the Test button turns the guess
				     into an answer. -->
				Saved to {svc.display_name}. Test it to confirm it is ready.
			{:else if outcome === 'incomplete'}
				Saved. {svc.display_name} still needs {remainingSlots?.length} more credential{remainingSlots?.length ===
				1
					? ''
					: 's'} — you'll have a separate link for each.
			{:else}
				{svc.display_name} is connected.
			{/if}
		</p>

		{#if canTest}
			<!-- An explicit button, not only the auto-run. The probe fires on its
			     own when this submission completed the setup, but that is the one
			     case of several: a sibling slot still outstanding, a bind that
			     did not land, or simply wanting to check again after fixing
			     something elsewhere all leave the person here with nothing to
			     press. Same shape as the service detail page's Credentials tab. -->
			<div class="test-row">
				<button
					type="button"
					class="btn secondary"
					onclick={runTest}
					disabled={testing}
					title={svc.test_action?.summary ?? `Runs ${svc.test_action?.action}`}
				>
					{testing ? 'Testing…' : 'Test service'}
				</button>
			</div>
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

		<RequestIdentityBox orgName={m.org_name} userEmail={m.viewer?.email ?? null}>
			{#snippet note()}
				{#if m.viewer}
					Your name will be recorded on the audit trail for this submission.
				{:else}
					This link is what authorizes the submission — signing in is optional, and
					only adds your name to the audit trail.
				{/if}
			{/snippet}
		</RequestIdentityBox>

		<div class="meta">
			<div class="row">
				<span class="k">Stored as</span>
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

		{#if !m.viewer && m.require_user_session}
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

		<p class="footnote">Expires in {fmtCountdown(m.expires_at, now)}</p>
		<p class="note">
			Providing a credential does not grant the agent permission to use it. A separate
			approval is still required.
		</p>
	{/if}
{/if}
</PublicRequestCard>

<style>
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
	.test-row {
		display: flex;
		margin-bottom: 0.75rem;
	}
	/* `.btn` in the shared card is `flex: 1` — right for the submit button it
	   was written for, wrong for a secondary action that should size to its
	   label. */
	.test-row :global(.btn) {
		flex: 0 0 auto;
	}
	.slot-help {
		margin: 0 0 1rem;
		font-size: 0.82rem;
		color: var(--color-text-muted);
		line-height: 1.45;
	}
</style>

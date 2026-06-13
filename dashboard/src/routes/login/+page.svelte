<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let { data } = $props();

	const providers = $derived(
		data.providers as Array<{ key: string; display_name: string; source: string; is_default?: boolean }>
	);
	const scope = $derived((data.scope as 'root' | 'org') ?? 'root');
	const next = $derived(data.next as string | null);
	const returnTo = $derived(data.returnTo as string);
	const reason = $derived(data.reason as string | null);

	// Captured in `onMount` so the login `<a href>` URLs re-render with
	// `preview_origin` set after hydration. Reading `window.location.origin`
	// straight from `loginUrl()` would be `undefined` during SSR and the
	// template wouldn't re-evaluate on the client (no reactive dep), so the
	// SSR'd hrefs would ship without it — and the API would never see a
	// `preview_origin`, leaving previews stuck on the cookie path that
	// can't work cross-domain.
	let browserOrigin = $state<string | null>(null);

	function loginUrl(key: string): string {
		const target = `/auth/login/${encodeURIComponent(key)}`;
		const params = new URLSearchParams();
		// Forward `next` so the OAuth-AS resumption path survives the IdP
		// bounce. Without this, `/oauth/authorize` redirects here, the user
		// signs in, and the callback dumps them at the dashboard root —
		// breaking MCP onboarding.
		if (next) params.set('next', next);
		// Vercel preview-deployment OAuth handoff. We always advertise our
		// origin; the API gates the handoff on `OVERSLASH_ENV=dev` plus its
		// `PREVIEW_ORIGIN_ALLOWLIST` regex and silently ignores values that
		// don't match (so prod and the corp-apex dashboard fall through to
		// the cookie-based path unchanged).
		if (browserOrigin) params.set('preview_origin', browserOrigin);
		const qs = params.toString();
		return qs ? `${target}?${qs}` : target;
	}

	let devProfile = $state<'admin' | 'member' | 'readonly'>('admin');

	async function devLogin() {
		const res = await fetch(`/auth/dev/token?profile=${devProfile}`, {
			credentials: 'include'
		});
		if (res.ok) {
			await goto(next ?? returnTo);
		}
	}

	// Passwordless email magic-link. Submitting POSTs to the backend, which
	// always responds 200 (no account enumeration) and emails a one-time link;
	// we swap to a "check your inbox" confirmation rather than redirecting —
	// the user continues by clicking the emailed link.
	let email = $state('');
	let magicLinkSubmitting = $state(false);
	let magicLinkSentTo = $state<string | null>(null);
	let magicLinkError = $state<string | null>(null);
	// Only populated when the backend runs with DEV_AUTH (local/dev): the
	// NoopMailer drops the body, so the verify URL is echoed back for testing.
	let devVerifyUrl = $state<string | null>(null);

	async function submitMagicLink(e: SubmitEvent) {
		e.preventDefault();
		if (magicLinkSubmitting) return;
		magicLinkError = null;
		magicLinkSubmitting = true;
		try {
			const res = await fetch('/auth/magic-link/request', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({ email, next })
			});
			if (!res.ok) {
				magicLinkError = 'Something went wrong. Please try again.';
				return;
			}
			const body = await res.json().catch(() => ({}));
			devVerifyUrl = typeof body?.dev_verify_url === 'string' ? body.dev_verify_url : null;
			magicLinkSentTo = email;
		} catch {
			magicLinkError = 'Network error. Please try again.';
		} finally {
			magicLinkSubmitting = false;
		}
	}

	function brandClass(key: string): string {
		if (key === 'google') return 'btn-google';
		if (key === 'github') return 'btn-github';
		if (key === 'dev') return 'btn-dev';
		return 'btn-oidc';
	}

	// Auto-redirect when the org has designated a single default IdP.
	// Skip the picker entirely so MCP-driven OAuth bounces don't show an
	// extra click. Users can always go back from the IdP to pick another.
	onMount(() => {
		// Set first so the loginUrl computed below picks it up — and so the
		// post-hydration template re-render attaches `preview_origin` to the
		// rest of the providers' hrefs.
		browserOrigin = window.location.origin;

		if (scope !== 'org') return;
		const def = providers.find((p) => p.is_default);
		if (def && def.key !== 'dev') {
			window.location.replace(loginUrl(def.key));
		}
	});
</script>

<svelte:head>
	<title>Sign in — Overslash</title>
</svelte:head>

<div class="login-page">
	<div class="card">
		<div class="wordmark" aria-label="Overslash">
			<span>Overs</span><span class="slash">/</span><span>ash</span>
		</div>

		{#if reason === 'expired'}
			<div class="toast">Session expired — please sign in again.</div>
		{/if}

		{#if reason === 'magic_link_invalid'}
			<div class="toast">That sign-in link is invalid or has expired. Request a new one below.</div>
		{/if}

		<h1>Sign in</h1>

		{#if providers.length === 0 && scope === 'org'}
			<p class="empty">
				This organization has no sign-in configured yet. Ask the org creator to
				add an identity provider on their Org Settings page — corp orgs admit
				members only through their own IdP, and the creator's bootstrap
				admin access is the only route in until that's done.
			</p>
		{:else if providers.length === 0}
			<p class="empty">
				No identity providers are configured. Set <code>GOOGLE_AUTH_CLIENT_ID</code>,
				<code>GITHUB_AUTH_CLIENT_ID</code>, or <code>DEV_AUTH</code> on the backend.
			</p>
		{:else}
			<div class="providers">
				{#each providers as p (p.key)}
					{#if p.key === 'email'}
						{#if magicLinkSentTo}
							<div class="magic-sent" data-testid="magic-link-sent">
								<p class="magic-sent-title">Check your inbox</p>
								<p class="magic-sent-body">
									We sent a sign-in link to <strong>{magicLinkSentTo}</strong>. Click it to
									finish signing in — it expires in 15 minutes.
								</p>
								{#if devVerifyUrl}
									<a class="magic-dev-link" href={devVerifyUrl} data-testid="magic-link-dev-url"
										>Dev: open sign-in link</a
									>
								{/if}
							</div>
						{:else}
							<form class="magic-form" onsubmit={submitMagicLink}>
								<input
									class="magic-input"
									type="email"
									bind:value={email}
									placeholder="you@example.com"
									autocomplete="email"
									aria-label="Email address"
									data-testid="magic-link-email"
									required
								/>
								<button
									class="btn btn-primary"
									type="submit"
									disabled={magicLinkSubmitting}
									data-testid="magic-link-submit"
								>
									{magicLinkSubmitting ? 'Sending…' : 'Email me a sign-in link'}
								</button>
								{#if magicLinkError}
									<p class="magic-error">{magicLinkError}</p>
								{/if}
							</form>
						{/if}
					{:else if p.key === 'dev'}
						<div class="dev-row">
							<button class="btn {brandClass(p.key)}" onclick={devLogin}>
								Continue with {p.display_name}
							</button>
							<select
								class="profile-select"
								bind:value={devProfile}
								aria-label="Dev login profile"
								data-testid="dev-profile"
							>
								<option value="admin">admin</option>
								<option value="member">member</option>
								<option value="readonly">readonly</option>
							</select>
						</div>
					{:else}
						<a class="btn {brandClass(p.key)}" href={loginUrl(p.key)}>
							Continue with {p.display_name}
						</a>
					{/if}
				{/each}
			</div>
		{/if}
	</div>
</div>

<style>
	.login-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--color-bg);
		padding: 2rem;
	}

	.card {
		width: 100%;
		max-width: 380px;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 12px;
		padding: 2.5rem 2rem;
		box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
	}

	.wordmark {
		font-family: var(--font-mono);
		font-size: 2rem;
		font-weight: 700;
		color: var(--color-text);
		text-align: center;
		margin-bottom: 1.5rem;
		letter-spacing: -0.02em;
	}

	.wordmark .slash {
		font-family: var(--font-mono);
		font-weight: 800;
		color: var(--color-primary);
		display: inline-block;
		transform: skewX(-12deg);
		margin: 0 1px;
	}

	h1 {
		font-size: 1.1rem;
		font-weight: 600;
		text-align: center;
		color: var(--color-text-muted);
		margin-bottom: 1.5rem;
	}

	.toast {
		background: var(--warning-500);
		color: #1a1300;
		padding: 0.6rem 0.8rem;
		border-radius: 6px;
		font-size: 0.85rem;
		text-align: center;
		margin-bottom: 1rem;
	}

	.providers {
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
	}

	.btn {
		display: block;
		text-align: center;
		padding: 0.7rem 1rem;
		border-radius: 8px;
		font-size: 0.9rem;
		font-weight: 500;
		cursor: pointer;
		text-decoration: none;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
		transition: background 0.15s, border-color 0.15s;
	}

	.btn:hover {
		background: var(--color-border-subtle);
	}

	.btn-google {
		border-color: #dadce0;
	}

	.btn-github {
		background: #24292f;
		color: #fff;
		border-color: #24292f;
	}

	.btn-github:hover {
		background: #1b1f23;
	}

	.btn-dev {
		background: var(--orange-500);
		color: #fff;
		border-color: var(--orange-500);
	}

	.btn-dev:hover {
		filter: brightness(0.95);
	}

	.dev-row {
		display: flex;
		gap: 0.4rem;
		align-items: stretch;
	}

	.dev-row .btn {
		flex: 1;
	}

	.profile-select {
		font-family: var(--font-mono);
		font-size: 0.8rem;
		padding: 0 0.5rem;
		border-radius: 8px;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
	}

	.empty {
		font-size: 0.85rem;
		color: var(--color-text-muted);
		text-align: center;
	}

	.empty code {
		background: var(--color-border-subtle);
		padding: 0.1rem 0.3rem;
		border-radius: 3px;
		font-size: 0.8rem;
	}

	.btn-primary {
		background: var(--color-primary);
		color: #fff;
		border-color: var(--color-primary);
	}

	.btn-primary:hover {
		background: var(--color-primary-hover);
		border-color: var(--color-primary-hover);
	}

	.btn-primary:disabled {
		opacity: 0.6;
		cursor: default;
	}

	.magic-form {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.magic-input {
		padding: 0.7rem 0.85rem;
		border-radius: 8px;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
		font-size: 0.9rem;
	}

	.magic-input:focus {
		outline: none;
		border-color: var(--color-primary);
		box-shadow: 0 0 0 3px rgba(99, 89, 217, 0.15);
	}

	.magic-error {
		margin: 0;
		font-size: 0.8rem;
		color: var(--color-danger);
		text-align: center;
	}

	.magic-sent {
		text-align: center;
		padding: 0.5rem 0;
	}

	.magic-sent-title {
		margin: 0 0 0.4rem 0;
		font-size: 1rem;
		font-weight: 600;
		color: var(--color-text);
	}

	.magic-sent-body {
		margin: 0;
		font-size: 0.85rem;
		line-height: 1.5;
		color: var(--color-text-muted);
	}

	.magic-dev-link {
		display: inline-block;
		margin-top: 0.75rem;
		font-family: var(--font-mono);
		font-size: 0.8rem;
		color: var(--color-primary);
	}
</style>

<script lang="ts">
	/**
	 * BYOC (Bring Your Own OAuth app) input section for the Create Service
	 * flow. Collapsible by default; forced open and marked required when no
	 * org or system fallback exists for the provider. SPEC §7 tier 1.
	 */

	let {
		provider,
		required = false,
		defaultExpanded = false,
		disabled = false,
		alreadyConfigured = false,
		clientId = $bindable(''),
		clientSecret = $bindable(''),
		providerDisplayName = '',
		scopes = [],
		redirectUri = '',
		jsOrigin = ''
	}: {
		provider: string;
		required?: boolean;
		defaultExpanded?: boolean;
		disabled?: boolean;
		/** Caller has a BYOC credential for this provider already. Changes
		 * the toggle into a "Replace" affordance and surfaces a configured
		 * badge so the current state is obvious even when collapsed. */
		alreadyConfigured?: boolean;
		clientId?: string;
		clientSecret?: string;
		providerDisplayName?: string;
		/** Service-level scope union the OAuth app's consent screen will
		 * request. Shown so the user knows what their app must authorize. */
		scopes?: string[];
		/** Authorized redirect URI the user must register in their OAuth app. */
		redirectUri?: string;
		/** Authorized JavaScript origin to register alongside the redirect URI. */
		jsOrigin?: string;
	} = $props();

	let expanded = $state(false);
	let reveal = $state(false);

	// Force-open whenever required flips true or defaultExpanded is set.
	$effect(() => {
		if (required || defaultExpanded) expanded = true;
	});

	const label = $derived(providerDisplayName || provider);

	// Internal docs guide on creating your own OAuth app per provider. Relative
	// `/docs/...` path so it resolves against whichever host the dashboard runs
	// under (matches the convention used elsewhere in the dashboard).
	const DOCS_URL = '/docs/guide/connections/bring-your-own-oauth';

	const placeholders: Record<string, string> = {
		google: 'e.g. 1234567890-abc.apps.googleusercontent.com',
		github: 'e.g. Iv1.abc123def456',
		slack: 'e.g. 1234567890.1234567890',
		microsoft: 'e.g. 12345678-abcd-1234-abcd-123456789abc',
	};
	const clientIdPlaceholder = $derived(placeholders[provider] ?? 'Paste client ID');

	// Track which setup value was most recently copied so we can flash a
	// confirmation on its button. Cleared after a short delay.
	let copied = $state<string | null>(null);
	async function copy(value: string, key: string) {
		try {
			await navigator.clipboard.writeText(value);
			copied = key;
			setTimeout(() => {
				if (copied === key) copied = null;
			}, 1500);
		} catch {
			/* clipboard unavailable — user can still select the text manually */
		}
	}

	// When the caller already has a BYOC credential for this provider we render
	// a read-only confirmation card instead of the paste form. Replacing a
	// BYOC would invalidate every existing connection that was authorized
	// against the old OAuth app, so we route that flow through a separate UI
	// (tracked in TECH_DEBT.md) rather than surfacing it inline here.
</script>

{#if alreadyConfigured && !required}
	<section class="byoc configured">
		<div class="configured-row">
			<span class="check" aria-hidden="true">✓</span>
			<span class="configured-title">Your {label} OAuth app is configured</span>
		</div>
		<p class="configured-hint">
			To replace it, remove it from your profile first. Replacing here would
			invalidate existing {label} connections.
		</p>
	</section>
{:else}
<section class="byoc" class:expanded class:required>
	<header>
		<button
			type="button"
			class="toggle"
			onclick={() => {
				if (!required) expanded = !expanded;
			}}
			aria-expanded={expanded}
			disabled={required}
		>
			<span class="caret" aria-hidden="true">{expanded ? '▾' : '▸'}</span>
			<span class="title">Use your own OAuth app</span>
			{#if required}
				<span class="pill">Required</span>
			{:else}
				<span class="optional">optional</span>
			{/if}
		</button>
	</header>

	{#if expanded}
		<div class="body">
			<p class="hint">
				{#if required}
					No org or system credentials are configured for {label}. Paste your OAuth app's
					Client ID and Client Secret to continue.
				{:else}
					Override org/system credentials with your own {label} OAuth app.
				{/if}
			</p>

			{#if scopes.length}
				<div class="scopes">
					<span class="label">Scopes this connection will request</span>
					<ul>
						{#each scopes as s}
							<li><code>{s}</code></li>
						{/each}
					</ul>
				</div>
			{/if}

			{#if redirectUri || jsOrigin}
				<div class="setup">
					<span class="label">Configure your OAuth app with these values</span>
					{#if redirectUri}
						<div class="setup-row">
							<span class="setup-key">Authorized redirect URI</span>
							<div class="setup-val">
								<code>{redirectUri}</code>
								<button
									type="button"
									class="copy"
									onclick={() => copy(redirectUri, 'redirect')}
								>
									{copied === 'redirect' ? 'Copied' : 'Copy'}
								</button>
							</div>
						</div>
					{/if}
					{#if jsOrigin}
						<div class="setup-row">
							<span class="setup-key">Authorized JavaScript origin</span>
							<div class="setup-val">
								<code>{jsOrigin}</code>
								<button
									type="button"
									class="copy"
									onclick={() => copy(jsOrigin, 'origin')}
								>
									{copied === 'origin' ? 'Copied' : 'Copy'}
								</button>
							</div>
						</div>
					{/if}
				</div>
			{/if}

			<label class="field">
				<span class="label">Client ID</span>
				<input
					type="text"
					bind:value={clientId}
					{disabled}
					autocomplete="off"
					spellcheck="false"
					placeholder={clientIdPlaceholder}
				/>
			</label>

			<label class="field">
				<span class="label">Client Secret</span>
				<div class="input-wrap">
					<input
						type={reveal ? 'text' : 'password'}
						bind:value={clientSecret}
						{disabled}
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
						{disabled}
					>
						{reveal ? 'Hide' : 'Show'}
					</button>
				</div>
			</label>

			<a
				class="help"
				href={DOCS_URL}
				target="_blank"
				rel="noopener noreferrer"
			>
				How to set up your own OAuth app →
			</a>
		</div>
	{/if}
</section>
{/if}

<style>
	.byoc {
		border: 1px solid var(--color-border);
		border-radius: 8px;
		background: var(--color-bg);
	}
	.byoc.required {
		border-color: var(--color-primary, #6366f1);
	}
	header {
		display: flex;
	}
	.toggle {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		width: 100%;
		padding: 0.6rem 0.8rem;
		background: none;
		border: none;
		cursor: pointer;
		font: inherit;
		color: inherit;
		text-align: left;
	}
	.toggle[disabled] {
		cursor: default;
	}
	.caret {
		display: inline-block;
		width: 1rem;
		color: var(--color-text-muted);
	}
	.title {
		font-weight: 500;
		font-size: 0.88rem;
	}
	.pill {
		margin-left: auto;
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		padding: 0.15rem 0.5rem;
		border-radius: 4px;
		background: var(--color-primary, #6366f1);
		color: white;
	}
	.optional {
		margin-left: auto;
		font-size: 0.72rem;
		color: var(--color-text-muted);
	}
	.body {
		padding: 0.8rem;
		border-top: 1px solid var(--color-border);
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	.hint {
		margin: 0;
		font-size: 0.8rem;
		color: var(--color-text-muted);
	}
	.scopes {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}
	.scopes ul {
		margin: 0;
		padding-left: 1.1rem;
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
	}
	.scopes li {
		font-size: 0.78rem;
		color: var(--color-text-muted);
	}
	.scopes code {
		font-size: 0.76rem;
		word-break: break-all;
	}
	.setup {
		display: flex;
		flex-direction: column;
		gap: 0.45rem;
	}
	.setup-row {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
	}
	.setup-key {
		font-size: 0.74rem;
		color: var(--color-text-muted);
	}
	.setup-val {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		padding: 0.35rem 0.5rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-surface);
	}
	.setup-val code {
		font-size: 0.78rem;
		word-break: break-all;
		flex: 1;
	}
	.copy {
		background: none;
		border: none;
		font: inherit;
		font-size: 0.74rem;
		color: var(--color-primary, #6366f1);
		cursor: pointer;
		padding: 0.1rem 0.3rem;
		flex-shrink: 0;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}
	.label {
		font-size: 0.72rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-weight: 600;
	}
	input[type='text'],
	input[type='password'] {
		padding: 0.5rem 0.7rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: inherit;
		font: inherit;
		font-size: 0.88rem;
		width: 100%;
		box-sizing: border-box;
	}
	.input-wrap {
		position: relative;
	}
	.input-wrap input {
		padding-right: 4.5rem;
	}
	.reveal {
		position: absolute;
		right: 0.4rem;
		top: 50%;
		transform: translateY(-50%);
		background: none;
		border: none;
		font: inherit;
		font-size: 0.78rem;
		color: var(--color-primary, #6366f1);
		cursor: pointer;
		padding: 0.2rem 0.4rem;
	}
	.help {
		font-size: 0.78rem;
		color: var(--color-primary, #6366f1);
		text-decoration: none;
	}
	.help:hover {
		text-decoration: underline;
	}
	.byoc.configured {
		padding: 0.65rem 0.8rem;
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}
	.configured-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.88rem;
	}
	.check {
		color: #15803d;
		font-weight: 700;
	}
	.configured-title {
		font-weight: 500;
	}
	.configured-hint {
		margin: 0;
		font-size: 0.75rem;
		color: var(--color-text-muted);
	}
</style>

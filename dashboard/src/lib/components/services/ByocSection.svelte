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
		clientId = $bindable(''),
		clientSecret = $bindable(''),
		providerDisplayName = ''
	}: {
		provider: string;
		required?: boolean;
		defaultExpanded?: boolean;
		disabled?: boolean;
		clientId?: string;
		clientSecret?: string;
		providerDisplayName?: string;
	} = $props();

	let expanded = $state(false);
	let reveal = $state(false);

	// Force-open whenever required flips true or defaultExpanded is set.
	$effect(() => {
		if (required || defaultExpanded) expanded = true;
	});

	const label = $derived(providerDisplayName || provider);
</script>

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
					Override org/system credentials with your own {label} OAuth app
					(e.g. from your personal GCP project).
				{/if}
			</p>

			<label class="field">
				<span class="label">Client ID</span>
				<input
					type="text"
					bind:value={clientId}
					{disabled}
					autocomplete="off"
					spellcheck="false"
					placeholder="e.g. 1234567890-abc.apps.googleusercontent.com"
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
				href="https://support.google.com/cloud/answer/6158849"
				target="_blank"
				rel="noopener noreferrer"
			>
				How to create your own OAuth app →
			</a>
		</div>
	{/if}
</section>

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
</style>

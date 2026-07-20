<script lang="ts">
	import SecretNamePicker from '$lib/components/SecretNamePicker.svelte';
	import type { SecretSlot, SecretSummary } from '$lib/types';

	let {
		slots,
		credentials = $bindable<Record<string, string>>({}),
		available,
		loading = false,
		idPrefix = 'svc-cred'
	}: {
		/**
		 * The credential slots the template declares — one picker each. A
		 * template needing one secret declares one slot; `services/email.yaml`
		 * declares a username and a password that its header joins.
		 */
		slots: SecretSlot[];
		credentials: Record<string, string>;
		available: SecretSummary[];
		loading?: boolean;
		idPrefix?: string;
	} = $props();

	/** Label when the template declares exactly one credential slot. */
	const SINGLE_LABEL = 'Secret name';

	// One slot is unambiguous — keep the familiar generic label. Several must
	// be told apart by their slot key ("mailbox_user", "mailbox_pass").
	const showSlotLabels = $derived(slots.length > 1);
	const vaultNames = $derived(new Set(available.map((s) => s.name)));

	// Human-readable row naming, taken from the template YAML: the slot's
	// `label` ("Mailbox username") names the row; its `description` renders as
	// help text under the picker. No label falls back to the slot key
	// ("mailbox_user secret name") / `SINGLE_LABEL`.
	function rowLabel(s: SecretSlot): string {
		const l = (s.label ?? '').trim();
		if (l) return l;
		return showSlotLabels ? `${s.key} secret name` : SINGLE_LABEL;
	}

	// Every slot key must hold a string BEFORE the pickers render — binding
	// an undefined map slot into SecretNamePicker's fallback-valued `value`
	// prop is a Svelte error (props_invalid_value). Init-time loop covers the
	// first render; the effect covers `slots` changing under a live map.
	// svelte-ignore state_referenced_locally
	for (const s of slots) {
		if (s.key && credentials[s.key] === undefined) credentials[s.key] = '';
	}
	$effect(() => {
		for (const s of slots) {
			if (s.key && credentials[s.key] === undefined) credentials[s.key] = '';
		}
	});
</script>

{#each slots as s (s.key)}
	{@const key = s.key}
	{@const isOrg = s.source === 'org'}
	{@const bound = (credentials[key] ?? '').trim().length > 0}
	<div class="field">
		<label class="label" for="{idPrefix}-{key}">
			{rowLabel(s)}
			{#if s.optional}<span class="cred-badge">optional</span>{/if}
		</label>
		<SecretNamePicker
			id="{idPrefix}-{key}"
			bind:value={credentials[key]}
			{available}
			{loading}
			placeholder={isOrg && s.default_secret_name ? s.default_secret_name : 'my-secret'}
		/>
		{#if s.description}
			<small>{s.description}</small>
		{/if}
		{#if isOrg && !bound && s.default_secret_name}
			<!-- The vault list is scoped to what THIS user can see; the org-wide
			     default may still resolve at execution time from another owner's
			     secret. Word it softly and never block saving on it. -->
			<small>
				Blank uses the org-wide <code>{s.default_secret_name}</code>{#if !loading}{vaultNames.has(
						s.default_secret_name
					)
						? ' (found in your vault)'
						: s.optional
							? ' (not set anywhere you can see — this credential is skipped)'
							: ' (not visible in your vault)'}{/if}.
			</small>
		{/if}
	</div>
{/each}

<style>
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}
	.label {
		font-size: 0.78rem;
		font-weight: 600;
		color: var(--color-text-muted);
		display: inline-flex;
		align-items: center;
		gap: 6px;
	}
	.cred-badge {
		font-size: 9px;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		font-weight: 600;
		color: var(--color-text-muted);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm);
		padding: 1px 5px;
	}
	small {
		font-size: 0.75rem;
		color: var(--color-text-muted);
	}
	small code {
		font-family: var(--font-mono);
		font-size: 0.72rem;
		background: var(--color-primary-bg);
		padding: 1px 4px;
		border-radius: var(--radius-sm);
	}
</style>

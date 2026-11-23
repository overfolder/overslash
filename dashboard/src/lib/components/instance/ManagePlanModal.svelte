<script lang="ts">
	import Modal from './Modal.svelte';
	import { extendTrial, setOrgPlan, startTrial, type InstanceOrg } from '#lib/api/instance.ts';
	import { isoDate } from './format.ts';
	import { mutationError } from './errors.ts';

	let {
		org,
		defaultDays,
		onClose,
		onSaved
	}: {
		org: InstanceOrg;
		defaultDays: number;
		onClose: () => void;
		onSaved: (message: string) => void;
	} = $props();

	type Plan = 'standard' | 'trial' | 'free_unlimited';
	// svelte-ignore state_referenced_locally
	let plan = $state<Plan>((org.plan as Plan) ?? 'standard');
	// svelte-ignore state_referenced_locally
	let days = $state(defaultDays);
	let busy = $state(false);
	let error = $state<string | null>(null);

	const onTrial = $derived(org.plan === 'trial');
	const unchanged = $derived(plan === org.plan && plan !== 'trial');
	const daysValid = $derived(Number.isInteger(days) && days >= 1 && days <= 3650);
	const action = $derived(
		plan === 'trial' ? (onTrial ? 'Extend Trial' : 'Start Trial') : 'Save Plan'
	);

	const options: { value: Plan; label: string; help: string }[] = $derived([
		{
			value: 'standard',
			label: 'Standard',
			help: 'The normal plan. Billed per seat when cloud billing is on.'
		},
		{
			value: 'trial',
			label: onTrial ? 'Trial — extend' : 'Trial',
			help: 'Members see a trial banner with the end date. Enforcement is banner-only.'
		},
		{
			value: 'free_unlimited',
			label: 'Free unlimited',
			help: 'No billing and no rate limits. For internal and partner orgs.'
		}
	]);

	async function save() {
		busy = true;
		error = null;
		try {
			if (plan === 'trial') {
				if (onTrial) await extendTrial(org.id, days);
				else await startTrial(org.id, days);
			} else {
				await setOrgPlan(org.id, plan);
			}
			onSaved(
				plan === 'trial'
					? `${org.name}: trial ${onTrial ? 'extended' : 'started'}`
					: `${org.name}: plan set to ${plan === 'standard' ? 'Standard' : 'Free unlimited'}`
			);
		} catch (e) {
			error = mutationError(e);
		} finally {
			busy = false;
		}
	}
</script>

<Modal title="Manage Plan" {error} {onClose}>
	{#snippet sub()}{org.name} · <span class="slug">{org.slug}</span>{/snippet}
	<div class="radios" role="radiogroup" aria-label="Plan">
		{#each options as o (o.value)}
			<label class="radio" class:on={plan === o.value}>
				<input type="radio" name="plan" value={o.value} bind:group={plan} disabled={busy} />
				<span class="row-body">
					<span class="row-label"
						>{o.label}{#if org.plan === o.value}<span class="tag">current</span>{/if}</span
					>
					<span class="help">{o.help}</span>
				</span>
			</label>
		{/each}
	</div>
	{#if plan === 'trial'}
		<div class="field">
			<label for="trial-days">{onTrial ? 'Extend by' : 'Duration'}</label>
			<div class="inline">
				<input id="trial-days" type="number" min="1" max="3650" bind:value={days} disabled={busy} />
				<span class="muted">days</span>
			</div>
			<span class="hint"
				>{onTrial && org.trial_ends_at ? `Currently ends ${isoDate(org.trial_ends_at)}. ` : ''}Default
				is {defaultDays} days (<code>TRIAL_DEFAULT_DURATION_DAYS</code>).</span
			>
		</div>
	{/if}
	{#snippet footer()}
		<button class="btn" type="button" onclick={onClose} disabled={busy}>Cancel</button>
		<button
			class="btn btn-primary"
			type="button"
			onclick={save}
			disabled={busy || unchanged || (plan === 'trial' && !daysValid)}
			>{busy ? 'Saving…' : action}</button
		>
	{/snippet}
</Modal>

<style>
	.slug {
		font-family: var(--font-mono);
		font-size: 12px;
	}
	.radios {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.radio {
		display: flex;
		gap: 10px;
		align-items: flex-start;
		padding: 10px 12px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		cursor: pointer;
	}
	.radio.on {
		border-color: var(--color-primary);
		background: var(--color-primary-bg);
	}
	.radio input {
		margin-top: 3px;
		accent-color: var(--color-primary);
	}
	.row-body {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.row-label {
		font: var(--text-body-medium);
		color: var(--color-text-heading);
	}
	.tag {
		margin-left: 8px;
		font: var(--text-label-sm);
		color: var(--color-text-muted);
		border: 1px solid var(--color-border);
		border-radius: 9999px;
		padding: 0 6px;
	}
	.help,
	.hint {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.field label {
		font: var(--text-label);
		color: var(--color-text);
	}
	.inline {
		display: flex;
		align-items: center;
		gap: 8px;
	}
	.inline input {
		width: 96px;
		padding: 7px 10px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		font: var(--text-body);
		font-variant-numeric: tabular-nums;
		background: var(--color-surface);
		color: var(--color-text);
	}
	.muted {
		color: var(--color-text-muted);
	}
</style>

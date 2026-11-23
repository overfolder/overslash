<script lang="ts">
	import Modal from './Modal.svelte';
	import { createInstanceOrg, type OrgPlan } from '#lib/api/instance.ts';
	import { slugify, makeDebouncedSlugChecker, type SlugCheck } from '#lib/utils/slug.ts';
	import { mutationError } from './errors.ts';

	let {
		defaultDays,
		onClose,
		onCreated
	}: {
		defaultDays: number;
		onClose: () => void;
		onCreated: (message: string) => void;
	} = $props();

	let name = $state('');
	let slug = $state('');
	let slugTouched = $state(false);
	let plan = $state<OrgPlan>('free_unlimited');
	let busy = $state(false);
	let error = $state<string | null>(null);
	let slugCheck = $state<SlugCheck>({ kind: 'idle' });
	const scheduleSlugCheck = makeDebouncedSlugChecker((s) => (slugCheck = s));

	const canSubmit = $derived(
		name.trim() !== '' && slug !== '' && slugCheck.kind === 'available' && !busy
	);

	function onName(e: Event) {
		name = (e.currentTarget as HTMLInputElement).value;
		if (!slugTouched) {
			slug = slugify(name);
			scheduleSlugCheck(slug);
		}
	}

	function onSlug(e: Event) {
		slug = (e.currentTarget as HTMLInputElement).value;
		slugTouched = true;
		scheduleSlugCheck(slug);
	}

	async function create() {
		if (!canSubmit) return;
		busy = true;
		error = null;
		try {
			await createInstanceOrg({
				name: name.trim(),
				slug,
				plan,
				...(plan === 'trial' ? { trial_days: defaultDays } : {})
			});
			onCreated(`Created ${name.trim()}. You're its first admin.`);
		} catch (e) {
			error = mutationError(e);
		} finally {
			busy = false;
		}
	}
</script>

<Modal title="Create Org" {error} {onClose}>
	{#snippet sub()}A new tenant on this instance. You become its first admin; your current org
		stays selected.{/snippet}
	<div class="field">
		<label for="org-name">Name</label>
		<input
			id="org-name"
			value={name}
			oninput={onName}
			placeholder="Acme Research"
			disabled={busy}
		/>
	</div>
	<div class="field">
		<label for="org-slug">Slug</label>
		<input
			id="org-slug"
			class="mono"
			value={slug}
			oninput={onSlug}
			placeholder="acme-research"
			disabled={busy}
		/>
		{#if slugCheck.kind === 'invalid'}
			<span class="hint bad">{slugCheck.reason}</span>
		{:else if slugCheck.kind === 'checking'}
			<span class="hint">Checking…</span>
		{:else if slugCheck.kind === 'available'}
			<span class="hint ok">Available · used in URLs, can’t be changed later.</span>
		{:else}
			<span class="hint">Used in URLs. Can’t be changed later.</span>
		{/if}
	</div>
	<div class="field">
		<label for="org-plan">Plan</label>
		<select id="org-plan" bind:value={plan} disabled={busy}>
			<option value="free_unlimited">Free unlimited</option>
			<option value="trial">Trial — {defaultDays} days</option>
			<option value="standard">Standard</option>
		</select>
	</div>
	{#snippet footer()}
		<button class="btn" type="button" onclick={onClose} disabled={busy}>Cancel</button>
		<button class="btn btn-primary" type="button" onclick={create} disabled={!canSubmit}
			>{busy ? 'Creating…' : 'Create Org'}</button
		>
	{/snippet}
</Modal>

<style>
	.field {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	label {
		font: var(--text-label);
		color: var(--color-text);
	}
	input,
	select {
		padding: 8px 10px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		background: var(--color-surface);
		color: var(--color-text);
		font: var(--text-body);
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 13px;
	}
	.hint {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
	}
	.hint.ok {
		color: var(--color-success);
	}
	.hint.bad {
		color: var(--color-danger);
	}
</style>

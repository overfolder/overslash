<script lang="ts">
	import Badge from './Badge.svelte';
	import ManagePlanModal from './ManagePlanModal.svelte';
	import CreateOrgModal from './CreateOrgModal.svelte';
	import { listInstanceOrgs, type InstanceOrg, type InstanceOrgList } from '#lib/api/instance.ts';
	import { PLAN_LABEL, PLAN_TONE, isoDate, relativeAgo, trialBadge } from './format.ts';
	import { pushToast } from '#lib/stores/toasts.svelte.ts';
	import { apiErrorReason } from '#lib/session.ts';

	let q = $state('');
	let planFilter = $state('all');
	let showPersonal = $state(false);
	let data = $state<InstanceOrgList | null>(null);
	let loadError = $state<string | null>(null);
	let manage = $state<InstanceOrg | null>(null);
	let creating = $state(false);

	async function load() {
		try {
			data = await listInstanceOrgs(showPersonal);
			loadError = null;
		} catch (e) {
			loadError = apiErrorReason(e) ?? 'Could not load orgs.';
		}
	}

	$effect(() => {
		// Re-fetch when the personal toggle flips; it changes the server query.
		void showPersonal;
		void load();
	});

	const rows = $derived(
		(data?.orgs ?? []).filter(
			(o) =>
				(planFilter === 'all' || o.plan === planFilter) &&
				`${o.name} ${o.slug}`.toLowerCase().includes(q.trim().toLowerCase())
		)
	);
	const defaultDays = $derived(data?.trial_default_duration_days ?? 30);

	function done(message: string) {
		manage = null;
		creating = false;
		pushToast('success', message);
		void load();
	}
</script>

<div class="head">
	<div>
		<div class="group">Tenancy</div>
		<h1>Orgs</h1>
		<p class="desc">
			Every org on this instance, as a tenancy and billing unit. Start or extend trials and change
			plans without joining the org.
		</p>
	</div>
	{#if data?.allow_org_creation !== false}
		<button class="btn btn-primary" type="button" onclick={() => (creating = true)}
			>+ Create Org</button
		>
	{/if}
</div>

<div class="toolbar">
	<input
		class="search"
		type="search"
		aria-label="Filter orgs"
		placeholder="Filter by name or slug…"
		bind:value={q}
	/>
	<select class="select" aria-label="Plan" bind:value={planFilter}>
		<option value="all">All plans</option>
		<option value="standard">Standard</option>
		<option value="trial">Trial</option>
		<option value="free_unlimited">Free unlimited</option>
	</select>
	<label class="check"><input type="checkbox" bind:checked={showPersonal} /> Show personal orgs</label>
</div>

<div class="card">
	<div class="table-box">
		<table>
			<thead>
				<tr>
					<th>Org</th>
					<th>Plan</th>
					<th>Trial ends</th>
					<th>Members</th>
					<th>Last activity</th>
					<th>Created</th>
					<th><span class="sr-only">Actions</span></th>
				</tr>
			</thead>
			<tbody>
				{#if loadError}
					<tr><td colspan="7" class="empty error">{loadError}</td></tr>
				{:else if !data}
					<tr><td colspan="7" class="empty">Loading…</td></tr>
				{:else}
					{#each rows as o (o.id)}
						{@const trial = o.trial_ends_at ? trialBadge(o.trial_ends_at) : null}
						<tr>
							<td>
								<div class="org">
									<span class="org-name"
										>{o.name}{#if o.is_personal}<span class="personal">personal</span>{/if}</span
									>
									<span class="slug">{o.slug}</span>
								</div>
							</td>
							<td data-label="Plan">
								<Badge tone={PLAN_TONE[o.plan] ?? 'neutral'}>{PLAN_LABEL[o.plan] ?? o.plan}</Badge>
							</td>
							<td data-label="Trial ends">
								{#if trial && o.trial_ends_at}
									<Badge tone={trial.tone} title={isoDate(o.trial_ends_at)}>{trial.label}</Badge>
								{:else}
									<span class="muted">—</span>
								{/if}
							</td>
							<td class="num" data-label="Members">{o.member_count}</td>
							<td class="time" data-label="Last activity">
								{#if o.last_activity_at}{relativeAgo(o.last_activity_at)}{:else}<span
										class="muted">—</span
									>{/if}
							</td>
							<td class="time" data-label="Created">{isoDate(o.created_at)}</td>
							<td class="act">
								<button class="btn btn-sm" type="button" onclick={() => (manage = o)}
									>Manage Plan</button
								>
							</td>
						</tr>
					{:else}
						<tr><td colspan="7" class="empty">No orgs match.</td></tr>
					{/each}
				{/if}
			</tbody>
		</table>
	</div>
	{#if data}
		<div class="foot">
			<span>{rows.length} of {data.orgs.length} orgs</span>
			<span>{showPersonal ? 'Personal orgs shown' : 'Personal orgs hidden'}</span>
		</div>
	{/if}
</div>

<div class="boundary">
	<svg
		width="14"
		height="14"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		stroke-width="1.5"
		stroke-linecap="round"
		stroke-linejoin="round"
		aria-hidden="true"><rect width="18" height="11" x="3" y="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg
	>
	<span
		>Org contents stay with the org: no secrets, connections, approvals or members are shown here.
		To see inside an org, join it as a member. Its members see that you joined.</span
	>
</div>

{#if manage}
	<ManagePlanModal org={manage} {defaultDays} onClose={() => (manage = null)} onSaved={done} />
{/if}
{#if creating}
	<CreateOrgModal {defaultDays} onClose={() => (creating = false)} onCreated={done} />
{/if}

<style>
	.org {
		display: flex;
		flex-direction: column;
		gap: 1px;
	}
	.org-name {
		font-weight: 500;
		color: var(--color-text-heading);
	}
	.personal {
		margin-left: 6px;
		font: var(--text-label-sm);
		color: var(--color-text-muted);
	}
	.slug {
		font-family: var(--font-mono);
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.boundary {
		display: flex;
		gap: 10px;
		align-items: flex-start;
		margin-top: 16px;
		font: var(--text-body-sm);
		color: var(--color-text-secondary);
		background: var(--color-surface);
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		padding: 12px 14px;
	}
	.boundary svg {
		flex: none;
		margin-top: 1px;
		color: var(--color-text-muted);
	}
</style>

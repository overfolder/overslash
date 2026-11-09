<script lang="ts">
	import Badge from './Badge.svelte';
	import Modal from './Modal.svelte';
	import GrantAdminModal from './GrantAdminModal.svelte';
	import {
		listInstanceAdmins,
		revokeInstanceAdmin,
		type InstanceAdmin
	} from '#lib/api/instance.ts';
	import { isoDate, providerLabel, relativeAgo } from './format.ts';
	import { mutationError } from './errors.ts';
	import { pushToast } from '#lib/stores/toasts.svelte.ts';
	import { apiErrorReason } from '#lib/session.ts';

	let admins = $state<InstanceAdmin[] | null>(null);
	let loadError = $state<string | null>(null);
	let granting = $state(false);
	let revoking = $state<InstanceAdmin | null>(null);
	let busy = $state(false);
	let revokeError = $state<string | null>(null);

	async function load() {
		try {
			admins = await listInstanceAdmins();
			loadError = null;
		} catch (e) {
			loadError = apiErrorReason(e) ?? 'Could not load instance admins.';
		}
	}
	void load();

	const last = $derived((admins?.length ?? 0) <= 1);

	function label(a: InstanceAdmin): string {
		return a.name || a.email || a.user_id;
	}

	async function revoke() {
		if (!revoking) return;
		busy = true;
		revokeError = null;
		try {
			await revokeInstanceAdmin(revoking.user_id);
			const wasMe = revoking.is_you;
			pushToast('success', `Revoked instance admin from ${revoking.email ?? label(revoking)}`);
			revoking = null;
			// Revoking yourself ends your access to this panel.
			if (wasMe) window.location.href = '/';
			else void load();
		} catch (e) {
			revokeError = mutationError(e);
		} finally {
			busy = false;
		}
	}
</script>

<div class="head">
	<div>
		<div class="group">Access</div>
		<h1>Instance Admins</h1>
		<p class="desc">
			People who can manage orgs, plans and admins across this instance. Only users who sign in
			through the Overslash IdP can hold the role.
		</p>
	</div>
	<button class="btn btn-primary" type="button" onclick={() => (granting = true)}
		>+ Grant Admin</button
	>
</div>

<div class="card">
	<div class="table-box">
		<table>
			<thead>
				<tr>
					<th>User</th>
					<th>Sign-in</th>
					<th>Granted</th>
					<th>Last active</th>
					<th><span class="sr-only">Actions</span></th>
				</tr>
			</thead>
			<tbody>
				{#if loadError}
					<tr><td colspan="5" class="empty error">{loadError}</td></tr>
				{:else if !admins}
					<tr><td colspan="5" class="empty">Loading…</td></tr>
				{:else}
					{#each admins as a (a.user_id)}
						<tr>
							<td>
								<span class="person">
									<span class="avatar" aria-hidden="true">{label(a).charAt(0).toUpperCase()}</span>
									<span>
										<span class="person-name"
											>{label(a)}{#if a.is_you}<span class="tag">you</span>{/if}</span
										>
										<span class="person-mail">{a.email ?? ''}</span>
									</span>
								</span>
							</td>
							<td data-label="Sign-in"><Badge>{providerLabel(a.provider)}</Badge></td>
							<td class="time" data-label="Granted">
								{#if a.granted_at}
									{isoDate(a.granted_at)}
									{#if a.granted_by_email}<span class="muted">by {a.granted_by_email}</span>{/if}
								{:else}
									<span class="muted">Bootstrap</span>
								{/if}
							</td>
							<td class="time" data-label="Last active">
								{#if a.last_seen_at}{relativeAgo(a.last_seen_at)}{:else}<span class="muted">—</span
									>{/if}
							</td>
							<td class="act">
								{#if last}<span class="guard">The last instance admin can’t be revoked.</span>{/if}
								<button
									class="btn btn-sm btn-danger-outline"
									type="button"
									disabled={last}
									onclick={() => {
										revokeError = null;
										revoking = a;
									}}>Revoke</button
								>
							</td>
						</tr>
					{/each}
				{/if}
			</tbody>
		</table>
	</div>
</div>

{#if granting}
	<GrantAdminModal
		onClose={() => (granting = false)}
		onGranted={(msg) => {
			granting = false;
			pushToast('success', msg);
			void load();
		}}
	/>
{/if}

{#if revoking}
	<Modal title="Revoke Instance Admin" error={revokeError} onClose={() => (revoking = null)}>
		<p class="confirm">
			Revoke instance admin from <code>{revoking.email ?? label(revoking)}</code>?
			{#if revoking.is_you}You will lose access to this panel.{/if} Their org memberships and roles
			are unchanged.
		</p>
		{#snippet footer()}
			<button class="btn" type="button" onclick={() => (revoking = null)} disabled={busy}
				>Cancel</button
			>
			<button class="btn btn-danger" type="button" onclick={revoke} disabled={busy}
				>{busy ? 'Revoking…' : 'Revoke'}</button
			>
		{/snippet}
	</Modal>
{/if}

<style>
	.person {
		display: flex;
		align-items: center;
		gap: 10px;
		min-width: 0;
	}
	.person > span:last-child {
		display: flex;
		flex-direction: column;
	}
	.avatar {
		flex: none;
		width: 28px;
		height: 28px;
		border-radius: 50%;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		font-size: 12px;
		font-weight: 600;
		background: var(--color-primary-bg);
		color: var(--color-primary);
	}
	.person-name {
		font-weight: 500;
		color: var(--color-text-heading);
		display: flex;
		gap: 6px;
		align-items: center;
	}
	.person-mail {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
	}
	.tag {
		font: var(--text-label-sm);
		color: var(--color-text-muted);
		border: 1px solid var(--color-border);
		border-radius: 9999px;
		padding: 0 6px;
	}
	.guard {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
		margin-right: 8px;
	}
	.confirm {
		margin: 0;
		font: var(--text-body);
		color: var(--color-text);
	}
</style>

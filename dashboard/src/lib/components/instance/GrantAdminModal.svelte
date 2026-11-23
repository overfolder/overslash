<script lang="ts">
	import Badge from './Badge.svelte';
	import Modal from './Modal.svelte';
	import {
		grantInstanceAdmin,
		searchInstanceUsers,
		type UserSearchResult
	} from '#lib/api/instance.ts';
	import { providerLabel } from './format.ts';
	import { mutationError } from './errors.ts';

	let {
		onClose,
		onGranted
	}: {
		onClose: () => void;
		onGranted: (message: string) => void;
	} = $props();

	let q = $state('');
	let results = $state<UserSearchResult[]>([]);
	let searching = $state(false);
	let pick = $state<string | null>(null);
	let busy = $state(false);
	let error = $state<string | null>(null);

	let timer: ReturnType<typeof setTimeout> | null = null;
	let ctrl: AbortController | null = null;

	function onInput(e: Event) {
		q = (e.currentTarget as HTMLInputElement).value;
		if (timer) clearTimeout(timer);
		timer = setTimeout(search, 250);
	}

	async function search() {
		ctrl?.abort();
		const term = q.trim();
		if (term.length < 2) {
			results = [];
			return;
		}
		ctrl = new AbortController();
		searching = true;
		try {
			results = await searchInstanceUsers(term, ctrl.signal);
			if (pick && !results.some((r) => r.id === pick)) pick = null;
		} catch (e) {
			if ((e as Error)?.name !== 'AbortError') results = [];
		} finally {
			searching = false;
		}
	}

	const picked = $derived(results.find((r) => r.id === pick) ?? null);

	async function grant() {
		if (!picked) return;
		busy = true;
		error = null;
		try {
			await grantInstanceAdmin(picked.id);
			onGranted(`Granted instance admin to ${picked.email ?? picked.name ?? 'user'}`);
		} catch (e) {
			error = mutationError(e);
		} finally {
			busy = false;
		}
	}

	function display(r: UserSearchResult): string {
		return r.name || r.email || r.id;
	}
</script>

<Modal title="Grant Instance Admin" {error} {onClose}>
	{#snippet sub()}Full control over orgs, plans and admins on this instance.{/snippet}
	<!-- svelte-ignore a11y_autofocus -->
	<input
		class="search"
		type="search"
		aria-label="Search users"
		placeholder="Search users by name or email…"
		value={q}
		oninput={onInput}
		autofocus
	/>
	{#if results.length > 0}
		<div class="results" role="radiogroup" aria-label="User">
			{#each results as r (r.id)}
				{@const ok = r.eligible && !r.is_instance_admin}
				<label class="result" class:on={pick === r.id} class:off={!ok}>
					<input type="radio" name="grant" value={r.id} bind:group={pick} disabled={!ok || busy} />
					<span class="person">
						<span class="avatar" aria-hidden="true">{display(r).charAt(0).toUpperCase()}</span>
						<span class="who">
							<span class="name">{display(r)}</span>
							<span class="mail">{r.email ?? ''}</span>
						</span>
					</span>
					<span class="reason">
						{#if r.is_instance_admin}
							Already an admin
						{:else if r.eligible}
							<Badge>{providerLabel(r.provider)}</Badge>
						{:else}
							{r.reason}<br />Not eligible
						{/if}
					</span>
				</label>
			{/each}
		</div>
	{:else if q.trim().length >= 2 && !searching}
		<p class="none">No users match.</p>
	{/if}
	<p class="help">Only users who sign in through the Overslash IdP can hold this role.</p>
	{#snippet footer()}
		<button class="btn" type="button" onclick={onClose} disabled={busy}>Cancel</button>
		<button class="btn btn-primary" type="button" onclick={grant} disabled={!picked || busy}
			>{busy ? 'Granting…' : 'Grant Admin'}</button
		>
	{/snippet}
</Modal>

<style>
	.search {
		padding: 8px 10px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		background: var(--color-surface);
		color: var(--color-text);
		font: var(--text-body);
	}
	.results {
		display: flex;
		flex-direction: column;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		overflow: hidden;
	}
	.result {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 12px;
		border-top: 1px solid var(--color-border-subtle);
		cursor: pointer;
		background: var(--color-surface);
	}
	.result:first-child {
		border-top: 0;
	}
	.result.on {
		background: var(--color-primary-bg);
	}
	.result.off {
		cursor: not-allowed;
	}
	.result.off .name {
		color: var(--color-text-secondary);
	}
	.result input {
		accent-color: var(--color-primary);
	}
	.person {
		display: flex;
		align-items: center;
		gap: 10px;
		min-width: 0;
	}
	.who {
		display: flex;
		flex-direction: column;
		min-width: 0;
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
		background: var(--badge-bg-neutral);
		color: var(--color-text-secondary);
	}
	.name {
		font-weight: 500;
		color: var(--color-text-heading);
	}
	.mail,
	.reason,
	.help,
	.none {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
	}
	.reason {
		margin-left: auto;
		text-align: right;
	}
	.help,
	.none {
		margin: 0;
	}
</style>

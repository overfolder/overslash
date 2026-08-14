<script lang="ts">
	import type { Identity } from '$lib/api/groups';
	import { makeIdentityFormatter } from '$lib/identityDisplay';

	let {
		open,
		identities,
		excludeIds = [],
		allowedDomains = [],
		onPick,
		onCancel
	}: {
		open: boolean;
		identities: Identity[];
		excludeIds?: string[];
		/** Org's allowed sign-in domains; a single entry is stripped off the
		 *  emails shown here. Defaults to none so this renders standalone. */
		allowedDomains?: string[];
		onPick: (id: Identity) => void;
		onCancel: () => void;
	} = $props();

	let query = $state('');

	const fmt = $derived(makeIdentityFormatter(allowedDomains));
	const users = $derived(identities.filter((i) => i.kind === 'user'));
	// Matching runs against the raw fields, so typing either half of an address
	// finds the user whether or not the domain is stripped from the label.
	const filtered = $derived(
		users.filter((u) => {
			if (excludeIds.includes(u.id)) return false;
			if (!query.trim()) return true;
			const q = query.toLowerCase();
			return (
				(u.email ?? '').toLowerCase().includes(q) ||
				u.name.toLowerCase().includes(q) ||
				(u.external_id ?? '').toLowerCase().includes(q)
			);
		})
	);
</script>

{#if open}
	<div class="backdrop" role="dialog" aria-modal="true">
		<div class="card">
			<h2>Add member</h2>
			<input
				type="text"
				placeholder="Search by email or name…"
				bind:value={query}
				class="search"
			/>
			<ul class="list">
				{#each filtered as u (u.id)}
					{@const d = fmt.format(u)}
					<li>
						<button class="row" onclick={() => onPick(u)} title={d.title}>
							<span class="name">{d.primary}</span>
							{#if d.secondary}
								<span class="ext">{d.secondary}</span>
							{/if}
						</button>
					</li>
				{:else}
					<li class="empty">No users found.</li>
				{/each}
			</ul>
			<div class="actions">
				<button class="btn" onclick={onCancel}>Cancel</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.backdrop {
		position: fixed;
		inset: 0;
		background: rgba(23, 25, 28, 0.45);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
		padding: var(--space-4);
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
		padding: var(--space-6);
		max-width: 480px;
		width: 100%;
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	h2 {
		margin: 0;
		font: var(--text-h3);
		color: var(--color-text-heading);
	}
	.search {
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		font: var(--text-body);
		color: var(--color-text);
		background: var(--color-surface);
	}
	.list {
		list-style: none;
		margin: 0;
		padding: 0;
		max-height: 320px;
		overflow-y: auto;
		border: 1px solid var(--color-border-subtle);
		border-radius: var(--radius-md);
	}
	.list li + li {
		border-top: 1px solid var(--color-border-subtle);
	}
	.row {
		display: flex;
		justify-content: space-between;
		gap: var(--space-3);
		width: 100%;
		text-align: left;
		padding: var(--space-3);
		background: transparent;
		border: 0;
		cursor: pointer;
		font: var(--text-body);
		color: var(--color-text);
	}
	.row:hover {
		background: var(--color-primary-bg);
	}
	.name {
		font-weight: 500;
	}
	.ext {
		color: var(--color-text-muted);
		font: var(--text-body-sm);
	}
	.empty {
		padding: var(--space-4);
		color: var(--color-text-muted);
		text-align: center;
		font: var(--text-body-sm);
	}
	.actions {
		display: flex;
		justify-content: flex-end;
	}
	.btn {
		padding: var(--space-2) var(--space-4);
		border-radius: var(--radius-md);
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
		cursor: pointer;
		font: var(--text-body-medium);
	}
</style>

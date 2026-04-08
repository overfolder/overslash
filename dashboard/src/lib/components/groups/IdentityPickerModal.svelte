<script lang="ts">
	import type { Identity } from '$lib/api/groups';

	let {
		open,
		identities,
		excludeIds = [],
		onPick,
		onCancel
	}: {
		open: boolean;
		identities: Identity[];
		excludeIds?: string[];
		onPick: (id: Identity) => void;
		onCancel: () => void;
	} = $props();

	let query = $state('');

	const users = $derived(identities.filter((i) => i.kind === 'user'));
	const filtered = $derived(
		users.filter((u) => {
			if (excludeIds.includes(u.id)) return false;
			if (!query.trim()) return true;
			const q = query.toLowerCase();
			return (
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
				placeholder="Search users…"
				bind:value={query}
				class="search"
			/>
			<ul class="list">
				{#each filtered as u (u.id)}
					<li>
						<button class="row" onclick={() => onPick(u)}>
							<span class="name">{u.name}</span>
							{#if u.external_id}
								<span class="ext">{u.external_id}</span>
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

<script lang="ts">
	import type { MeIdentity } from '$lib/session';

	let { data } = $props<{ data: { user: MeIdentity } }>();
	const profile = $derived(data.user);
</script>

<svelte:head>
	<title>Profile - Overslash</title>
</svelte:head>

<div class="page">
	<h1>Profile</h1>

	<div class="profile-grid">
		<div class="card">
			<h2>Session</h2>
			<div class="field-list">
				<div class="field">
					<span class="field-label">Email</span>
					<span class="field-value">{profile.email}</span>
				</div>
				<div class="field">
					<span class="field-label">Name</span>
					<span class="field-value">{profile.name}</span>
				</div>
				<div class="field">
					<span class="field-label">Kind</span>
					<span class="field-value">
						<span class="badge">{profile.kind}</span>
					</span>
				</div>
			</div>
		</div>

		<div class="card">
			<h2>Identifiers</h2>
			<div class="field-list">
				<div class="field">
					<span class="field-label">Identity ID</span>
					<span class="field-value mono">{profile.identity_id}</span>
				</div>
				<div class="field">
					<span class="field-label">Org ID</span>
					<span class="field-value mono">{profile.org_id}</span>
				</div>
				{#if profile.external_id}
					<div class="field">
						<span class="field-label">External ID</span>
						<span class="field-value mono">{profile.external_id}</span>
					</div>
				{/if}
			</div>
		</div>
	</div>
</div>

<style>
	.page {
		max-width: 900px;
	}

	h1 {
		font: var(--text-h1);
		margin-bottom: 1.5rem;
	}

	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 1.5rem;
	}

	.card h2 {
		font-size: 1rem;
		font-weight: 600;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.05em;
		margin-bottom: 1rem;
	}

	.profile-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 1rem;
	}

	.field-list {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.field {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
	}

	.field-label {
		font-size: 0.8rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	.field-value {
		font-size: 0.95rem;
	}

	.mono {
		font-family: var(--font-mono);
		font-size: 0.85rem;
	}

	.badge {
		display: inline-block;
		background: var(--color-primary);
		color: white;
		padding: 0.15rem 0.5rem;
		border-radius: 4px;
		font-size: 0.8rem;
		font-weight: 500;
	}
</style>

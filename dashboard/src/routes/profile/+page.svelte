<script lang="ts">
	import { onMount } from 'svelte';
	import { session, ApiError } from '$lib/session';
	import type { MeIdentity } from '$lib/session';

	let profile: MeIdentity | null = $state(null);
	let error: string | null = $state(null);
	let loading = $state(true);
	let devMode = $state(false);

	async function loadProfile() {
		loading = true;
		error = null;
		try {
			profile = await session.get<MeIdentity>('/auth/me/identity');
		} catch (e) {
			if (e instanceof ApiError && e.status === 401) {
				error = 'not_authenticated';
			} else {
				error = e instanceof Error ? e.message : 'Unknown error';
			}
		} finally {
			loading = false;
		}
	}

	async function devLogin() {
		try {
			await session.get('/auth/dev/token');
			devMode = true;
			await loadProfile();
		} catch (e) {
			if (e instanceof ApiError && e.status === 404) {
				error = 'not_authenticated';
			} else {
				error = e instanceof Error ? e.message : 'Dev login failed';
			}
		}
	}

	onMount(loadProfile);
</script>

<svelte:head>
	<title>Profile - Overslash</title>
</svelte:head>

<div class="page">
	<h1>Profile</h1>

	{#if loading}
		<div class="card loading-card">
			<div class="spinner"></div>
			<p>Loading profile...</p>
		</div>
	{:else if error === 'not_authenticated'}
		<div class="card auth-card">
			<h2>Not Authenticated</h2>
			<p>Sign in to view your profile.</p>
			<div class="auth-actions">
				<a href="/auth/google/login" class="btn btn-primary">Sign in with Google</a>
				{#if import.meta.env.DEV}
					<button class="btn btn-secondary" onclick={devLogin}>Dev Login</button>
				{/if}
			</div>
		</div>
	{:else if error}
		<div class="card error-card">
			<h2>Error</h2>
			<p>{error}</p>
			<button class="btn btn-secondary" onclick={loadProfile}>Retry</button>
		</div>
	{:else if profile}
		{#if devMode}
			<div class="dev-banner">Dev mode — using local test account</div>
		{/if}

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
	{/if}
</div>

<style>
	.page {
		max-width: 900px;
	}

	h1 {
		font-size: 1.75rem;
		font-weight: 600;
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

	.loading-card {
		display: flex;
		align-items: center;
		gap: 1rem;
		color: var(--color-text-muted);
	}

	.spinner {
		width: 20px;
		height: 20px;
		border: 2px solid var(--color-border);
		border-top-color: var(--color-primary);
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}

	.auth-card {
		max-width: 400px;
	}

	.auth-card h2 {
		color: var(--color-text);
		text-transform: none;
		letter-spacing: 0;
		font-size: 1.25rem;
	}

	.auth-card p {
		color: var(--color-text-muted);
		margin-bottom: 1.5rem;
	}

	.auth-actions {
		display: flex;
		gap: 0.75rem;
	}

	.btn {
		padding: 0.6rem 1.25rem;
		border-radius: 6px;
		font-size: 0.9rem;
		font-weight: 500;
		cursor: pointer;
		border: none;
		transition:
			background 0.15s,
			opacity 0.15s;
	}

	.btn-primary {
		background: var(--color-primary);
		color: white;
		display: inline-block;
	}

	.btn-primary:hover {
		background: var(--color-primary-hover);
		color: white;
	}

	.btn-secondary {
		background: var(--color-border);
		color: var(--color-text);
	}

	.btn-secondary:hover {
		opacity: 0.8;
	}

	.error-card h2 {
		color: var(--color-danger);
		text-transform: none;
		letter-spacing: 0;
	}

	.dev-banner {
		background: #422006;
		border: 1px solid #854d0e;
		color: #fbbf24;
		padding: 0.5rem 1rem;
		border-radius: 6px;
		font-size: 0.85rem;
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

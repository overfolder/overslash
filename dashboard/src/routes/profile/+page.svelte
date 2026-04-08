<script lang="ts">
	import { session, type MeIdentity, type SecretMetadata, type PermissionRule, type EnrollmentTokenItem, type UserPreferences } from '$lib/session';
	import { theme, timeFormat } from '$lib/stores/shell';
	import { formatTime, ttlRemaining } from '$lib/utils/time';
	import { copyToClipboard } from '$lib/utils/clipboard';
	import { invalidateAll } from '$app/navigation';

	let { data } = $props<{
		data: {
			user: MeIdentity;
			secrets: SecretMetadata[];
			permissions: PermissionRule[];
			enrollmentTokens: EnrollmentTokenItem[];
			preferences: UserPreferences;
		};
	}>();

	const profile = $derived(data.user);
	const initials = $derived(
		(profile.name || profile.email || '?')
			.split(/\s+/)
			.map((s: string) => s[0])
			.filter(Boolean)
			.slice(0, 2)
			.join('')
			.toUpperCase()
	);

	let busy = $state<string | null>(null);
	let error = $state<string | null>(null);
	let copiedId = $state<string | null>(null);

	async function deleteSecret(name: string) {
		if (!confirm(`Delete secret "${name}"? This cannot be undone.`)) return;
		busy = `secret:${name}`;
		error = null;
		try {
			await session.delete(`/v1/secrets/${encodeURIComponent(name)}`);
			await invalidateAll();
		} catch (e) {
			error = `Failed to delete secret: ${(e as Error).message}`;
		} finally {
			busy = null;
		}
	}

	async function revokePermission(id: string) {
		if (!confirm('Revoke this remembered approval?')) return;
		busy = `perm:${id}`;
		error = null;
		try {
			await session.delete(`/v1/permissions/${id}`);
			await invalidateAll();
		} catch (e) {
			error = `Failed to revoke: ${(e as Error).message}`;
		} finally {
			busy = null;
		}
	}

	async function revokeEnrollment(id: string) {
		if (!confirm('Revoke this enrollment token?')) return;
		busy = `tok:${id}`;
		error = null;
		try {
			await session.delete(`/v1/enrollment-tokens/${id}`);
			await invalidateAll();
		} catch (e) {
			error = `Failed to revoke: ${(e as Error).message}`;
		} finally {
			busy = null;
		}
	}

	async function copy(id: string, value: string) {
		const ok = await copyToClipboard(value);
		if (ok) {
			copiedId = id;
			setTimeout(() => {
				if (copiedId === id) copiedId = null;
			}, 1500);
		}
	}
</script>

<svelte:head>
	<title>Profile - Overslash</title>
</svelte:head>

<div class="page">
	<h1>Profile</h1>

	{#if error}
		<div class="error-banner">{error}</div>
	{/if}

	<!-- 1. Header -->
	<div class="card header-card">
		<div class="avatar">
			{#if profile.picture}
				<img src={profile.picture} alt="" />
			{:else}
				<span>{initials}</span>
			{/if}
		</div>
		<div class="header-info">
			<h2 class="name">{profile.name}</h2>
			<div class="email">{profile.email}</div>
			<div class="meta">
				{#if profile.org_name}
					<span class="meta-item">{profile.org_name}</span>
				{/if}
				<span class="badge">{profile.kind}</span>
				{#if profile.is_org_admin}
					<span class="badge badge-success">Org admin</span>
				{/if}
			</div>
		</div>
	</div>

	<!-- 2. Secrets -->
	<div class="card">
		<h2>My secrets</h2>
		<p class="muted small">Secret values are never displayed. Stored in the org vault.</p>
		{#if data.secrets.length === 0}
			<p class="empty">No secrets stored.</p>
		{:else}
			<ul class="list">
				{#each data.secrets as secret (secret.name)}
					<li class="row">
						<div class="row-main">
							<div class="row-title mono">{secret.name}</div>
							<div class="row-sub">v{secret.current_version}</div>
						</div>
						<button
							class="btn btn-danger"
							disabled={busy === `secret:${secret.name}`}
							onclick={() => deleteSecret(secret.name)}
						>
							Delete
						</button>
					</li>
				{/each}
			</ul>
		{/if}
	</div>

	<!-- 3. Remembered approvals -->
	<div class="card">
		<h2>Remembered approvals</h2>
		<p class="muted small">"Allow &amp; remember" rules — auto-approve matching actions.</p>
		{#if data.permissions.length === 0}
			<p class="empty">No remembered rules.</p>
		{:else}
			<ul class="list">
				{#each data.permissions as rule (rule.id)}
					<li class="row">
						<div class="row-main">
							<div class="row-title mono">{rule.action_pattern}</div>
							<div class="row-sub">
								<span class="pill pill-{rule.effect}">{rule.effect}</span>
								<span>TTL: {ttlRemaining(rule.expires_at)}</span>
								<span>Created {formatTime(rule.created_at)}</span>
							</div>
						</div>
						<button
							class="btn btn-danger"
							disabled={busy === `perm:${rule.id}`}
							onclick={() => revokePermission(rule.id)}
						>
							Revoke
						</button>
					</li>
				{/each}
			</ul>
		{/if}
	</div>

	<!-- 4. Enrollment tokens -->
	<div class="card">
		<h2>Enrollment tokens</h2>
		<p class="muted small">Active tokens that can enroll a new agent identity.</p>
		{#if data.enrollmentTokens.length === 0}
			<p class="empty">No active enrollment tokens.</p>
		{:else}
			<ul class="list">
				{#each data.enrollmentTokens as tok (tok.id)}
					<li class="row">
						<div class="row-main">
							<div class="row-title mono">{tok.token_prefix}…</div>
							<div class="row-sub">
								<span>Identity <span class="mono">{tok.identity_id}</span></span>
								<span>Expires {formatTime(tok.expires_at)}</span>
							</div>
						</div>
						<div class="row-actions">
							<button class="btn" onclick={() => copy(tok.id, tok.token_prefix)}>
								{copiedId === tok.id ? 'Copied' : 'Copy'}
							</button>
							<button
								class="btn btn-danger"
								disabled={busy === `tok:${tok.id}`}
								onclick={() => revokeEnrollment(tok.id)}
							>
								Revoke
							</button>
						</div>
					</li>
				{/each}
			</ul>
		{/if}
	</div>

	<!-- 5. Settings -->
	<div class="card">
		<h2>Settings</h2>
		<div class="settings-grid">
			<label class="setting">
				<span class="setting-label">Time display</span>
				<select bind:value={$timeFormat}>
					<option value="relative">Relative (5m ago)</option>
					<option value="absolute">Absolute (timestamp)</option>
				</select>
			</label>
			<label class="setting">
				<span class="setting-label">Theme</span>
				<select bind:value={$theme}>
					<option value="light">Light</option>
					<option value="dark">Dark</option>
				</select>
			</label>
		</div>
		<p class="muted small">Synced to your account.</p>
	</div>
</div>

<style>
	.page {
		max-width: 900px;
		display: flex;
		flex-direction: column;
		gap: 1.25rem;
	}
	h1 {
		font: var(--text-h1);
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
		margin: 0 0 0.5rem;
	}
	.muted {
		color: var(--color-text-muted);
	}
	.small {
		font-size: 0.85rem;
	}
	.empty {
		color: var(--color-text-muted);
		font-size: 0.9rem;
		margin: 0.5rem 0 0;
	}
	.error-banner {
		background: var(--color-danger, #d93636);
		color: white;
		padding: 0.75rem 1rem;
		border-radius: 6px;
		font-size: 0.9rem;
	}

	/* Header */
	.header-card {
		display: flex;
		gap: 1.25rem;
		align-items: center;
	}
	.avatar {
		width: 72px;
		height: 72px;
		border-radius: 50%;
		background: var(--color-primary);
		color: white;
		display: flex;
		align-items: center;
		justify-content: center;
		font-size: 1.75rem;
		font-weight: 600;
		overflow: hidden;
		flex-shrink: 0;
	}
	.avatar img {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}
	.header-info {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		min-width: 0;
	}
	.name {
		text-transform: none;
		letter-spacing: 0;
		color: var(--color-text);
		font-size: 1.4rem;
		margin: 0;
	}
	.email {
		color: var(--color-text-muted);
		font-size: 0.95rem;
	}
	.meta {
		display: flex;
		gap: 0.5rem;
		align-items: center;
		flex-wrap: wrap;
		margin-top: 0.35rem;
	}
	.meta-item {
		font-size: 0.85rem;
		color: var(--color-text-secondary, var(--color-text-muted));
	}

	/* Lists */
	.list {
		list-style: none;
		padding: 0;
		margin: 0.75rem 0 0;
		display: flex;
		flex-direction: column;
		border-top: 1px solid var(--color-border);
	}
	.row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		padding: 0.75rem 0;
		border-bottom: 1px solid var(--color-border);
	}
	.row-main {
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
	}
	.row-title {
		font-size: 0.95rem;
		color: var(--color-text);
		overflow: hidden;
		text-overflow: ellipsis;
	}
	.row-sub {
		font-size: 0.8rem;
		color: var(--color-text-muted);
		display: flex;
		gap: 0.75rem;
		flex-wrap: wrap;
	}
	.row-actions {
		display: flex;
		gap: 0.5rem;
	}

	.mono {
		font-family: var(--font-mono);
		font-size: 0.85rem;
	}

	/* Badges */
	.badge {
		display: inline-block;
		background: var(--color-primary);
		color: white;
		padding: 0.15rem 0.5rem;
		border-radius: 4px;
		font-size: 0.75rem;
		font-weight: 500;
	}
	.badge-success {
		background: var(--color-success, #2da44e);
	}
	.pill {
		display: inline-block;
		padding: 0.05rem 0.4rem;
		border-radius: 999px;
		font-size: 0.75rem;
		font-weight: 500;
		background: var(--color-border);
		color: var(--color-text);
	}
	.pill-allow {
		background: rgba(45, 164, 78, 0.15);
		color: var(--color-success, #2da44e);
	}
	.pill-deny {
		background: rgba(217, 54, 54, 0.15);
		color: var(--color-danger, #d93636);
	}

	/* Buttons */
	.btn {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		color: var(--color-text);
		padding: 0.35rem 0.75rem;
		border-radius: 6px;
		font-size: 0.85rem;
		cursor: pointer;
	}
	.btn:hover {
		background: var(--color-border);
	}
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn-danger {
		border-color: var(--color-danger, #d93636);
		color: var(--color-danger, #d93636);
	}
	.btn-danger:hover {
		background: var(--color-danger, #d93636);
		color: white;
	}

	/* Settings */
	.settings-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 1rem;
		margin-top: 0.5rem;
	}
	.setting {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}
	.setting-label {
		font-size: 0.8rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.setting select {
		padding: 0.4rem 0.6rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
		font-size: 0.9rem;
	}

	@media (max-width: 600px) {
		.settings-grid {
			grid-template-columns: 1fr;
		}
		.header-card {
			flex-direction: column;
			align-items: flex-start;
		}
	}
</style>

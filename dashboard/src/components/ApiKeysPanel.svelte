<script lang="ts">
	import { getApiKeys, createApiKey, revokeApiKey } from '$lib/api';
	import type { ApiKey, CreatedApiKey } from '$lib/types';

	let {
		identityId,
		orgId
	}: {
		identityId: string;
		orgId: string;
	} = $props();

	let keys = $state<ApiKey[]>([]);
	let loading = $state(true);
	let newKeyName = $state('');
	let justCreated = $state<CreatedApiKey | null>(null);
	let copied = $state(false);

	async function loadKeys() {
		loading = true;
		try {
			keys = await getApiKeys(identityId);
		} finally {
			loading = false;
		}
	}

	async function handleGenerate() {
		if (!newKeyName.trim()) return;
		const result = await createApiKey({
			org_id: orgId,
			identity_id: identityId,
			name: newKeyName.trim()
		});
		justCreated = result;
		newKeyName = '';
		await loadKeys();
	}

	async function handleRevoke(id: string) {
		await revokeApiKey(id);
		justCreated = null;
		await loadKeys();
	}

	async function copyKey() {
		if (justCreated) {
			await navigator.clipboard.writeText(justCreated.key);
			copied = true;
			setTimeout(() => (copied = false), 2000);
		}
	}

	// Load keys on mount
	$effect(() => {
		loadKeys();
	});
</script>

<div class="api-keys-panel">
	{#if loading}
		<p class="muted">Loading keys...</p>
	{:else}
		{#if justCreated}
			<div class="new-key-alert">
				<strong>New API Key Created</strong> — copy it now, it won't be shown again:
				<div class="key-display">
					<code>{justCreated.key}</code>
					<button class="btn btn-small" onclick={copyKey}>
						{copied ? 'Copied!' : 'Copy'}
					</button>
				</div>
			</div>
		{/if}

		{#if keys.length === 0}
			<p class="muted">No API keys yet.</p>
		{:else}
			<table class="keys-table">
				<thead>
					<tr>
						<th>Name</th>
						<th>Prefix</th>
						<th>Last Used</th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					{#each keys as key}
						<tr>
							<td>{key.name}</td>
							<td><code>{key.key_prefix}...</code></td>
							<td class="muted">{key.last_used_at || 'Never'}</td>
							<td>
								<button class="btn btn-small btn-danger" onclick={() => handleRevoke(key.id)}>
									Revoke
								</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}

		<div class="generate-form">
			<input
				type="text"
				bind:value={newKeyName}
				placeholder="Key name..."
				onkeydown={(e) => e.key === 'Enter' && handleGenerate()}
			/>
			<button class="btn btn-primary" onclick={handleGenerate} disabled={!newKeyName.trim()}>
				Generate Key
			</button>
		</div>
	{/if}
</div>

<style>
	.api-keys-panel {
		background: #fafafa;
		border: 1px solid #e0e0e0;
		border-radius: 6px;
		padding: 12px 16px;
		margin: 4px 0 8px;
	}

	.muted {
		color: #888;
		font-size: 13px;
		margin: 4px 0;
	}

	.new-key-alert {
		background: #fef9c3;
		border: 1px solid #fbbf24;
		border-radius: 4px;
		padding: 10px 12px;
		margin-bottom: 12px;
		font-size: 13px;
	}

	.key-display {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-top: 6px;
	}

	.key-display code {
		background: #fff;
		padding: 4px 8px;
		border-radius: 4px;
		font-size: 12px;
		word-break: break-all;
		flex: 1;
	}

	.keys-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 13px;
		margin-bottom: 12px;
	}

	.keys-table th {
		text-align: left;
		padding: 6px 8px;
		border-bottom: 1px solid #ddd;
		color: #666;
		font-weight: 600;
	}

	.keys-table td {
		padding: 6px 8px;
		border-bottom: 1px solid #eee;
	}

	.keys-table code {
		background: #f0f0f0;
		padding: 2px 6px;
		border-radius: 3px;
		font-size: 12px;
	}

	.generate-form {
		display: flex;
		gap: 8px;
		align-items: center;
	}

	.generate-form input {
		padding: 6px 10px;
		border: 1px solid #d0d0d0;
		border-radius: 4px;
		font-size: 13px;
		width: 180px;
	}

	.btn {
		padding: 6px 12px;
		border-radius: 4px;
		font-size: 12px;
		cursor: pointer;
		border: none;
		font-weight: 500;
	}

	.btn-small {
		padding: 4px 8px;
	}

	.btn-primary {
		background: #6366f1;
		color: #fff;
	}

	.btn-primary:disabled {
		opacity: 0.5;
	}

	.btn-danger {
		background: #fee2e2;
		color: #dc2626;
	}

	.btn-danger:hover {
		background: #fecaca;
	}
</style>

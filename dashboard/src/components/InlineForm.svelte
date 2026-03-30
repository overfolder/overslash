<script lang="ts">
	let {
		parentKind,
		onsave,
		oncancel
	}: {
		parentKind: 'org' | 'user' | 'agent';
		onsave: (name: string, kind: string) => void;
		oncancel: () => void;
	} = $props();

	let name = $state('');
	let saving = $state(false);

	// Auto-determine kind based on parent
	const kind = $derived(parentKind === 'org' ? 'user' : 'agent');
	const kindLabel = $derived(kind === 'user' ? 'User' : 'Agent');

	async function handleSave() {
		if (!name.trim()) return;
		saving = true;
		try {
			await onsave(name.trim(), kind);
		} finally {
			saving = false;
		}
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter') handleSave();
		if (e.key === 'Escape') oncancel();
	}
</script>

<div class="inline-form">
	<span class="kind-badge {kind}">{kindLabel}</span>
	<input
		data-testid="inline-name"
		type="text"
		bind:value={name}
		placeholder="Name..."
		onkeydown={handleKeydown}
		disabled={saving}
	/>
	<button
		data-testid="inline-save"
		class="btn btn-save"
		onclick={handleSave}
		disabled={!name.trim() || saving}
	>
		{saving ? 'Saving...' : 'Save'}
	</button>
	<button class="btn btn-cancel" onclick={oncancel} disabled={saving}>Cancel</button>
</div>

<style>
	.inline-form {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 6px 0;
	}

	.kind-badge {
		font-size: 11px;
		padding: 2px 8px;
		border-radius: 10px;
		font-weight: 600;
		text-transform: uppercase;
	}

	.kind-badge.user {
		background: #dbeafe;
		color: #1d4ed8;
	}

	.kind-badge.agent {
		background: #dcfce7;
		color: #15803d;
	}

	input {
		padding: 6px 10px;
		border: 1px solid #d0d0d0;
		border-radius: 4px;
		font-size: 14px;
		width: 200px;
	}

	input:focus {
		outline: none;
		border-color: #6366f1;
		box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.15);
	}

	.btn {
		padding: 6px 12px;
		border-radius: 4px;
		font-size: 13px;
		cursor: pointer;
		border: none;
		font-weight: 500;
	}

	.btn-save {
		background: #6366f1;
		color: #fff;
	}

	.btn-save:hover:not(:disabled) {
		background: #4f46e5;
	}

	.btn-save:disabled {
		opacity: 0.5;
	}

	.btn-cancel {
		background: #e0e0e0;
		color: #333;
	}
</style>

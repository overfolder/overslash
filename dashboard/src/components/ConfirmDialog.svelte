<script lang="ts">
	let {
		title,
		message,
		onconfirm,
		oncancel
	}: {
		title: string;
		message: string;
		onconfirm: () => void;
		oncancel: () => void;
	} = $props();
</script>

<!-- svelte-ignore a11y_click_events_have_key_events -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="overlay" onclick={oncancel}>
	<div class="dialog" onclick={(e) => e.stopPropagation()}>
		<h3>{title}</h3>
		<p>{message}</p>
		<div class="actions">
			<button class="btn btn-cancel" onclick={oncancel}>Cancel</button>
			<button class="btn btn-danger" data-testid="confirm-delete" onclick={onconfirm}>
				Delete
			</button>
		</div>
	</div>
</div>

<style>
	.overlay {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.4);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 100;
	}

	.dialog {
		background: #fff;
		border-radius: 8px;
		padding: 24px;
		max-width: 400px;
		width: 90%;
		box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
	}

	.dialog h3 {
		margin: 0 0 8px;
	}

	.dialog p {
		color: #666;
		margin: 0 0 20px;
		font-size: 14px;
	}

	.actions {
		display: flex;
		gap: 8px;
		justify-content: flex-end;
	}

	.btn {
		padding: 8px 16px;
		border-radius: 6px;
		font-size: 13px;
		cursor: pointer;
		border: none;
		font-weight: 500;
	}

	.btn-cancel {
		background: #e0e0e0;
		color: #333;
	}

	.btn-danger {
		background: #ef4444;
		color: #fff;
	}

	.btn-danger:hover {
		background: #dc2626;
	}
</style>

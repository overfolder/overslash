<script lang="ts">
	import ApprovalDetail from '$lib/components/ApprovalDetail.svelte';
	import type { ApprovalResponse } from '$lib/session';
	import { goto } from '$app/navigation';

	let {
		data
	}: {
		data: { approval: ApprovalResponse | null; error: string | null };
	} = $props();

	function backToQueue() {
		goto('/approvals');
	}
</script>

<svelte:head><title>Approval — Overslash</title></svelte:head>

{#if data.approval}
	<ApprovalDetail approval={data.approval} onBack={backToQueue} onResolved={backToQueue} />
{:else}
	<div class="detail-error">
		<div class="aq-wrap">
			<button class="aq-back" onclick={backToQueue}>‹ Queue</button>
			<div class="empty">{data.error ?? 'Approval not found.'}</div>
		</div>
	</div>
{/if}

<style>
	.detail-error {
		flex: 1;
		padding: 24px 32px 40px;
		width: 100%;
	}
	.aq-wrap {
		max-width: 1080px;
		margin: 0 auto;
	}
	.aq-back {
		display: inline-flex;
		align-items: center;
		gap: 7px;
		background: transparent;
		border: 0;
		padding: 4px 0;
		color: var(--color-text-secondary);
		font: var(--text-label);
		cursor: pointer;
		margin-bottom: 14px;
	}
	.aq-back:hover {
		color: var(--color-text);
	}
	.empty {
		border: 1px dashed var(--color-border);
		border-radius: 12px;
		padding: 48px 24px;
		text-align: center;
		color: var(--color-text-muted);
		font-size: 14px;
	}
</style>

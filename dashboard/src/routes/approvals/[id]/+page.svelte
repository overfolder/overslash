<script lang="ts">
	import ApprovalResolver from '$lib/components/ApprovalResolver.svelte';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();
</script>

<div class="page">
	<div class="card">
		<header class="header">
			<span class="logo">&#x2F;&#x2F; overslash</span>
			<h1>Approval request</h1>
		</header>

		{#if data.approval}
			<ApprovalResolver approval={data.approval} />
		{:else if data.error}
			<div class="empty">
				<div class="empty-title">Approval unavailable</div>
				<div class="empty-msg">{data.error.message}</div>
			</div>
		{/if}
	</div>
</div>

<style>
	.page {
		min-height: 100vh;
		display: flex;
		align-items: flex-start;
		justify-content: center;
		padding: 3rem 1.5rem;
		background: var(--color-bg);
	}
	.card {
		width: 100%;
		max-width: 640px;
		background: var(--color-bg);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 2rem 2.25rem;
		display: flex;
		flex-direction: column;
		gap: 1.5rem;
	}
	.header {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		border-bottom: 1px solid var(--color-border);
		padding-bottom: 1rem;
	}
	.logo {
		font-family: var(--font-mono);
		color: var(--color-primary);
		font-size: 0.9rem;
		font-weight: 600;
	}
	.header h1 {
		margin: 0;
		font-size: 1.4rem;
		color: var(--color-text);
	}
	.empty {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		text-align: center;
		padding: 2rem 0;
	}
	.empty-title {
		font-size: 1.05rem;
		color: var(--color-text);
		font-weight: 600;
	}
	.empty-msg {
		color: var(--color-text-muted);
		font-size: 0.9rem;
	}
</style>

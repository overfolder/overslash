<script lang="ts">
	import ApprovalResolver from '$lib/components/ApprovalResolver.svelte';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();
</script>

<div class="page">
	<header class="topbar">
		<a class="logo" href="/">Overs<span class="slash">/</span>ash</a>
	</header>

	<main class="body">
		{#if data.approval}
			<ApprovalResolver approval={data.approval} />
		{:else if data.error}
			<div class="card empty">
				<h1>Approval unavailable</h1>
				<p>{data.error.message}</p>
			</div>
		{/if}
	</main>
</div>

<style>
	.page {
		min-height: 100vh;
		background: var(--color-bg, #f7f7fa);
		display: flex;
		flex-direction: column;
	}
	.topbar {
		background: #fff;
		border-bottom: 1px solid var(--color-border);
		padding: 1rem 2rem;
	}
	.logo {
		font-weight: 700;
		font-size: 1.05rem;
		color: var(--color-text);
		text-decoration: none;
		font-family: var(--font-sans);
	}
	.slash {
		color: var(--color-primary);
	}
	.body {
		flex: 1;
		display: flex;
		justify-content: center;
		padding: 4rem 1.5rem;
	}
	.empty {
		max-width: 520px;
		background: #fff;
		border: 1px solid var(--color-border);
		border-radius: 12px;
		padding: 2rem;
		text-align: center;
		box-shadow: 0 4px 24px rgba(0, 0, 0, 0.06);
	}
	.empty h1 {
		margin: 0 0 0.5rem 0;
		font-size: 1.1rem;
	}
	.empty p {
		margin: 0;
		color: var(--color-text-muted);
		font-size: 0.9rem;
	}
</style>

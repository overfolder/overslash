<script lang="ts">
	import type { LayoutData } from './$types';

	let { data, children }: { data: LayoutData; children: any } = $props();
</script>

<div class="app">
	{#if data.session}
		<nav class="sidebar">
			<div class="sidebar-header">
				<h2>Overslash</h2>
			</div>
			<ul class="nav-links">
				<li><a href="/hierarchy" class="active">Hierarchy</a></li>
				<li><a href="#" class="disabled">Connections</a></li>
				<li><a href="#" class="disabled">Audit Log</a></li>
				<li><a href="#" class="disabled">Settings</a></li>
			</ul>
			<div class="sidebar-footer">
				<span class="user-email">{data.session.email}</span>
			</div>
		</nav>
	{/if}
	<main class={data.session ? 'with-sidebar' : ''}>
		{@render children()}
	</main>
</div>

<style>
	:global(body) {
		margin: 0;
		font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
		background: #f5f5f5;
		color: #1a1a1a;
	}

	:global(*) {
		box-sizing: border-box;
	}

	.app {
		display: flex;
		min-height: 100vh;
	}

	.sidebar {
		width: 220px;
		background: #1a1a2e;
		color: #e0e0e0;
		display: flex;
		flex-direction: column;
		flex-shrink: 0;
	}

	.sidebar-header {
		padding: 20px;
		border-bottom: 1px solid #2a2a4a;
	}

	.sidebar-header h2 {
		margin: 0;
		font-size: 18px;
		color: #fff;
	}

	.nav-links {
		list-style: none;
		padding: 0;
		margin: 12px 0;
	}

	.nav-links li a {
		display: block;
		padding: 10px 20px;
		color: #b0b0c0;
		text-decoration: none;
		font-size: 14px;
		transition: background 0.15s;
	}

	.nav-links li a:hover {
		background: #2a2a4a;
		color: #fff;
	}

	.nav-links li a.active {
		background: #2a2a4a;
		color: #fff;
		border-left: 3px solid #6366f1;
	}

	.nav-links li a.disabled {
		opacity: 0.4;
		pointer-events: none;
	}

	.sidebar-footer {
		margin-top: auto;
		padding: 16px 20px;
		border-top: 1px solid #2a2a4a;
		font-size: 12px;
		color: #888;
		word-break: break-all;
	}

	main {
		flex: 1;
		padding: 24px 32px;
		overflow-y: auto;
	}

	main.with-sidebar {
		max-width: calc(100vw - 220px);
	}
</style>

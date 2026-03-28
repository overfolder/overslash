<script lang="ts">
	let { data } = $props();

	const cards = $derived([
		{ label: 'Identities', count: data.counts.identities, href: '/identities', color: 'bg-blue-500/10 text-blue-400' },
		{ label: 'Pending Approvals', count: data.counts.approvals, href: '/approvals', color: data.counts.approvals > 0 ? 'bg-amber-500/10 text-amber-400' : 'bg-green-500/10 text-green-400' },
		{ label: 'Secrets', count: data.counts.secrets, href: '/secrets', color: 'bg-purple-500/10 text-purple-400' },
	]);
</script>

<svelte:head>
	<title>Dashboard — Overslash</title>
</svelte:head>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-bold text-white">Dashboard</h1>
		<p class="mt-1 text-sm text-zinc-400">Welcome to Overslash</p>
	</div>

	<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
		{#each cards as card}
			<a
				href={card.href}
				class="rounded-xl border border-zinc-800 bg-zinc-900 p-5 transition-colors hover:border-zinc-700"
			>
				<p class="text-sm text-zinc-400">{card.label}</p>
				<p class="mt-2 text-3xl font-bold {card.color}">{card.count}</p>
			</a>
		{/each}
	</div>
</div>

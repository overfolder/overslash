<script lang="ts">
	import { enhance } from '$app/forms';
	import { page } from '$app/stores';

	let { data, form } = $props();

	const isResolved = $derived(
		form?.resolved || data.approval.status !== 'pending'
	);
	const expired = $derived(new Date(data.approval.expires_at) < new Date());
</script>

<svelte:head>
	<title>Approve Action — Overslash</title>
</svelte:head>

<div class="w-full max-w-lg rounded-xl border border-zinc-800 bg-zinc-900 p-6">
	<div class="text-center">
		<h1 class="text-xl font-bold text-white">Action Approval Request</h1>
		<p class="mt-1 text-sm text-zinc-400">An agent is requesting permission to perform an action</p>
	</div>

	<div class="mt-6 space-y-4">
		<div>
			<p class="text-xs font-medium uppercase text-zinc-500">Action</p>
			<p class="mt-1 text-white">{data.approval.action_summary}</p>
		</div>

		<div>
			<p class="text-xs font-medium uppercase text-zinc-500">Permission Keys</p>
			<div class="mt-1 flex flex-wrap gap-1">
				{#each data.approval.permission_keys as key}
					<span class="rounded bg-zinc-800 px-2 py-1 text-xs font-mono text-zinc-300">{key}</span>
				{/each}
			</div>
		</div>

		<div>
			<p class="text-xs font-medium uppercase text-zinc-500">Expires</p>
			<p class="mt-1 text-sm text-zinc-300">
				{#if expired}
					<span class="text-red-400">Expired</span>
				{:else}
					{new Date(data.approval.expires_at).toLocaleString()}
				{/if}
			</p>
		</div>
	</div>

	{#if isResolved}
		<div class="mt-6 rounded-lg border border-zinc-700 bg-zinc-800 p-4 text-center">
			<p class="text-sm text-zinc-300">
				This approval has been
				<span class="font-medium {form?.status === 'allowed' || data.approval.status === 'allowed' ? 'text-green-400' : 'text-red-400'}">
					{form?.status ?? data.approval.status}
				</span>
			</p>
		</div>
	{:else if expired}
		<div class="mt-6 rounded-lg border border-red-800 bg-red-900/20 p-4 text-center">
			<p class="text-sm text-red-400">This approval has expired and can no longer be resolved.</p>
		</div>
	{:else}
		<div class="mt-6 flex gap-3">
			<form method="POST" action="?/resolve&token={data.token}" class="flex-1" use:enhance>
				<input type="hidden" name="decision" value="allow" />
				<button
					type="submit"
					class="w-full rounded-lg bg-green-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-green-500 transition-colors"
				>
					Allow
				</button>
			</form>
			<form method="POST" action="?/resolve&token={data.token}" class="flex-1" use:enhance>
				<input type="hidden" name="decision" value="deny" />
				<button
					type="submit"
					class="w-full rounded-lg bg-red-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-red-500 transition-colors"
				>
					Deny
				</button>
			</form>
			<form method="POST" action="?/resolve&token={data.token}" class="flex-1" use:enhance>
				<input type="hidden" name="decision" value="allow_remember" />
				<button
					type="submit"
					class="w-full rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-500 transition-colors"
					title="Allow and create a permanent permission rule"
				>
					Remember
				</button>
			</form>
		</div>
	{/if}
</div>

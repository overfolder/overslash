<script lang="ts">
	import { enhance } from '$app/forms';

	let { data, form } = $props();
	let showCreate = $state(false);
</script>

<svelte:head>
	<title>Identities — Overslash</title>
</svelte:head>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<h1 class="text-2xl font-bold text-white">Identities</h1>
		<button
			class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-colors"
			onclick={() => (showCreate = true)}
		>
			Create Identity
		</button>
	</div>

	{#if form?.error}
		<div class="rounded-md bg-red-900/50 border border-red-800 p-3 text-sm text-red-300">
			{form.error}
		</div>
	{/if}

	{#if data.identities.length === 0}
		<div class="rounded-xl border border-zinc-800 bg-zinc-900 p-12 text-center">
			<p class="text-zinc-400">No identities yet</p>
			<button
				class="mt-3 text-sm text-blue-400 hover:text-blue-300"
				onclick={() => (showCreate = true)}
			>
				Create your first identity
			</button>
		</div>
	{:else}
		<div class="overflow-x-auto rounded-xl border border-zinc-800">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-zinc-800 bg-zinc-900/50">
					<tr>
						<th class="px-4 py-3 font-medium text-zinc-400">Name</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Kind</th>
						<th class="px-4 py-3 font-medium text-zinc-400">External ID</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Created</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each data.identities as identity}
						<tr class="hover:bg-zinc-900/50">
							<td class="px-4 py-3 text-white">{identity.name}</td>
							<td class="px-4 py-3">
								<span
									class="inline-flex rounded-full px-2 py-0.5 text-xs font-medium {identity.kind === 'user' ? 'bg-blue-500/10 text-blue-400' : 'bg-purple-500/10 text-purple-400'}"
								>
									{identity.kind}
								</span>
							</td>
							<td class="px-4 py-3 text-zinc-400">{identity.external_id ?? '—'}</td>
							<td class="px-4 py-3 text-zinc-400">{new Date(identity.created_at).toLocaleDateString()}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}

	<!-- Create Dialog -->
	{#if showCreate}
		<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
			<div class="w-full max-w-md rounded-xl border border-zinc-800 bg-zinc-900 p-6">
				<h2 class="text-lg font-bold text-white">Create Identity</h2>
				<form
					method="POST"
					action="?/create"
					use:enhance={() => {
						return async ({ update }) => {
							await update();
							showCreate = false;
						};
					}}
					class="mt-4 space-y-4"
				>
					<div>
						<label for="name" class="block text-sm text-zinc-400">Name</label>
						<input
							id="name"
							name="name"
							type="text"
							required
							class="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-white placeholder-zinc-500 focus:border-blue-500 focus:outline-none"
							placeholder="My Agent"
						/>
					</div>
					<div>
						<label for="kind" class="block text-sm text-zinc-400">Kind</label>
						<select
							id="kind"
							name="kind"
							required
							class="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
						>
							<option value="user">User</option>
							<option value="agent">Agent</option>
						</select>
					</div>
					<div>
						<label for="external_id" class="block text-sm text-zinc-400">External ID (optional)</label>
						<input
							id="external_id"
							name="external_id"
							type="text"
							class="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-white placeholder-zinc-500 focus:border-blue-500 focus:outline-none"
							placeholder="ext-123"
						/>
					</div>
					<div class="flex justify-end gap-3">
						<button
							type="button"
							class="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800"
							onclick={() => (showCreate = false)}
						>
							Cancel
						</button>
						<button
							type="submit"
							class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500"
						>
							Create
						</button>
					</div>
				</form>
			</div>
		</div>
	{/if}
</div>

<script lang="ts">
	import { enhance } from '$app/forms';

	let { data, form } = $props();
	let showCreate = $state(false);
</script>

<svelte:head>
	<title>Permissions — Overslash</title>
</svelte:head>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<h1 class="text-2xl font-bold text-white">Permission Rules</h1>
		<button
			class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-colors"
			onclick={() => (showCreate = true)}
		>
			Create Rule
		</button>
	</div>

	{#if form?.error}
		<div class="rounded-md bg-red-900/50 border border-red-800 p-3 text-sm text-red-300">
			{form.error}
		</div>
	{/if}

	{#if data.permissions.length === 0}
		<div class="rounded-xl border border-zinc-800 bg-zinc-900 p-12 text-center">
			<p class="text-zinc-400">No permission rules yet</p>
		</div>
	{:else}
		<div class="overflow-x-auto rounded-xl border border-zinc-800">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-zinc-800 bg-zinc-900/50">
					<tr>
						<th class="px-4 py-3 font-medium text-zinc-400">Identity</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Action Pattern</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Effect</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Created</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Actions</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each data.permissions as perm}
						<tr class="hover:bg-zinc-900/50">
							<td class="px-4 py-3 text-zinc-400 text-xs font-mono">{perm.identity_id}</td>
							<td class="px-4 py-3 font-mono text-white text-xs">{perm.action_pattern}</td>
							<td class="px-4 py-3">
								<span class="inline-flex rounded-full px-2 py-0.5 text-xs font-medium {perm.effect === 'allow' ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}">
									{perm.effect}
								</span>
							</td>
							<td class="px-4 py-3 text-zinc-400">{new Date(perm.created_at).toLocaleDateString()}</td>
							<td class="px-4 py-3">
								<form method="POST" action="?/delete" use:enhance>
									<input type="hidden" name="id" value={perm.id} />
									<button type="submit" class="rounded bg-red-600/10 px-2.5 py-1 text-xs font-medium text-red-400 hover:bg-red-600/20">
										Delete
									</button>
								</form>
							</td>
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
				<h2 class="text-lg font-bold text-white">Create Permission Rule</h2>
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
						<label for="identity_id" class="block text-sm text-zinc-400">Identity ID</label>
						<input
							id="identity_id"
							name="identity_id"
							type="text"
							required
							class="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-white placeholder-zinc-500 focus:border-blue-500 focus:outline-none"
							placeholder="identity UUID"
						/>
					</div>
					<div>
						<label for="action_pattern" class="block text-sm text-zinc-400">Action Pattern</label>
						<input
							id="action_pattern"
							name="action_pattern"
							type="text"
							required
							class="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-white placeholder-zinc-500 focus:border-blue-500 focus:outline-none font-mono"
							placeholder="http:*:api.github.com/**"
						/>
						<p class="mt-1 text-xs text-zinc-500">Glob pattern. Examples: http:GET:*.example.com/**, http:*:api.stripe.com/**</p>
					</div>
					<div>
						<label for="effect" class="block text-sm text-zinc-400">Effect</label>
						<select
							id="effect"
							name="effect"
							class="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
						>
							<option value="allow">Allow</option>
							<option value="deny">Deny</option>
						</select>
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

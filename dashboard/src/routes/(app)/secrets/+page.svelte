<script lang="ts">
	import { enhance } from '$app/forms';

	let { data, form } = $props();
	let showCreate = $state(false);
	let showValue = $state(false);
</script>

<svelte:head>
	<title>Secrets — Overslash</title>
</svelte:head>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<h1 class="text-2xl font-bold text-white">Secrets</h1>
		<button
			class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-colors"
			onclick={() => { showCreate = true; showValue = false; }}
		>
			Create Secret
		</button>
	</div>

	{#if form?.error}
		<div class="rounded-md bg-red-900/50 border border-red-800 p-3 text-sm text-red-300">
			{form.error}
		</div>
	{/if}

	{#if data.secrets.length === 0}
		<div class="rounded-xl border border-zinc-800 bg-zinc-900 p-12 text-center">
			<p class="text-zinc-400">No secrets yet</p>
			<button
				class="mt-3 text-sm text-blue-400 hover:text-blue-300"
				onclick={() => (showCreate = true)}
			>
				Create your first secret
			</button>
		</div>
	{:else}
		<div class="overflow-x-auto rounded-xl border border-zinc-800">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-zinc-800 bg-zinc-900/50">
					<tr>
						<th class="px-4 py-3 font-medium text-zinc-400">Name</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Version</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Actions</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each data.secrets as secret}
						<tr class="hover:bg-zinc-900/50">
							<td class="px-4 py-3 font-mono text-white">{secret.name}</td>
							<td class="px-4 py-3">
								<span class="inline-flex rounded-full bg-purple-500/10 px-2 py-0.5 text-xs font-medium text-purple-400">
									v{secret.current_version}
								</span>
							</td>
							<td class="px-4 py-3">
								<form method="POST" action="?/delete" use:enhance>
									<input type="hidden" name="name" value={secret.name} />
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

	<!-- Create/Update Dialog -->
	{#if showCreate}
		<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
			<div class="w-full max-w-md rounded-xl border border-zinc-800 bg-zinc-900 p-6">
				<h2 class="text-lg font-bold text-white">Create or Update Secret</h2>
				<form
					method="POST"
					action="?/upsert"
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
							placeholder="MY_SECRET_KEY"
						/>
					</div>
					<div>
						<label for="value" class="block text-sm text-zinc-400">Value</label>
						<div class="relative">
							<input
								id="value"
								name="value"
								type={showValue ? 'text' : 'password'}
								required
								class="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 pr-16 text-white placeholder-zinc-500 focus:border-blue-500 focus:outline-none"
								placeholder="sk-..."
							/>
							<button
								type="button"
								class="absolute right-2 top-1/2 -translate-y-1/2 mt-0.5 text-xs text-zinc-400 hover:text-white"
								onclick={() => (showValue = !showValue)}
							>
								{showValue ? 'Hide' : 'Show'}
							</button>
						</div>
						<p class="mt-1 text-xs text-zinc-500">Value will be encrypted and cannot be retrieved after saving.</p>
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
							Save
						</button>
					</div>
				</form>
			</div>
		</div>
	{/if}
</div>

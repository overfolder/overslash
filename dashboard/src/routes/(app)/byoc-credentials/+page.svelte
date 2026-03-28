<script lang="ts">
	import { enhance } from '$app/forms';

	let { data, form } = $props();
	let showCreate = $state(false);
</script>

<svelte:head>
	<title>BYOC Credentials — Overslash</title>
</svelte:head>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<h1 class="text-2xl font-bold text-white">BYOC Credentials</h1>
		<button
			class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-colors"
			onclick={() => (showCreate = true)}
		>
			Register Credentials
		</button>
	</div>

	{#if form?.error}
		<div class="rounded-md bg-red-900/50 border border-red-800 p-3 text-sm text-red-300">
			{form.error}
		</div>
	{/if}

	{#if data.credentials.length === 0}
		<div class="rounded-xl border border-zinc-800 bg-zinc-900 p-12 text-center">
			<p class="text-zinc-400">No BYOC credentials yet</p>
		</div>
	{:else}
		<div class="overflow-x-auto rounded-xl border border-zinc-800">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-zinc-800 bg-zinc-900/50">
					<tr>
						<th class="px-4 py-3 font-medium text-zinc-400">Provider</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Identity</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Created</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Actions</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each data.credentials as cred}
						<tr class="hover:bg-zinc-900/50">
							<td class="px-4 py-3 font-medium text-white">{cred.provider_key}</td>
							<td class="px-4 py-3 text-zinc-400">{cred.identity_id ?? 'Org-wide'}</td>
							<td class="px-4 py-3 text-zinc-400">{new Date(cred.created_at).toLocaleDateString()}</td>
							<td class="px-4 py-3">
								<form method="POST" action="?/delete" use:enhance>
									<input type="hidden" name="id" value={cred.id} />
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
				<h2 class="text-lg font-bold text-white">Register BYOC Credentials</h2>
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
						<label for="provider" class="block text-sm text-zinc-400">Provider</label>
						<select
							id="provider"
							name="provider"
							required
							class="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
						>
							<option value="">Select provider...</option>
							<option value="github">GitHub</option>
							<option value="google">Google</option>
							<option value="slack">Slack</option>
							<option value="x">X (Twitter)</option>
						</select>
					</div>
					<div>
						<label for="client_id" class="block text-sm text-zinc-400">Client ID</label>
						<input
							id="client_id"
							name="client_id"
							type="text"
							required
							class="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-white placeholder-zinc-500 focus:border-blue-500 focus:outline-none"
						/>
					</div>
					<div>
						<label for="client_secret" class="block text-sm text-zinc-400">Client Secret</label>
						<input
							id="client_secret"
							name="client_secret"
							type="password"
							required
							class="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-white placeholder-zinc-500 focus:border-blue-500 focus:outline-none"
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
							Register
						</button>
					</div>
				</form>
			</div>
		</div>
	{/if}
</div>

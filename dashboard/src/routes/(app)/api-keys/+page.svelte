<script lang="ts">
	import { enhance } from '$app/forms';

	let { data, form } = $props();
	let showCreate = $state(false);
	let copied = $state(false);
</script>

<svelte:head>
	<title>API Keys — Overslash</title>
</svelte:head>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<h1 class="text-2xl font-bold text-white">API Keys</h1>
		<button
			class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-colors"
			onclick={() => { showCreate = true; copied = false; }}
		>
			Create API Key
		</button>
	</div>

	{#if form?.error}
		<div class="rounded-md bg-red-900/50 border border-red-800 p-3 text-sm text-red-300">
			{form.error}
		</div>
	{/if}

	<!-- One-time key display -->
	{#if form?.created_key}
		<div class="rounded-xl border border-amber-800 bg-amber-900/20 p-4">
			<p class="text-sm font-medium text-amber-300">API Key Created — {form.key_name}</p>
			<p class="mt-1 text-xs text-amber-400/80">This key will not be shown again. Copy it now.</p>
			<div class="mt-3 flex items-center gap-2">
				<code class="flex-1 rounded bg-zinc-800 px-3 py-2 text-sm font-mono text-white break-all">{form.created_key}</code>
				<button
					class="rounded bg-amber-600 px-3 py-2 text-sm font-medium text-white hover:bg-amber-500"
					onclick={() => { navigator.clipboard.writeText(form?.created_key ?? ''); copied = true; }}
				>
					{copied ? 'Copied!' : 'Copy'}
				</button>
			</div>
		</div>
	{/if}

	{#if data.keys.length === 0 && !form?.created_key}
		<div class="rounded-xl border border-zinc-800 bg-zinc-900 p-12 text-center">
			<p class="text-zinc-400">No API keys yet</p>
			<button
				class="mt-3 text-sm text-blue-400 hover:text-blue-300"
				onclick={() => (showCreate = true)}
			>
				Create your first API key
			</button>
		</div>
	{:else if data.keys.length > 0}
		<div class="overflow-x-auto rounded-xl border border-zinc-800">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-zinc-800 bg-zinc-900/50">
					<tr>
						<th class="px-4 py-3 font-medium text-zinc-400">Name</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Prefix</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Identity</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Last Used</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Created</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each data.keys as key}
						<tr class="hover:bg-zinc-900/50">
							<td class="px-4 py-3 text-white">{key.name}</td>
							<td class="px-4 py-3 font-mono text-zinc-400">{key.key_prefix}...</td>
							<td class="px-4 py-3 text-zinc-400">{key.identity_id ?? 'Org-wide'}</td>
							<td class="px-4 py-3 text-zinc-400">{key.last_used_at ? new Date(key.last_used_at).toLocaleDateString() : 'Never'}</td>
							<td class="px-4 py-3 text-zinc-400">{new Date(key.created_at).toLocaleDateString()}</td>
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
				<h2 class="text-lg font-bold text-white">Create API Key</h2>
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
							placeholder="My API Key"
						/>
					</div>
					<div>
						<label for="identity_id" class="block text-sm text-zinc-400">Identity (optional — leave blank for org-wide)</label>
						<input
							id="identity_id"
							name="identity_id"
							type="text"
							class="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-white placeholder-zinc-500 focus:border-blue-500 focus:outline-none"
							placeholder="identity UUID"
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

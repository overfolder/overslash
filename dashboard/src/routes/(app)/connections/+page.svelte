<script lang="ts">
	import { enhance } from '$app/forms';
	import { goto } from '$app/navigation';

	let { data, form } = $props();
	let showConnect = $state(false);

	// If the action returned a redirect URL, navigate to it (OAuth flow)
	$effect(() => {
		if (form?.redirect_url) {
			window.location.href = form.redirect_url;
		}
	});
</script>

<svelte:head>
	<title>Connections — Overslash</title>
</svelte:head>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<h1 class="text-2xl font-bold text-white">Connections</h1>
		<button
			class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-colors"
			onclick={() => (showConnect = true)}
		>
			Connect Service
		</button>
	</div>

	{#if form?.error}
		<div class="rounded-md bg-red-900/50 border border-red-800 p-3 text-sm text-red-300">
			{form.error}
		</div>
	{/if}

	{#if data.connections.length === 0}
		<div class="rounded-xl border border-zinc-800 bg-zinc-900 p-12 text-center">
			<p class="text-zinc-400">No connections yet — connect a service to get started</p>
		</div>
	{:else}
		<div class="overflow-x-auto rounded-xl border border-zinc-800">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-zinc-800 bg-zinc-900/50">
					<tr>
						<th class="px-4 py-3 font-medium text-zinc-400">Provider</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Account</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Default</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Created</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Actions</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each data.connections as conn}
						<tr class="hover:bg-zinc-900/50">
							<td class="px-4 py-3 font-medium text-white">{conn.provider_key}</td>
							<td class="px-4 py-3 text-zinc-400">{conn.account_email ?? '—'}</td>
							<td class="px-4 py-3">
								{#if conn.is_default}
									<span class="inline-flex rounded-full bg-green-500/10 px-2 py-0.5 text-xs font-medium text-green-400">Yes</span>
								{:else}
									<span class="text-zinc-500">No</span>
								{/if}
							</td>
							<td class="px-4 py-3 text-zinc-400">{new Date(conn.created_at).toLocaleDateString()}</td>
							<td class="px-4 py-3">
								<form method="POST" action="?/revoke" use:enhance>
									<input type="hidden" name="id" value={conn.id} />
									<button type="submit" class="rounded bg-red-600/10 px-2.5 py-1 text-xs font-medium text-red-400 hover:bg-red-600/20">
										Revoke
									</button>
								</form>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}

	<!-- Connect Dialog -->
	{#if showConnect}
		<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
			<div class="w-full max-w-md rounded-xl border border-zinc-800 bg-zinc-900 p-6">
				<h2 class="text-lg font-bold text-white">Connect Service</h2>
				<form
					method="POST"
					action="?/connect"
					use:enhance
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
							<option value="">Select a provider...</option>
							<option value="github">GitHub</option>
							<option value="google">Google</option>
							<option value="slack">Slack</option>
							<option value="x">X (Twitter)</option>
						</select>
					</div>
					<div class="flex justify-end gap-3">
						<button
							type="button"
							class="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800"
							onclick={() => (showConnect = false)}
						>
							Cancel
						</button>
						<button
							type="submit"
							class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500"
						>
							Connect
						</button>
					</div>
				</form>
			</div>
		</div>
	{/if}
</div>

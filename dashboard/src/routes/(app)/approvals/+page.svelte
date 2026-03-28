<script lang="ts">
	import { enhance } from '$app/forms';

	let { data, form } = $props();
</script>

<svelte:head>
	<title>Approvals — Overslash</title>
</svelte:head>

<div class="space-y-6">
	<h1 class="text-2xl font-bold text-white">Pending Approvals</h1>

	{#if form?.error}
		<div class="rounded-md bg-red-900/50 border border-red-800 p-3 text-sm text-red-300">
			{form.error}
		</div>
	{/if}

	{#if data.approvals.length === 0}
		<div class="rounded-xl border border-zinc-800 bg-zinc-900 p-12 text-center">
			<p class="text-green-400">No pending approvals</p>
		</div>
	{:else}
		<div class="overflow-x-auto rounded-xl border border-zinc-800">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-zinc-800 bg-zinc-900/50">
					<tr>
						<th class="px-4 py-3 font-medium text-zinc-400">Action Summary</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Permission Keys</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Expires</th>
						<th class="px-4 py-3 font-medium text-zinc-400">Actions</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each data.approvals as approval}
						{@const expired = new Date(approval.expires_at) < new Date()}
						<tr class="hover:bg-zinc-900/50 {expired ? 'opacity-50' : ''}">
							<td class="px-4 py-3 text-white">{approval.action_summary}</td>
							<td class="px-4 py-3">
								<div class="flex flex-wrap gap-1">
									{#each approval.permission_keys as key}
										<span class="rounded bg-zinc-800 px-1.5 py-0.5 text-xs font-mono text-zinc-300">{key}</span>
									{/each}
								</div>
							</td>
							<td class="px-4 py-3 text-zinc-400">
								{#if expired}
									<span class="text-red-400">Expired</span>
								{:else}
									{new Date(approval.expires_at).toLocaleString()}
								{/if}
							</td>
							<td class="px-4 py-3">
								{#if !expired}
									<div class="flex gap-2">
										<form method="POST" action="?/resolve" use:enhance>
											<input type="hidden" name="id" value={approval.id} />
											<input type="hidden" name="decision" value="allow" />
											<button type="submit" class="rounded bg-green-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-green-500">Allow</button>
										</form>
										<form method="POST" action="?/resolve" use:enhance>
											<input type="hidden" name="id" value={approval.id} />
											<input type="hidden" name="decision" value="deny" />
											<button type="submit" class="rounded bg-red-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-red-500">Deny</button>
										</form>
										<form method="POST" action="?/resolve" use:enhance>
											<input type="hidden" name="id" value={approval.id} />
											<input type="hidden" name="decision" value="allow_remember" />
											<button type="submit" class="rounded bg-blue-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-blue-500" title="Allow and create a permanent permission rule">Remember</button>
										</form>
									</div>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>

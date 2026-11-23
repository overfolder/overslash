<script lang="ts">
	import Badge from './Badge.svelte';
	import { getInstanceConfig, type ConfigGroup } from '#lib/api/instance.ts';
	import { apiErrorReason } from '#lib/session.ts';

	let groups = $state<ConfigGroup[] | null>(null);
	let loadError = $state<string | null>(null);

	getInstanceConfig()
		.then((r) => (groups = r.groups))
		.catch((e) => (loadError = apiErrorReason(e) ?? 'Could not load the configuration.'));
</script>

<div class="head">
	<div>
		<div class="group">Deployment</div>
		<h1>Configuration</h1>
		<p class="desc">
			The effective values this deployment runs with. They come from the environment; change them
			in Terraform and redeploy. Secrets show only whether they’re set.
		</p>
	</div>
	<Badge>Read-only</Badge>
</div>

{#if loadError}
	<p class="empty error">{loadError}</p>
{:else if !groups}
	<p class="empty">Loading…</p>
{:else}
	<div class="stack">
		{#each groups as g (g.title)}
			<section class="card padded">
				<h2>{g.title}</h2>
				<dl class="kv">
					{#each g.rows as r (r.key)}
						<dt>{r.key}</dt>
						<dd>
							{#if r.kind === 'text'}
								<code>{r.value}</code>
							{:else if r.kind === 'list'}
								{#each r.values as v (v)}<Badge>{v}</Badge>{/each}
							{:else if r.kind === 'secret'}
								<span class="ro" class:muted={!r.set}>
									<svg
										width="14"
										height="14"
										viewBox="0 0 24 24"
										fill="none"
										stroke="currentColor"
										stroke-width="1.5"
										stroke-linecap="round"
										stroke-linejoin="round"
										aria-hidden="true"
										><rect width="18" height="11" x="3" y="11" rx="2" /><path
											d="M7 11V7a5 5 0 0 1 10 0v4"
										/></svg
									>{r.set ? 'Set' : 'Not set'}
								</span>
							{:else}
								<span class="muted">Not set{#if r.note} · {r.note}{/if}</span>
							{/if}
							{#if r.note && r.kind !== 'unset'}<span class="src">{r.note}</span>{/if}
							{#if r.is_default}<span class="src">default</span>{/if}
						</dd>
					{/each}
				</dl>
			</section>
		{/each}
	</div>
{/if}

<style>
	.stack {
		display: flex;
		flex-direction: column;
		gap: 16px;
	}
	.padded {
		padding: 16px 20px;
	}
	h2 {
		font-size: 13px;
		font-weight: 600;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.05em;
		margin: 0 0 6px;
	}
	.kv {
		display: grid;
		grid-template-columns: minmax(200px, 300px) minmax(0, 1fr);
		margin: 0;
	}
	dt,
	dd {
		padding: 10px 0;
		border-top: 1px solid var(--color-border-subtle);
		min-width: 0;
		margin: 0;
	}
	dt:first-of-type,
	dt:first-of-type + dd {
		border-top: 0;
	}
	dt {
		font-family: var(--font-mono);
		font-size: 12px;
		color: var(--color-text-secondary);
		overflow-wrap: anywhere;
		padding-right: 16px;
	}
	dd {
		font: var(--text-body);
		color: var(--color-text);
		display: flex;
		gap: 8px;
		align-items: baseline;
		flex-wrap: wrap;
	}
	dd code {
		font-size: 12.5px;
		overflow-wrap: anywhere;
	}
	.src {
		font: var(--text-body-sm);
		color: var(--color-text-muted);
	}
	.ro {
		display: inline-flex;
		align-items: center;
		gap: 4px;
	}
	@media (max-width: 900px) {
		.kv {
			grid-template-columns: minmax(0, 1fr);
		}
		dt {
			padding-bottom: 0;
		}
		dd {
			border-top: 0;
			padding-top: 4px;
		}
	}
</style>

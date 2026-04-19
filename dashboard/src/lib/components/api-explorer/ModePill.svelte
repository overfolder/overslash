<script lang="ts">
	export type ExplorerMode = 'service_action' | 'raw_http';

	let { mode, onchange }: { mode: ExplorerMode; onchange: (m: ExplorerMode) => void } = $props();
</script>

<div class="pill" role="tablist">
	<button
		type="button"
		role="tab"
		class="seg"
		aria-selected={mode === 'service_action'}
		onclick={() => onchange('service_action')}
	>
		Service + Action
	</button>
	<button
		type="button"
		role="tab"
		class="seg"
		aria-selected={mode === 'raw_http'}
		onclick={() => onchange('raw_http')}
	>
		Raw HTTP
	</button>
</div>

<style>
	.pill {
		display: inline-flex;
		gap: 0.25rem;
		padding: 0.15rem;
		background: var(--color-bg);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
	}
	.seg {
		padding: 0.35rem 0.9rem;
		font: inherit;
		font-size: 0.82rem;
		font-weight: 500;
		color: var(--color-text-muted);
		background: transparent;
		border: none;
		border-radius: 6px;
		cursor: pointer;
		transition: background 0.1s ease, color 0.1s ease;
	}
	.seg:hover {
		color: var(--color-text);
	}
	.seg[aria-selected='true'] {
		background: var(--color-primary);
		color: #fff;
	}
</style>

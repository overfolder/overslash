<script lang="ts">
	type Variant =
		| 'draft'
		| 'active'
		| 'archived'
		| 'connected'
		| 'needs-setup'
		| 'built-in'
		| 'needs-reconnect'
		| 'partially-degraded'
		| 'global'
		| 'org'
		| 'user';
	let { variant, label }: { variant: Variant; label?: string } = $props();
	const text = $derived(label ?? variant.replace('-', ' '));
</script>

<span class="badge {variant}">{text}</span>

<style>
	.badge {
		display: inline-block;
		padding: 0.15rem 0.55rem;
		border-radius: 999px;
		font-size: 0.75rem;
		font-weight: 600;
		text-transform: capitalize;
		letter-spacing: 0.02em;
		border: 1px solid transparent;
		line-height: 1.4;
	}
	.active,
	.connected {
		background: rgba(34, 197, 94, 0.12);
		color: #15803d;
		border-color: rgba(34, 197, 94, 0.3);
	}
	.draft,
	.needs-setup,
	.partially-degraded {
		background: rgba(234, 179, 8, 0.14);
		color: #a16207;
		border-color: rgba(234, 179, 8, 0.35);
	}
	.needs-reconnect {
		background: rgba(220, 38, 38, 0.1);
		color: #b91c1c;
		border-color: rgba(220, 38, 38, 0.35);
	}
	.archived,
	.built-in {
		background: var(--color-bg, #f4f4f5);
		color: var(--color-text-muted, #6b7280);
		border-color: var(--color-border, #e5e7eb);
	}
	.global {
		background: rgba(59, 130, 246, 0.12);
		color: #1d4ed8;
		border-color: rgba(59, 130, 246, 0.3);
	}
	.org {
		background: rgba(168, 85, 247, 0.12);
		color: #7e22ce;
		border-color: rgba(168, 85, 247, 0.3);
	}
	.user {
		background: rgba(20, 184, 166, 0.12);
		color: #0f766e;
		border-color: rgba(20, 184, 166, 0.3);
	}
</style>

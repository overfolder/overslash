<script lang="ts">
	let { status = '' }: { status: string } = $props();

	const colorMap: Record<string, string> = {
		active: 'var(--color-success)',
		success: 'var(--color-success)',
		global: '#6b7280',
		org: 'var(--color-primary)',
		user: '#a78bfa',
		draft: '#6b7280',
		archived: '#4b5563',
		read: '#60a5fa',
		write: '#f59e0b',
		admin: '#ef4444',
		env: '#eab308',
		db: 'var(--color-primary)',
		enabled: 'var(--color-success)',
		disabled: '#6b7280'
	};

	let color = $derived(colorMap[status.toLowerCase()] ?? 'var(--color-text-muted)');
</script>

<span class="badge" style="background: {color}">{status}</span>

<style>
	.badge {
		display: inline-block;
		padding: 0.1rem 0.5rem;
		border-radius: 4px;
		font-size: 0.75rem;
		font-weight: 500;
		color: white;
		white-space: nowrap;
	}
</style>

<script lang="ts">
	let {
		name = '',
		email = '',
		showName = false
	}: { name?: string; email?: string; showName?: boolean } = $props();

	function initials(n: string, e: string): string {
		const src = (n || e || '?').trim();
		const parts = src.split(/\s+/).filter(Boolean);
		if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
		return src.slice(0, 2).toUpperCase();
	}

	const ini = $derived(initials(name, email));
</script>

<a class="avatar-link" class:with-name={showName} href="/profile" title={name || email}>
	<span class="avatar">{ini}</span>
	{#if showName}
		<span class="name-block">
			<span class="name">{name || email}</span>
			{#if name && email}<span class="email">{email}</span>{/if}
		</span>
	{/if}
</a>

<style>
	.avatar-link {
		display: flex;
		align-items: center;
		gap: 0.6rem;
		padding: 0.5rem;
		border-radius: 6px;
		text-decoration: none;
		color: var(--color-text);
	}
	.avatar-link:hover {
		background: var(--color-neutral-100, var(--color-border));
	}
	.avatar {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 32px;
		height: 32px;
		border-radius: 50%;
		background: var(--color-primary);
		color: #fff;
		font-size: 0.75rem;
		font-weight: 600;
		flex-shrink: 0;
	}
	.name-block {
		display: flex;
		flex-direction: column;
		min-width: 0;
	}
	.name {
		font-size: 0.85rem;
		font-weight: 600;
		color: var(--color-text);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.email {
		font-size: 0.7rem;
		color: var(--color-text-muted);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
</style>

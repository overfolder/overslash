<script lang="ts">
	import Avatar from '$lib/components/Avatar.svelte';

	let {
		name = '',
		email = '',
		picture = null,
		showName = false
	}: { name?: string; email?: string; picture?: string | null; showName?: boolean } = $props();
</script>

<a class="avatar-link" class:with-name={showName} href="/profile" title={name || email}>
	<Avatar {name} {email} {picture} size={32} />
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

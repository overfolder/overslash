<script lang="ts">
	import type { Snippet } from 'svelte';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { session, ApiError } from '$lib/session';
	import type { MeIdentity } from '$lib/session';

	let { children }: { children: Snippet } = $props();

	let authorized = $state(false);
	let checking = $state(true);

	onMount(async () => {
		try {
			const me = await session.get<MeIdentity>('/auth/me/identity');
			if (me.kind !== 'user') {
				goto('/profile');
				return;
			}
			authorized = true;
		} catch (e) {
			if (e instanceof ApiError && e.status === 401) {
				goto('/profile');
			} else {
				goto('/profile');
			}
		} finally {
			checking = false;
		}
	});
</script>

{#if checking}
	<div class="guard-loading">
		<div class="spinner"></div>
		<span>Checking access...</span>
	</div>
{:else if authorized}
	{@render children()}
{/if}

<style>
	.guard-loading {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 2rem;
		color: var(--color-text-muted);
	}

	.spinner {
		width: 18px;
		height: 18px;
		border: 2px solid var(--color-border);
		border-top-color: var(--color-primary);
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}
</style>

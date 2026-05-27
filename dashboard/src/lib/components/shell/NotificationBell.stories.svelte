<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import { notificationsStore } from '$lib/stores/shell';
	import NotificationBell from './NotificationBell.svelte';

	// The bell reads the global `notificationsStore` singleton. `beforeEach` sets
	// the count before each story renders (and resets it on cleanup) so the
	// stories are deterministic regardless of order.
	function setCount(count: number) {
		return () => {
			notificationsStore.set({ count });
			return () => notificationsStore.set({ count: 0 });
		};
	}

	const { Story } = defineMeta({
		title: 'Shell/NotificationBell',
		component: NotificationBell,
		tags: ['autodocs']
	});
</script>

<Story name="No notifications" beforeEach={setCount(0)} />
<Story name="With badge" beforeEach={setCount(5)} />
<Story name="Overflow (99+)" beforeEach={setCount(128)} />

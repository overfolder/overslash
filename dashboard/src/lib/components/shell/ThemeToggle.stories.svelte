<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import ThemeToggle from './ThemeToggle.svelte';

	// ThemeToggle flips the app's own `theme` store (persisted to localStorage).
	// Note: the Storybook canvas theme is driven by the toolbar "Theme" control
	// (see .storybook/preview.ts), so clicking this button changes the app store
	// but not the preview background — it's shown here for its visual states.
	const { Story } = defineMeta({
		title: 'Shell/ThemeToggle',
		component: ThemeToggle,
		tags: ['autodocs']
	});
</script>

<Story name="Default" />

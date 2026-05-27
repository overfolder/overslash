import type { StorybookConfig } from '@storybook/sveltekit';

// Storybook reuses the dashboard's own Vite + Svelte config via the sveltekit
// framework, so design tokens, Tailwind, and the `$lib` alias all resolve the
// same way they do in `vite dev`.
//
// NOTE: we intentionally do NOT install `@storybook/addon-vitest`. On Vite 8
// (Rolldown) + Svelte 5 its dep scanner can't resolve `.svelte` imports
// (storybookjs/storybook#34304). The Storybook UI and `storybook build` work
// fine without it.
const config: StorybookConfig = {
	stories: ['../src/**/*.stories.@(svelte|ts)'],
	addons: ['@storybook/addon-svelte-csf', '@storybook/addon-docs'],
	framework: {
		name: '@storybook/sveltekit',
		options: {}
	},
	core: {
		// No anonymous usage telemetry — keeps CI builds hermetic and offline.
		disableTelemetry: true
	}
};

export default config;

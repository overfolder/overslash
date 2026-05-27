import type { Preview } from '@storybook/sveltekit';

// Pull in the same global stylesheet the app boots with: Inter + Roboto Mono
// variable fonts and the design-token CSS variables. Without this, components
// render with no tokens (transparent badges, fallback fonts).
import '../src/app.css';

// Dark mode keys off `[data-theme='dark']` on the document root (see
// design-tokens.css). We set the attribute explicitly per the toolbar choice so
// the canvas ignores the OS preference and matches what the user picked.
const preview: Preview = {
	globalTypes: {
		theme: {
			description: 'Light / dark design tokens',
			toolbar: {
				title: 'Theme',
				icon: 'paintbrush',
				items: [
					{ value: 'light', title: 'Light', icon: 'sun' },
					{ value: 'dark', title: 'Dark', icon: 'moon' }
				],
				dynamicTitle: true
			}
		}
	},
	initialGlobals: {
		theme: 'light'
	},
	decorators: [
		(story, context) => {
			const theme = context.globals.theme ?? 'light';
			if (typeof document !== 'undefined') {
				document.documentElement.dataset.theme = theme;
				// The story canvas paints on the themed page background.
				document.body.style.background = 'var(--color-bg)';
				document.body.style.color = 'var(--color-text)';
			}
			return story();
		}
	],
	parameters: {
		layout: 'centered',
		controls: {
			matchers: {
				color: /(background|color)$/i,
				date: /Date$/i
			}
		}
	}
};

export default preview;

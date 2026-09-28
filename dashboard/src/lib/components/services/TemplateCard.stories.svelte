<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import { fn } from 'storybook/test';
	import type { TemplateSummary } from '$lib/types';
	import TemplateCard from './TemplateCard.svelte';

	const github: TemplateSummary = {
		key: 'github',
		display_name: 'GitHub',
		description: 'Issues, pull requests, repository contents, and more.',
		category: 'Developer tools',
		hosts: ['api.github.com'],
		action_count: 42,
		tier: 'global'
	};

	const { Story } = defineMeta({
		title: 'Services/TemplateCard',
		component: TemplateCard,
		tags: ['autodocs'],
		parameters: { layout: 'padded' },
		args: { template: github, selected: false, onselect: fn() }
	});
</script>

<Story name="Default" />
<Story name="Selected" args={{ selected: true }} />
<Story
	name="Hidden"
	args={{
		template: {
			key: 'test_email',
			display_name: 'Test Mail',
			description: 'Test email service for end-to-end evals. Hidden from agent-facing catalogs.',
			category: 'Communication',
			hosts: ['httpbun.com'],
			action_count: 2,
			tier: 'global',
			hidden: true
		}
	}}
/>

<Story name="Catalog row" asChild>
	<div style="display:flex; gap:16px; flex-wrap:wrap;">
		<TemplateCard template={github} onselect={fn()} />
		<TemplateCard
			template={{
				key: 'stripe',
				display_name: 'Stripe',
				description: 'Payments, customers, subscriptions.',
				category: 'Finance',
				hosts: ['api.stripe.com'],
				action_count: 30,
				tier: 'org'
			}}
			selected
			onselect={fn()}
		/>
	</div>
</Story>

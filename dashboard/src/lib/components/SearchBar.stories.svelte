<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import { fn } from 'storybook/test';
	import SearchBar, { emptySearch, type SearchKey, type SearchValue } from './SearchBar.svelte';

	// Mirrors the Audit Log key set from UI_SPEC § Search Bar.
	const auditKeys: SearchKey[] = [
		{ name: 'identity', operators: ['=', '~'], hint: 'agent or user', values: ['alice', 'agent:henry', 'sub:researcher'] },
		{ name: 'event', operators: ['='], values: ['action.executed', 'approval.created', 'approval.resolved', 'secret.revealed'] },
		{ name: 'service', operators: ['=', '~'], values: ['github', 'slack', 'stripe', 'google-calendar'] },
		{ name: 'result', operators: ['='], values: ['success', 'error'] },
		{ name: 'time', operators: ['=', '~'], hint: 'e.g. 24h' }
	];

	const empty: SearchValue = emptySearch();
	// Every term is a bubble: two column filters plus a free-text phrase, which
	// AND together in the order they were typed.
	const withChips: SearchValue = {
		terms: [
			{ kind: 'filter', key: 'service', op: '=', value: 'github' },
			{ kind: 'filter', key: 'result', op: '=', value: 'error' },
			{ kind: 'text', value: 'pull request' }
		]
	};
	// Two text bubbles AND with each other and with a filter, whatever the order.
	const textBubbles: SearchValue = {
		terms: [
			{ kind: 'text', value: 'timeout' },
			{ kind: 'filter', key: 'result', op: '=', value: 'error' },
			{ kind: 'text', value: 'rate limit' }
		]
	};

	const { Story } = defineMeta({
		title: 'Controls/SearchBar',
		component: SearchBar,
		tags: ['autodocs'],
		parameters: { layout: 'padded' },
		args: { keys: auditKeys, value: empty, placeholder: 'Search audit log…', onchange: fn() }
	});
</script>

<script lang="ts">
	let value = $state<SearchValue>(emptySearch());
</script>

<Story name="Empty" args={{ value: empty }} />
<Story name="With filter chips" args={{ value: withChips }} />
<Story name="Text bubbles" args={{ value: textBubbles }} />

<Story name="Interactive" asChild>
	<div style="width:560px; max-width:100%;">
		<SearchBar keys={auditKeys} bind:value onchange={(v) => (value = v)} placeholder="Search audit log…" />
		<pre style="margin-top:12px; font-size:12px; color:var(--color-text-muted);">{JSON.stringify(value, null, 2)}</pre>
	</div>
</Story>

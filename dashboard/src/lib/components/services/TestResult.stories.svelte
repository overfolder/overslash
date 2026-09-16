<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import TestResult from './TestResult.svelte';
	import type { ServiceTestResponse } from '$lib/types';

	// Every verdict the endpoint can return, side by side. The five-way
	// status→copy mapping is the whole component, and "does a red box say
	// something a human can act on" is a question only a rendering answers —
	// the three pages that mount this all pass the response straight through.
	const verdicts: ServiceTestResponse[] = [
		{
			status: 'ok',
			action: 'list_domains',
			http_status: 200,
			latency_ms: 214,
			summary: 'List verified sending domains'
		},
		{
			status: 'failed',
			action: 'list_domains',
			http_status: 401,
			latency_ms: 88,
			error: '{"message":"API key is invalid","name":"validation_error","statusCode":401}'
		},
		{
			status: 'failed',
			action: 'list_domains',
			latency_ms: 30_142,
			error: 'the service did not respond within 30000 ms'
		},
		{ status: 'needs_authentication', action: 'list_domains', latency_ms: 4 },
		{
			status: 'pending_approval',
			action: 'list_domains',
			latency_ms: 12,
			approval_url: 'https://app.overslash.com/approvals/apr_123'
		},
		{
			status: 'denied',
			action: 'list_domains',
			latency_ms: 6,
			error: 'a deny rule on resend:*:* refuses this call'
		},
		{ status: 'not_supported' }
	];

	const { Story } = defineMeta({
		title: 'Services/TestResult',
		component: TestResult,
		tags: ['autodocs'],
		args: { result: verdicts[0], running: false }
	});
</script>

<Story name="Works" args={{ result: verdicts[0] }} />
<Story name="Upstream rejected the credential" args={{ result: verdicts[1] }} />
<Story name="Running" args={{ result: null, running: true }} />

<Story name="Every verdict" asChild>
	<!-- With `onRetry` bound so the suppression rules are visible: no Retry on
	     `not_supported` or `denied`, which answer the same way every time. -->
	<div style="display:flex; flex-direction:column; gap:12px; max-width:560px;">
		{#each verdicts as v}
			<TestResult result={v} onRetry={() => {}} />
		{/each}
	</div>
</Story>

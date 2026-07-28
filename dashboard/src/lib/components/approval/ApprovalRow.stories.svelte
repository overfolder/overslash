<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import ApprovalRow from './ApprovalRow.svelte';
	import type { ApprovalResponse } from '$lib/session';

	// A realistic pending row: what the gateway returns for an agent that hit a
	// write action it has no rule for.
	const base: ApprovalResponse = {
		id: 'apr_01HZ',
		identity_id: 'idn_agent',
		requesting_identity_id: 'idn_agent',
		current_resolver_identity_id: 'idn_agent',
		identity_path: 'spiffe://acme/user/alice/agent/deploy-bot',
		identity_path_ids: ['idn_user', 'idn_agent'],
		tags: ['service:github', 'action:create_issue', 'risk:write', 'mode:c'],
		action_summary: 'Send an email to jane@example.com',
		permission_keys: ['gmail:send:recipient=jane@example.com'],
		derived_keys: [
			{
				service: 'gmail',
				action: 'send',
				arg: 'recipient=jane@example.com',
				label: 'recipient',
				value: 'jane@example.com'
			}
		],
		suggested_tiers: [
			{
				keys: ['gmail:send:recipient=jane@example.com'],
				description: 'Just this recipient'
			},
			{ keys: ['gmail:send:*'], description: 'Any recipient' },
			{ keys: ['gmail:*:*'], description: 'All Gmail actions' }
		],
		action_detail: null,
		action_detail_truncated: false,
		action_detail_size_bytes: 0,
		disclosed_fields: null,
		status: 'pending',
		token: 'tok',
		expires_at: new Date(Date.now() + 30 * 60_000).toISOString(),
		created_at: new Date(Date.now() - 2 * 60_000).toISOString(),
		risk: 'med'
	};

	const { Story } = defineMeta({
		title: 'Approval/ApprovalRow',
		component: ApprovalRow,
		tags: ['autodocs'],
		parameters: { layout: 'padded' },
		args: { approval: base }
	});
</script>

<!-- The three resolutions live on every row: ✓ approve once, ✕ deny,
     ✓✓ allow & remember at the narrowest suggested scope. -->
<Story name="Pending" args={{ approval: base }} />

<Story name="HighRisk" args={{ approval: { ...base, risk: 'high' } }} />

<Story name="LowRisk" args={{ approval: { ...base, risk: 'low' } }} />

<!-- Nothing to remember: the blue ✓✓ is disabled, approve/deny still work. -->
<Story name="NoSuggestedScope" args={{ approval: { ...base, suggested_tiers: [] } }} />

<!-- Bubbled to an ancestor — line 2 flags it. -->
<Story
	name="Bubbled"
	args={{ approval: { ...base, current_resolver_identity_id: 'idn_user' } }}
/>

<!-- Allowed but deferred: the row shows the execution state instead of the
     three buttons, with Call now / Cancel. -->
<Story
	name="AwaitingCall"
	args={{
		approval: {
			...base,
			status: 'allowed',
			execution: {
				id: 'exe_1',
				status: 'pending',
				created_at: new Date().toISOString(),
				expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
				output_read: false
			}
		},
		clickable: false
	}}
/>

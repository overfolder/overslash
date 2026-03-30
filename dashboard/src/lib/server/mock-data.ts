import type { AuditEntry, Identity, ServiceSummary } from '$lib/types';

const now = Date.now();
const h = (hours: number) => new Date(now - hours * 3600_000).toISOString();
const m = (minutes: number) => new Date(now - minutes * 60_000).toISOString();

export const MOCK_IDENTITIES: Identity[] = [
	{ id: '11111111-1111-1111-1111-111111111111', org_id: 'org-1', name: 'alice', kind: 'user', external_id: null },
	{ id: '22222222-2222-2222-2222-222222222222', org_id: 'org-1', name: 'henry', kind: 'agent', external_id: 'agent-henry' },
	{ id: '33333333-3333-3333-3333-333333333333', org_id: 'org-1', name: 'researcher', kind: 'agent', external_id: 'sub-researcher' },
	{ id: '44444444-4444-4444-4444-444444444444', org_id: 'org-1', name: 'bob', kind: 'user', external_id: null },
	{ id: '55555555-5555-5555-5555-555555555555', org_id: 'org-1', name: 'deploy-bot', kind: 'agent', external_id: 'deploy-bot-v2' }
];

export const MOCK_SERVICES: ServiceSummary[] = [
	{ key: 'github', display_name: 'GitHub', hosts: ['api.github.com'], action_count: 12 },
	{ key: 'slack', display_name: 'Slack', hosts: ['slack.com'], action_count: 8 },
	{ key: 'google_calendar', display_name: 'Google Calendar', hosts: ['www.googleapis.com'], action_count: 6 },
	{ key: 'stripe', display_name: 'Stripe', hosts: ['api.stripe.com'], action_count: 10 }
];

export const MOCK_AUDIT_ENTRIES: AuditEntry[] = [
	{
		id: 'a0000001-0000-0000-0000-000000000001',
		identity_id: '22222222-2222-2222-2222-222222222222',
		action: 'action.executed',
		resource_type: 'github',
		resource_id: null,
		detail: {
			method: 'GET',
			url: 'https://api.github.com/repos/acme/overslash/pulls',
			status_code: 200,
			duration_ms: 342,
			description: 'List pull requests',
			service: 'github',
			action: 'list_pull_requests'
		},
		ip_address: '10.0.1.42',
		created_at: m(3)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000002',
		identity_id: '11111111-1111-1111-1111-111111111111',
		action: 'approval.resolved',
		resource_type: 'approval',
		resource_id: 'b0000001-0000-0000-0000-000000000001',
		detail: {
			decision: 'allow_remember',
			status: 'allowed',
			action_summary: 'Allow henry to create GitHub issues'
		},
		ip_address: '192.168.1.10',
		created_at: m(12)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000003',
		identity_id: '22222222-2222-2222-2222-222222222222',
		action: 'action.executed',
		resource_type: 'slack',
		resource_id: null,
		detail: {
			method: 'POST',
			url: 'https://slack.com/api/chat.postMessage',
			status_code: 200,
			duration_ms: 187,
			description: 'Post message to #deployments',
			service: 'slack',
			action: 'post_message'
		},
		ip_address: '10.0.1.42',
		created_at: m(25)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000004',
		identity_id: '33333333-3333-3333-3333-333333333333',
		action: 'secret.put',
		resource_type: 'secret',
		resource_id: null,
		detail: { name: 'OPENAI_API_KEY', version: 3 },
		ip_address: '10.0.1.55',
		created_at: m(40)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000005',
		identity_id: '55555555-5555-5555-5555-555555555555',
		action: 'connection.created',
		resource_type: 'connection',
		resource_id: 'c0000001-0000-0000-0000-000000000001',
		detail: { provider: 'github' },
		ip_address: '10.0.2.10',
		created_at: h(1)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000006',
		identity_id: '22222222-2222-2222-2222-222222222222',
		action: 'action.executed',
		resource_type: 'google_calendar',
		resource_id: null,
		detail: {
			method: 'POST',
			url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
			status_code: 201,
			duration_ms: 521,
			description: 'Create calendar event: Team Standup',
			service: 'google_calendar',
			action: 'create_event'
		},
		ip_address: '10.0.1.42',
		created_at: h(1.5)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000007',
		identity_id: '11111111-1111-1111-1111-111111111111',
		action: 'permission_rule.created',
		resource_type: 'permission_rule',
		resource_id: 'd0000001-0000-0000-0000-000000000001',
		detail: {
			identity_id: '22222222-2222-2222-2222-222222222222',
			action_pattern: 'github.*',
			effect: 'allow'
		},
		ip_address: '192.168.1.10',
		created_at: h(2)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000008',
		identity_id: '44444444-4444-4444-4444-444444444444',
		action: 'identity.created',
		resource_type: 'identity',
		resource_id: '55555555-5555-5555-5555-555555555555',
		detail: { name: 'deploy-bot', kind: 'agent' },
		ip_address: '192.168.1.20',
		created_at: h(3)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000009',
		identity_id: '22222222-2222-2222-2222-222222222222',
		action: 'approval.created',
		resource_type: 'approval',
		resource_id: 'b0000001-0000-0000-0000-000000000002',
		detail: {},
		ip_address: '10.0.1.42',
		created_at: h(3.5)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000010',
		identity_id: '33333333-3333-3333-3333-333333333333',
		action: 'action.executed',
		resource_type: 'github',
		resource_id: null,
		detail: {
			method: 'POST',
			url: 'https://api.github.com/repos/acme/overslash/issues',
			status_code: 201,
			duration_ms: 445,
			description: 'Create issue: Fix login redirect',
			service: 'github',
			action: 'create_issue'
		},
		ip_address: '10.0.1.55',
		created_at: h(4)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000011',
		identity_id: '55555555-5555-5555-5555-555555555555',
		action: 'action.executed',
		resource_type: 'stripe',
		resource_id: null,
		detail: {
			method: 'GET',
			url: 'https://api.stripe.com/v1/charges?limit=10',
			status_code: 200,
			duration_ms: 290,
			description: 'List recent charges',
			service: 'stripe',
			action: 'list_charges'
		},
		ip_address: '10.0.2.10',
		created_at: h(5)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000012',
		identity_id: '11111111-1111-1111-1111-111111111111',
		action: 'secret.put',
		resource_type: 'secret',
		resource_id: null,
		detail: { name: 'STRIPE_SECRET_KEY', version: 1 },
		ip_address: '192.168.1.10',
		created_at: h(6)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000013',
		identity_id: '22222222-2222-2222-2222-222222222222',
		action: 'connection.deleted',
		resource_type: 'connection',
		resource_id: 'c0000001-0000-0000-0000-000000000002',
		detail: {},
		ip_address: '10.0.1.42',
		created_at: h(7)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000014',
		identity_id: '44444444-4444-4444-4444-444444444444',
		action: 'approval.resolved',
		resource_type: 'approval',
		resource_id: 'b0000001-0000-0000-0000-000000000003',
		detail: {
			decision: 'deny',
			status: 'denied',
			action_summary: 'Deny researcher access to Stripe'
		},
		ip_address: '192.168.1.20',
		created_at: h(8)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000015',
		identity_id: null,
		action: 'org.created',
		resource_type: 'org',
		resource_id: 'e0000001-0000-0000-0000-000000000001',
		detail: { name: 'Acme Corp', slug: 'acme' },
		ip_address: '203.0.113.1',
		created_at: h(24)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000016',
		identity_id: null,
		action: 'api_key.created',
		resource_type: 'api_key',
		resource_id: 'f0000001-0000-0000-0000-000000000001',
		detail: { name: 'Production Key', key_prefix: 'osk_a1b2' },
		ip_address: '203.0.113.1',
		created_at: h(24)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000017',
		identity_id: '11111111-1111-1111-1111-111111111111',
		action: 'webhook.created',
		resource_type: 'webhook',
		resource_id: 'g0000001-0000-0000-0000-000000000001',
		detail: { url: 'https://acme.com/webhooks/overslash', events: ['action.executed', 'approval.resolved'] },
		ip_address: '192.168.1.10',
		created_at: h(20)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000018',
		identity_id: '33333333-3333-3333-3333-333333333333',
		action: 'secret.deleted',
		resource_type: 'secret',
		resource_id: null,
		detail: { name: 'OLD_TOKEN' },
		ip_address: '10.0.1.55',
		created_at: h(10)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000019',
		identity_id: '55555555-5555-5555-5555-555555555555',
		action: 'action.streamed',
		resource_type: null,
		resource_id: null,
		detail: {
			method: 'GET',
			url: 'https://api.github.com/repos/acme/overslash/releases/latest',
			status_code: 200,
			content_length: 48200
		},
		ip_address: '10.0.2.10',
		created_at: h(12)
	},
	{
		id: 'a0000001-0000-0000-0000-000000000020',
		identity_id: '22222222-2222-2222-2222-222222222222',
		action: 'connection.created',
		resource_type: 'connection',
		resource_id: 'c0000001-0000-0000-0000-000000000003',
		detail: { provider: 'google_calendar' },
		ip_address: '10.0.1.42',
		created_at: h(15)
	}
];

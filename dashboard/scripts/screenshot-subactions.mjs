// Real-stack screenshots for `x-overslash-subactions`.
//
// Two surfaces: the service's Actions tab, where variants nest under the
// overloaded tool they classify (callable ones marked), and the approval a
// mixed batch raises — titled with what it writes, and listing one operation
// per matched variant instead of the bare tool name.
//
// The template is a small CRM stand-in with the shipped HubSpot block's shape,
// so the screenshot needs no OAuth. The gate fires before any upstream call,
// so the MCP URL is never dialled.
//
// Runs in a fresh org and deletes it on the way out.
//
// Prereq: `make e2e-up`. Run from `dashboard/`.
// Output: dashboard/screenshots/subactions-*.png.

import {
	api,
	deleteOrg,
	freshOrgSlug,
	login,
	makeSnapper,
	promoteToOrgAdmin,
	resolveEnv,
	seedApproval,
	seedService
} from '../tests/scenarios/index.mjs';

const env = resolveEnv();

const variant = (op, type, noun, label) => `
          - name: ${op}_${noun}
            match: '.op == "${op}" and .objectType == "${type}"'
            description: "${op === 'create' ? 'Create' : 'Update'} a ${noun}."
            verb: ${op}
            phrase: "${noun}[ {item.label}]"
            vars:
              label: '${label}'
            disclose:
              - label: ${noun[0].toUpperCase()}${noun.slice(1)}s to ${op}
                filter: '[.items[] | .label // "(unnamed)"] | join(", ")'
                primary: true`;

const TEMPLATE_YAML = `openapi: "3.1.0"
info:
  title: "Acme CRM"
  key: "subactdemo"
x-overslash-runtime: mcp
servers: []
paths: {}
x-overslash-mcp:
  url: "${env.mcpUrl ?? 'https://mcp.acme-crm.test'}"
  auth: {kind: none}
  autodiscover: false
  tools:
    - name: manage_crm_objects
      risk: write
      description: "Create or update CRM records"
      input_schema:
        type: object
        properties:
          createRequest: {type: object, properties: {objects: {type: array, items: {type: object}}}}
          updateRequest: {type: object, properties: {objects: {type: array, items: {type: object}}}}
      disclose:
        - label: Payload
          filter: '(.arguments.createRequest // .arguments.updateRequest) | tojson'
          max_chars: 400
      subactions:
        each: >-
          (.createRequest.objects[]? | . + {op: "create"}),
          (.updateRequest.objects[]? | . + {op: "update"})
        variants:${variant('create', 'contacts', 'contact', '.properties.email')}
            input_schema:
              type: object
              properties:
                properties: {type: object, properties: {email: {type: string}}, additionalProperties: {type: string}}
              required: [properties]
            transform: '{createRequest: {objects: [{objectType: "contacts", properties: .properties}]}}'${variant('create', 'deals', 'deal', '.properties.dealname')}${variant('update', 'deals', 'deal', '.properties.dealname // "#\\(.objectId)"')}
`;

const org = freshOrgSlug('subact');
const session = await login('admin', { org });

try {
	const identities = await api(session, '/v1/identities');
	const me = identities.find((i) => i.kind === 'user');
	if (me) await promoteToOrgAdmin(session, me.id);

	await api(session, '/v1/templates', {
		method: 'POST',
		body: { openapi: TEMPLATE_YAML, user_level: false },
		expect: [200, 201]
	});
	const svc = await seedService(session, { templateKey: 'subactdemo', name: 'acme-crm' });

	const approval = await seedApproval(session, {
		templateKey: 'acme-crm',
		action: 'manage_crm_objects',
		params: {
			createRequest: {
				objects: [
					{ objectType: 'contacts', properties: { email: 'jane@acme.com' } },
					{ objectType: 'deals', properties: { dealname: 'Acme renewal' } }
				]
			},
			updateRequest: {
				objects: [{ objectType: 'deals', objectId: 42, properties: { dealname: 'Big Co' } }]
			}
		}
	});
	console.log(`[subactions] approval: ${approval.action_summary}`);

	const snap = await makeSnapper(session);
	try {
		await snap.navigateAndSnap('subactions-service-actions', `/services/${svc.id}?tab=actions`, {
			viewport: { width: 1280, height: 720 },
			waitFor: (page) => page.waitForSelector('tr.subaction')
		});
		await snap.navigateAndSnap('subactions-approval', `/approvals/${approval.id}`, {
			viewport: { width: 1280, height: 1000 },
			waitFor: (page) => page.waitForSelector('code.op')
		});
	} finally {
		await snap.close();
	}
} finally {
	await deleteOrg(org);
}

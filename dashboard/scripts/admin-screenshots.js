// Screenshot script for org admin dashboard — PR proof-of-work
// Starts the dev server, mocks API responses, and captures admin page screenshots.

import { chromium } from 'playwright';
import { spawn } from 'child_process';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { mkdirSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const screenshotDir = resolve(__dirname, '../../docs/screenshots');
mkdirSync(screenshotDir, { recursive: true });

// ── Mock data ────────────────────────────────────────────────────────

const MOCK_IDENTITY = {
  identity_id: 'a1b2c3d4-0001-0001-0001-000000000001',
  org_id: 'a1b2c3d4-0002-0002-0002-000000000002',
  email: 'admin@acme.corp',
  name: 'Alice Admin',
  kind: 'user',
  external_id: null
};

const MOCK_TEMPLATES = [
  { key: 'github', display_name: 'GitHub', description: 'GitHub API', category: 'Dev Tools', hosts: ['api.github.com'], action_count: 12, tier: 'global', id: null },
  { key: 'slack', display_name: 'Slack', description: 'Slack API', category: 'Messaging', hosts: ['api.slack.com'], action_count: 8, tier: 'global', id: null },
  { key: 'stripe', display_name: 'Stripe', description: 'Payment processing', category: 'Finance', hosts: ['api.stripe.com'], action_count: 15, tier: 'global', id: null },
  { key: 'internal-crm', display_name: 'Internal CRM', description: 'Company CRM API', category: 'Internal', hosts: ['crm.acme.corp'], action_count: 6, tier: 'org', id: 'tpl-org-001' },
  { key: 'analytics-v2', display_name: 'Analytics v2', description: 'Internal analytics service', category: 'Internal', hosts: ['analytics.acme.corp'], action_count: 4, tier: 'org', id: 'tpl-org-002' }
];

const MOCK_SERVICES = [
  { id: 'svc-001', name: 'github', template_source: 'global', template_key: 'github', status: 'active', owner_identity_id: null, connection_id: 'conn-001', secret_name: null, created_at: '2026-03-20T10:00:00Z', updated_at: '2026-04-01T08:00:00Z' },
  { id: 'svc-002', name: 'slack-prod', template_source: 'global', template_key: 'slack', status: 'active', owner_identity_id: null, connection_id: null, secret_name: 'slack_bot_token', created_at: '2026-03-22T14:00:00Z', updated_at: '2026-03-30T09:00:00Z' },
  { id: 'svc-003', name: 'stripe-test', template_source: 'global', template_key: 'stripe', status: 'draft', owner_identity_id: null, connection_id: null, secret_name: 'stripe_sk_test', created_at: '2026-04-01T16:00:00Z', updated_at: '2026-04-02T11:00:00Z' },
  { id: 'svc-004', name: 'internal-crm', template_source: 'org', template_key: 'internal-crm', status: 'active', owner_identity_id: null, connection_id: null, secret_name: 'crm_api_key', created_at: '2026-04-02T09:00:00Z', updated_at: '2026-04-03T10:00:00Z' },
  { id: 'svc-005', name: 'old-analytics', template_source: 'org', template_key: 'analytics-v2', status: 'archived', owner_identity_id: null, connection_id: null, secret_name: null, created_at: '2026-02-15T12:00:00Z', updated_at: '2026-03-01T08:00:00Z' }
];

const MOCK_GROUPS = [
  { id: 'grp-001', org_id: MOCK_IDENTITY.org_id, name: 'Engineering', description: 'Full-stack engineering team', allow_raw_http: true, created_at: '2026-03-15T10:00:00Z', updated_at: '2026-04-01T08:00:00Z' },
  { id: 'grp-002', org_id: MOCK_IDENTITY.org_id, name: 'Data Science', description: 'ML and analytics', allow_raw_http: false, created_at: '2026-03-20T14:00:00Z', updated_at: '2026-03-25T09:00:00Z' },
  { id: 'grp-003', org_id: MOCK_IDENTITY.org_id, name: 'Support', description: 'Customer-facing support agents', allow_raw_http: false, created_at: '2026-03-25T11:00:00Z', updated_at: '2026-03-28T16:00:00Z' }
];

const MOCK_GRANTS = [
  { id: 'grant-001', group_id: 'grp-001', service_instance_id: 'svc-001', service_name: 'github', access_level: 'admin', auto_approve_reads: true, created_at: '2026-03-16T10:00:00Z' },
  { id: 'grant-002', group_id: 'grp-001', service_instance_id: 'svc-002', service_name: 'slack-prod', access_level: 'write', auto_approve_reads: true, created_at: '2026-03-16T10:00:00Z' },
  { id: 'grant-003', group_id: 'grp-001', service_instance_id: 'svc-004', service_name: 'internal-crm', access_level: 'read', auto_approve_reads: false, created_at: '2026-04-02T09:00:00Z' }
];

const MOCK_MEMBERS = [
  MOCK_IDENTITY.identity_id,
  'a1b2c3d4-0001-0001-0001-000000000003',
  'a1b2c3d4-0001-0001-0001-000000000004'
];

const MOCK_IDENTITIES = [
  { id: MOCK_IDENTITY.identity_id, org_id: MOCK_IDENTITY.org_id, name: 'Alice Admin', kind: 'user', email: 'alice@acme.corp', external_id: null, created_at: '2026-03-10T10:00:00Z' },
  { id: 'a1b2c3d4-0001-0001-0001-000000000003', org_id: MOCK_IDENTITY.org_id, name: 'Bob Developer', kind: 'user', email: 'bob@acme.corp', external_id: null, created_at: '2026-03-12T14:00:00Z' },
  { id: 'a1b2c3d4-0001-0001-0001-000000000004', org_id: MOCK_IDENTITY.org_id, name: 'Carol Analyst', kind: 'user', email: 'carol@acme.corp', external_id: null, created_at: '2026-03-15T09:00:00Z' },
  { id: 'a1b2c3d4-0001-0001-0001-000000000005', org_id: MOCK_IDENTITY.org_id, name: 'research-bot', kind: 'agent', email: null, external_id: null, created_at: '2026-04-01T16:00:00Z' }
];

const MOCK_WEBHOOKS = [
  { id: 'wh-001', url: 'https://platform.acme.corp/overslash/events', events: ['approval.created', 'approval.resolved', 'action.executed'], active: true },
  { id: 'wh-002', url: 'https://slack.com/api/webhooks/T0001/B0001/xyzabc123', events: ['approval.created'], active: true }
];

const MOCK_DELIVERIES = [
  { id: 'del-001', subscription_id: 'wh-001', event: 'approval.created', status_code: 200, response_body: '{"ok":true}', attempts: 1, delivered_at: '2026-04-04T10:30:01Z', created_at: '2026-04-04T10:30:00Z' },
  { id: 'del-002', subscription_id: 'wh-001', event: 'action.executed', status_code: 200, response_body: '{"ok":true}', attempts: 1, delivered_at: '2026-04-04T11:15:01Z', created_at: '2026-04-04T11:15:00Z' },
  { id: 'del-003', subscription_id: 'wh-001', event: 'approval.resolved', status_code: 502, response_body: 'Bad Gateway', attempts: 3, delivered_at: null, created_at: '2026-04-04T12:00:00Z' },
  { id: 'del-004', subscription_id: 'wh-001', event: 'action.executed', status_code: 200, response_body: '{"ok":true}', attempts: 1, delivered_at: '2026-04-05T09:00:01Z', created_at: '2026-04-05T09:00:00Z' }
];

const MOCK_IDP_CONFIGS = [
  { provider_key: 'google', display_name: 'Google', source: 'env', enabled: true },
  { id: 'idp-001', org_id: MOCK_IDENTITY.org_id, provider_key: 'oidc-login-microsoftonline-com-acme-corp', display_name: 'Microsoft Entra ID', source: 'db', enabled: true, allowed_email_domains: ['acme.corp', 'acme.io'], created_at: '2026-03-20T10:00:00Z', updated_at: '2026-04-01T08:00:00Z' },
  { id: 'idp-002', org_id: MOCK_IDENTITY.org_id, provider_key: 'github', display_name: 'GitHub', source: 'db', enabled: false, allowed_email_domains: [], created_at: '2026-03-25T14:00:00Z', updated_at: '2026-03-30T09:00:00Z' }
];

const MOCK_ORG = {
  id: MOCK_IDENTITY.org_id,
  name: 'Acme Corp',
  slug: 'acme',
  allow_user_templates: true,
  created_at: '2026-03-01T00:00:00Z'
};

// ── Router ───────────────────────────────────────────────────────────

function mockFetch(data) {
  const origFetch = window.fetch;
  window.fetch = async (url, opts) => {
    const u = typeof url === 'string' ? url : url.toString();
    const method = opts?.method?.toUpperCase() || 'GET';

    // Auth
    if (u.includes('/auth/me/identity')) return json(data.identity);

    // Templates
    if (u.includes('/v1/templates/search')) return json(data.templates);
    if (u.includes('/v1/templates') && method === 'GET') return json(data.templates);

    // Services
    if (u.match(/\/v1\/services$/) && method === 'GET') return json(data.services);

    // Groups
    if (u.match(/\/v1\/groups\/[^/]+\/grants/) && method === 'GET') return json(data.grants);
    if (u.match(/\/v1\/groups\/[^/]+\/members/) && method === 'GET') return json(data.members);
    if (u.match(/\/v1\/groups$/) && method === 'GET') return json(data.groups);

    // Webhooks
    if (u.match(/\/v1\/webhooks\/[^/]+\/deliveries/)) return json(data.deliveries);
    if (u.match(/\/v1\/webhooks$/) && method === 'GET') return json(data.webhooks);

    // Identities
    if (u.includes('/v1/identities')) return json(data.identities);

    // Org
    if (u.includes('/v1/orgs/me')) return json(data.org);

    // IdP
    if (u.includes('/v1/org-idp-configs')) return json(data.idpConfigs);

    return origFetch(url, opts);
  };

  function json(body) {
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// ── Main ─────────────────────────────────────────────────────────────

async function waitForServer(url, maxRetries = 30) {
  for (let i = 0; i < maxRetries; i++) {
    try { const r = await fetch(url); if (r.ok || r.status === 200) return; } catch {}
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error(`Server at ${url} did not start`);
}

async function main() {
  console.log('Starting dev server...');
  const server = spawn('npx', ['vite', 'dev', '--port', '5175'], {
    cwd: resolve(__dirname, '..'),
    stdio: 'pipe',
    env: { ...process.env, npm_config_omit: '' }
  });
  server.stderr.on('data', d => process.stderr.write(d));

  try {
    await waitForServer('http://localhost:5175');
    console.log('Dev server ready.');

    const browser = await chromium.launch();
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });

    const mockData = {
      identity: MOCK_IDENTITY,
      templates: MOCK_TEMPLATES,
      services: MOCK_SERVICES,
      groups: MOCK_GROUPS,
      grants: MOCK_GRANTS,
      members: MOCK_MEMBERS,
      identities: MOCK_IDENTITIES,
      webhooks: MOCK_WEBHOOKS,
      deliveries: MOCK_DELIVERIES,
      idpConfigs: MOCK_IDP_CONFIGS,
      org: MOCK_ORG
    };

    async function capture(route, name, setupFn) {
      const page = await context.newPage();
      await page.addInitScript(mockFetch, mockData);
      await page.goto(`http://localhost:5175${route}`);
      await page.waitForTimeout(2000);
      if (setupFn) await setupFn(page);
      await page.waitForTimeout(500);
      await page.screenshot({ path: `${screenshotDir}/${name}.png`, fullPage: false });
      console.log(`  Saved ${name}.png`);
      await page.close();
    }

    // 1. Sidebar nav
    console.log('Capturing admin-nav-sidebar...');
    await capture('/admin/templates', 'admin-nav-sidebar');

    // 2. Templates list
    console.log('Capturing admin-templates-list...');
    await capture('/admin/templates', 'admin-templates-list');

    // 3. Templates create modal
    console.log('Capturing admin-templates-create-modal...');
    await capture('/admin/templates', 'admin-templates-create-modal', async (page) => {
      await page.click('button:has-text("Create Template")');
      await page.waitForTimeout(300);
      await page.fill('#tpl-key', 'my-api');
      await page.fill('#tpl-name', 'My Custom API');
      await page.fill('#tpl-desc', 'Internal microservice API');
      await page.fill('#tpl-cat', 'Internal');
      await page.fill('#tpl-hosts', 'api.internal.acme.corp');
    });

    // 4. Services list
    console.log('Capturing admin-services-list...');
    await capture('/admin/services', 'admin-services-list');

    // 5. Groups detail
    console.log('Capturing admin-groups-detail...');
    await capture('/admin/groups', 'admin-groups-detail', async (page) => {
      await page.click('button:has-text("Engineering")');
      await page.waitForTimeout(1000);
    });

    // 6. Webhooks with deliveries
    console.log('Capturing admin-webhooks-deliveries...');
    await capture('/admin/webhooks', 'admin-webhooks-deliveries', async (page) => {
      await page.click('button:has-text("Deliveries")');
      await page.waitForTimeout(1000);
    });

    // 7. Settings org card
    console.log('Capturing admin-settings-org...');
    await capture('/admin/settings', 'admin-settings-org');

    // 8. Settings IdP card (scroll down)
    console.log('Capturing admin-settings-idp...');
    await capture('/admin/settings', 'admin-settings-idp', async (page) => {
      await page.evaluate(() => window.scrollTo(0, 600));
    });

    await browser.close();
    console.log('\nAll screenshots captured!');
  } finally {
    server.kill();
  }
}

main().catch(e => { console.error(e); process.exit(1); });

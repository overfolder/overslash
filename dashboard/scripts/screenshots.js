// Screenshot script for PR proof-of-work
// Starts the dev server, injects mock data, and captures screenshots.

import { chromium } from 'playwright';
import { spawn } from 'child_process';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const screenshotDir = resolve(__dirname, '../../docs/screenshots');

// Mock data matching real backend shapes
const MOCK_SERVICES = [
  { key: 'github', display_name: 'GitHub', hosts: ['api.github.com'], action_count: 3 },
  { key: 'slack', display_name: 'Slack', hosts: ['api.slack.com'], action_count: 2 },
  { key: 'stripe', display_name: 'Stripe', hosts: ['api.stripe.com'], action_count: 4 },
  { key: 'google_calendar', display_name: 'Google Calendar', hosts: ['www.googleapis.com'], action_count: 3 },
  { key: 'resend', display_name: 'Resend', hosts: ['api.resend.com'], action_count: 2 },
  { key: 'x', display_name: 'X (Twitter)', hosts: ['api.x.com'], action_count: 2 },
  { key: 'eventbrite', display_name: 'Eventbrite', hosts: ['www.eventbriteapi.com'], action_count: 2 }
];

const MOCK_GITHUB_DETAIL = {
  key: 'github',
  display_name: 'GitHub',
  hosts: ['api.github.com'],
  auth: [
    { type: 'oauth', provider: 'github', token_injection: { as: 'header', header_name: 'Authorization', prefix: 'Bearer ' } },
    { type: 'api_key', default_secret_name: 'github_token', injection: { as: 'header', header_name: 'Authorization', prefix: 'Bearer ' } }
  ],
  actions: {
    list_repos: {
      method: 'GET',
      path: '/user/repos',
      description: 'List repositories for the authenticated user',
      risk: 'read',
      params: {
        sort: { type: 'string', required: false, description: 'Sort by created, updated, pushed, full_name', enum: ['created', 'updated', 'pushed', 'full_name'] },
        per_page: { type: 'integer', required: false, description: 'Results per page (max 100)', default: 30 }
      }
    },
    create_pull_request: {
      method: 'POST',
      path: '/repos/{repo}/pulls',
      description: 'Create a pull request',
      risk: 'write',
      params: {
        repo: { type: 'string', required: true, description: 'owner/repo' },
        title: { type: 'string', required: true, description: 'PR title' },
        head: { type: 'string', required: true, description: 'Branch to merge from' },
        base: { type: 'string', required: true, description: 'Branch to merge into' },
        body: { type: 'string', required: false, description: 'PR description' }
      }
    },
    create_issue: {
      method: 'POST',
      path: '/repos/{repo}/issues',
      description: 'Create an issue',
      risk: 'write',
      params: {
        repo: { type: 'string', required: true, description: 'owner/repo' },
        title: { type: 'string', required: true, description: 'Issue title' },
        body: { type: 'string', required: false, description: 'Issue body' }
      }
    }
  }
};

const MOCK_CONNECTIONS = [
  { id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890', provider_key: 'github', account_email: 'dev@example.com', is_default: true, created_at: '2026-03-28T10:00:00Z' },
  { id: 'b2c3d4e5-f6a7-8901-bcde-f12345678901', provider_key: 'slack', account_email: 'team@example.com', is_default: false, created_at: '2026-03-29T14:30:00Z' }
];

const MOCK_EXECUTE_RESPONSE = {
  status: 'executed',
  result: {
    status_code: 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'x-ratelimit-limit': '5000',
      'x-ratelimit-remaining': '4998',
      'x-github-request-id': 'A1B2:3C4D:5E6F:7A8B:9C0D'
    },
    body: JSON.stringify([
      {
        id: 123456789,
        name: 'overslash',
        full_name: 'octocat/overslash',
        private: false,
        description: 'Multi-tenant actions gateway for AI agents',
        language: 'Rust',
        stargazers_count: 42,
        forks_count: 7,
        updated_at: '2026-03-30T08:15:00Z'
      },
      {
        id: 987654321,
        name: 'hello-world',
        full_name: 'octocat/hello-world',
        private: false,
        description: 'My first repository on GitHub!',
        language: 'JavaScript',
        stargazers_count: 1500,
        forks_count: 320,
        updated_at: '2026-03-29T16:45:00Z'
      }
    ]),
    duration_ms: 142
  },
  action_description: 'List repositories for the authenticated user (GitHub)'
};

async function waitForServer(url, maxRetries = 30) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const resp = await fetch(url);
      if (resp.ok) return true;
    } catch {}
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error(`Server at ${url} did not start in time`);
}

async function main() {
  console.log('Starting dev server...');
  const server = spawn('npx', ['vite', 'dev', '--port', '5174'], {
    cwd: resolve(__dirname, '..'),
    stdio: 'pipe',
    env: { ...process.env, npm_config_omit: '' }
  });

  server.stderr.on('data', (d) => process.stderr.write(d));

  try {
    await waitForServer('http://localhost:5174');
    console.log('Dev server ready.');

    const browser = await chromium.launch();
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();

    // Navigate and wait for SvelteKit to hydrate
    await page.goto('http://localhost:5174');
    await page.waitForTimeout(3000);

    // Set API key in the input
    await page.fill('input[placeholder="osk_..."]', 'osk_demo_xxxxxxxxxxxx');
    await page.waitForTimeout(500);

    // --- Screenshot 1: Service/Action Selector ---
    console.log('Capturing screenshot 1: Service/Action Selector...');

    // Inject mock services into store
    await page.evaluate((data) => {
      // Set services store and trigger reactivity
      window.__MOCK_SERVICES = data.services;
      window.__MOCK_DETAIL = data.detail;
    }, { services: MOCK_SERVICES, detail: MOCK_GITHUB_DETAIL });

    // Override fetch to return mock data
    await page.evaluate((data) => {
      const origFetch = window.fetch;
      window.fetch = async (url, opts) => {
        const urlStr = typeof url === 'string' ? url : url.toString();
        if (urlStr.includes('/v1/services/github')) {
          return new Response(JSON.stringify(data.detail), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        if (urlStr.includes('/v1/services')) {
          return new Response(JSON.stringify(data.services), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        if (urlStr.includes('/v1/connections')) {
          return new Response(JSON.stringify(data.connections), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        if (urlStr.includes('/v1/actions/execute')) {
          return new Response(JSON.stringify(data.executeResponse), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        return origFetch(url, opts);
      };
    }, { services: MOCK_SERVICES, detail: MOCK_GITHUB_DETAIL, connections: MOCK_CONNECTIONS, executeResponse: MOCK_EXECUTE_RESPONSE });

    // Clear the API key and re-enter to trigger fetch with mocked data
    await page.fill('input[placeholder="osk_..."]', '');
    await page.waitForTimeout(200);
    await page.fill('input[placeholder="osk_..."]', 'osk_demo_xxxxxxxxxxxx');
    await page.waitForTimeout(1000);

    // Select GitHub service
    await page.selectOption('#service-select', 'github');
    await page.waitForTimeout(1000);

    // Select create_pull_request action
    await page.selectOption('#action-select', 'create_pull_request');
    await page.waitForTimeout(500);

    await page.screenshot({ path: `${screenshotDir}/dev-tool-selectors.png`, fullPage: false });
    console.log('  Saved dev-tool-selectors.png');

    // --- Screenshot 2: Parameter Form Populated ---
    console.log('Capturing screenshot 2: Parameter Form Populated...');

    // Fill in parameter values
    await page.fill('#param-repo', 'octocat/Hello-World');
    await page.fill('#param-title', 'Amazing new feature');
    await page.fill('#param-head', 'feature/amazing');
    await page.fill('#param-base', 'main');
    await page.fill('#param-body', 'This PR adds an amazing new feature that improves performance by 50%.');
    await page.waitForTimeout(300);

    await page.screenshot({ path: `${screenshotDir}/dev-tool-params.png`, fullPage: false });
    console.log('  Saved dev-tool-params.png');

    // --- Screenshot 3: Execution Result ---
    console.log('Capturing screenshot 3: Execution Result...');

    // Switch back to list_repos (simpler response) and execute
    await page.selectOption('#action-select', 'list_repos');
    await page.waitForTimeout(500);

    // Click execute
    await page.click('button:has-text("Execute")');
    await page.waitForTimeout(1500);

    await page.screenshot({ path: `${screenshotDir}/dev-tool-response.png`, fullPage: false });
    console.log('  Saved dev-tool-response.png');

    await browser.close();
    console.log('All screenshots captured successfully!');
  } finally {
    server.kill();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

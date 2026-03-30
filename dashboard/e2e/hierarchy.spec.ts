import { test, expect } from '@playwright/test';

test('hierarchy tree with inline CRUD', async ({ page }) => {
	// 1. Login via dev token
	await page.goto('/login');
	await page.click('[data-testid="dev-login"]');
	await page.waitForURL('**/hierarchy');

	// Wait for the org node to appear (data loaded)
	await expect(page.locator('.org-node')).toBeVisible();

	// 2. Create a User under the org
	await page.click('[data-testid="add-root-identity"]');
	await page.fill('[data-testid="inline-name"]', 'Alice');
	await page.click('[data-testid="inline-save"]');
	await expect(page.locator('text=Alice')).toBeVisible();

	// 3. Create an Agent under Alice
	await page.click('[data-testid="add-child-Alice"]');
	await page.fill('[data-testid="inline-name"]', 'Agent Henry');
	await page.click('[data-testid="inline-save"]');
	await expect(page.locator('text=Agent Henry')).toBeVisible();

	// 4. Expand Henry and create a SubAgent
	await page.click('[data-testid="add-child-Agent Henry"]');
	await page.fill('[data-testid="inline-name"]', 'Researcher');
	await page.click('[data-testid="inline-save"]');
	await expect(page.locator('text=Researcher')).toBeVisible();

	// SCREENSHOT 1: 3+ levels of nesting
	await page.screenshot({ path: 'e2e/screenshots/01-hierarchy-3-levels.png', fullPage: true });

	// 5. Inline edit: rename Researcher → Senior Researcher
	await page.click('[data-testid="edit-Researcher"]');
	await page.fill('[data-testid="edit-name-input"]', 'Senior Researcher');
	await page.click('[data-testid="edit-save"]');
	await expect(page.locator('text=Senior Researcher')).toBeVisible();

	// SCREENSHOT 2: inline edit result
	await page.screenshot({ path: 'e2e/screenshots/02-inline-edit.png', fullPage: true });

	// 6. Delete Senior Researcher
	await page.click('[data-testid="delete-Senior Researcher"]');
	await page.click('[data-testid="confirm-delete"]');
	// Wait for the dialog to disappear first
	await expect(page.locator('[data-testid="confirm-delete"]')).not.toBeVisible();
	// Then verify the node is gone from the tree
	await expect(page.locator('.node-name', { hasText: 'Senior Researcher' })).not.toBeVisible();

	// SCREENSHOT 3: tree after mutation (node removed)
	await page.screenshot({ path: 'e2e/screenshots/03-after-delete.png', fullPage: true });
});

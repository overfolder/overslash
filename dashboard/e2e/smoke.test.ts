import { test, expect } from '@playwright/test';

test('login page loads', async ({ page }) => {
	await page.goto('/login');
	await expect(page.getByRole('heading', { name: /sign in/i })).toBeVisible();
});

test('unauthenticated users are redirected to login', async ({ page }) => {
	await page.goto('/');
	await expect(page).toHaveURL(/\/login/);
});

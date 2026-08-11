import { test, expect, loginAs } from '../fixtures/auth';

// Behaviour of the composable search bar, driven against a real stack.
//
// `tests/e2e/units/search-terms.spec.ts` pins the term model as pure data.
// What it cannot reach is the component: whether Enter actually mints a
// bubble, whether ✕ removes one, whether clicking a bubble hands it back to
// the input without eating what was half-typed, and — on /audit, the one
// server-side filtered list — whether two text bubbles really AND at the API.

const BAR = '.search input';
const CHIP = '.search .chip';

/** Commit one bubble per Enter. */
async function type(page: import('@playwright/test').Page, ...terms: string[]) {
	const input = page.locator(BAR).first();
	await input.click();
	for (const t of terms) {
		await input.fill(t);
		await input.press('Enter');
	}
	return input;
}

test.describe('search bubbles', () => {
	test.beforeEach(async ({ page, request }) => {
		await loginAs(page, request, 'admin');
	});

	test('text becomes a bubble on Enter, and text bubbles AND server-side', async ({ page }) => {
		await page.goto('/audit');
		await expect(page.locator(BAR).first()).toBeVisible({ timeout: 15_000 });
		await expect(page.locator('tr.row').first()).toBeVisible({ timeout: 15_000 });

		// One text bubble; the input is left empty, so nothing is loose text.
		await type(page, 'action');
		await expect(page.locator(CHIP)).toHaveCount(1);
		await expect(page.locator(BAR).first()).toHaveValue('');
		await expect(page.locator('tr.row').first()).toBeVisible();

		// A second text bubble narrows rather than replacing: both terms must
		// match, so an unmatchable one empties the table. A space-joined `q`
		// would be indistinguishable here, which is why the URL is asserted too.
		await type(page, 'zzzznotathing');
		await expect(page.locator(CHIP)).toHaveCount(2);
		await expect(page.locator('tr.row')).toHaveCount(0);
		await expect(page).toHaveURL(/q=action%2Czzzznotathing|q=action,zzzznotathing/);

		// ✕ on the second bubble widens the result set back out.
		await page.locator(`${CHIP} .chip-remove`).nth(1).click();
		await expect(page.locator(CHIP)).toHaveCount(1);
		await expect(page.locator('tr.row').first()).toBeVisible({ timeout: 15_000 });
	});

	test('a column filter and text compose, and survive a reload', async ({ page }) => {
		await page.goto('/audit');
		await expect(page.locator(BAR).first()).toBeVisible({ timeout: 15_000 });

		await type(page, 'result = error', 'action');
		await expect(page.locator(CHIP)).toHaveCount(2);
		// The filter chip renders its key/op; the text bubble does not.
		await expect(page.locator(CHIP).first()).toContainText('result');
		await expect(page.locator(CHIP).nth(1)).toContainText('action');

		await page.reload();
		await expect(page.locator(BAR).first()).toBeVisible({ timeout: 15_000 });
		// Both come back — `AuditFilters` is an unordered bag, so only the set
		// is guaranteed, not the original interleaving.
		await expect(page.locator(CHIP)).toHaveCount(2);
		await expect(page.locator('.search')).toContainText('result');
		await expect(page.locator('.search')).toContainText('action');
	});

	test('clicking a bubble returns it to the input without eating a half-typed term', async ({
		page
	}) => {
		await page.goto('/audit');
		await expect(page.locator(BAR).first()).toBeVisible({ timeout: 15_000 });

		await type(page, 'alpha');
		await expect(page.locator(CHIP)).toHaveCount(1);

		// Half-type a second term, then click the existing bubble to edit it.
		const input = page.locator(BAR).first();
		await input.fill('beta');
		await page.locator(`${CHIP} .chip-body`).first().click();

		// `alpha` is back in the input for editing, and `beta` was committed
		// rather than silently dropped.
		await expect(input).toHaveValue('alpha');
		await expect(page.locator(CHIP)).toHaveCount(1);
		await expect(page.locator(CHIP).first()).toContainText('beta');
	});

	test('Backspace on an empty input removes the last bubble', async ({ page }) => {
		await page.goto('/audit');
		await expect(page.locator(BAR).first()).toBeVisible({ timeout: 15_000 });

		const input = await type(page, 'alpha', 'beta');
		await expect(page.locator(CHIP)).toHaveCount(2);
		await input.press('Backspace');
		await expect(page.locator(CHIP)).toHaveCount(1);
		await expect(page.locator(CHIP).first()).toContainText('alpha');
	});

	test('a half-picked key can be cancelled instead of stranding a chip', async ({ page }) => {
		await page.goto('/audit');
		await expect(page.locator(BAR).first()).toBeVisible({ timeout: 15_000 });

		// Pick `result =` from the dropdown but type no value: the bar shows a
		// pending chip, which must be dismissable.
		const input = page.locator(BAR).first();
		await input.click();
		await input.fill('result');
		await page.locator('.suggestions button').first().click();
		await expect(page.locator('.chip.is-pending')).toHaveCount(1);

		await page.locator('.chip.is-pending .chip-remove').click();
		await expect(page.locator('.chip.is-pending')).toHaveCount(0);
	});

	test('surfaces that used a bare input now compose too', async ({ page }) => {
		// /approvals used to hold a text input, a risk <select> and a service
		// chip row as three states that could not be combined.
		await page.goto('/approvals');
		await expect(page.locator(BAR).first()).toBeVisible({ timeout: 15_000 });

		await type(page, 'risk = med', 'nothing-matches-this');
		await expect(page.locator(CHIP)).toHaveCount(2);
		await expect(page.getByText(/No requests match your filters/i)).toBeVisible();

		await page.locator(`${CHIP} .chip-remove`).nth(1).click();
		await expect(page.locator(CHIP)).toHaveCount(1);
	});
});

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

/**
 * Write one audit row we can search for. The page's own cookies carry the
 * session, so this lands as the signed-in user.
 */
async function seedAuditRow(page: import('@playwright/test').Page) {
	const res = await page.request.put(
		`${process.env.API_URL}/v1/secrets/e2e_search_bubbles_${Date.now()}`,
		{ data: { value: 'seed' } }
	);
	expect(res.ok(), `seeding audit row failed: HTTP ${res.status()}`).toBeTruthy();
}

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
		// Seed our own audit row rather than relying on whatever traffic other
		// specs happen to have left behind — `secret.put` gives a row whose
		// `action` contains both of the terms searched below.
		await seedAuditRow(page);

		await page.goto('/audit');
		await expect(page.locator(BAR).first()).toBeVisible({ timeout: 15_000 });
		await expect(page.locator('tr.row').first()).toBeVisible({ timeout: 15_000 });

		// One text bubble; the input is left empty, so nothing is loose text.
		await type(page, 'secret');
		await expect(page.locator(CHIP)).toHaveCount(1);
		await expect(page.locator(BAR).first()).toHaveValue('');
		await expect(page.locator('tr.row').first()).toBeVisible();

		// A second text bubble narrows rather than replacing: both terms must
		// match, so an unmatchable one empties the table. A space-joined `q`
		// would be indistinguishable here, which is why the URL is asserted too.
		await type(page, 'zzzznotathing');
		await expect(page.locator(CHIP)).toHaveCount(2);
		await expect(page.locator('tr.row')).toHaveCount(0);
		await expect(page).toHaveURL(/q=secret%2Czzzznotathing|q=secret,zzzznotathing/);

		// ✕ on the second bubble widens the result set back out.
		await page.locator(`${CHIP} .chip-remove`).nth(1).click();
		await expect(page.locator(CHIP)).toHaveCount(1);
		await expect(page.locator('tr.row').first()).toBeVisible({ timeout: 15_000 });
	});

	test('a comma inside a text term stays one bubble across a reload', async ({ page }) => {
		await seedAuditRow(page);
		await page.goto('/audit');
		await expect(page.locator(BAR).first()).toBeVisible({ timeout: 15_000 });

		// The comma is what would naively split `q` into two terms on the way
		// back in; it is escaped on the wire so the bubble survives intact.
		await type(page, 'New York, NY');
		await expect(page.locator(CHIP)).toHaveCount(1);

		await page.reload();
		await expect(page.locator(BAR).first()).toBeVisible({ timeout: 15_000 });
		await expect(page.locator(CHIP)).toHaveCount(1);
		await expect(page.locator(CHIP).first()).toContainText('New York, NY');
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

	test('a surface that used a bare input now composes too', async ({ page }) => {
		// /members held a bare `<input type="search">` with no keys and no
		// bubbles. It is the deterministic subject for this: the signed-in admin
		// is always a member, whereas /approvals only renders its bar when the
		// queue is non-empty, so a fresh CI org has nothing to search.
		await page.goto('/members');
		await expect(page.locator(BAR).first()).toBeVisible({ timeout: 15_000 });
		await expect(page.locator('tbody tr').first()).toBeVisible({ timeout: 15_000 });

		// `email ~ @` matches every member regardless of fixture data, so the
		// text bubble is what does the narrowing.
		await type(page, 'email ~ @', 'zzzznotathing');
		await expect(page.locator(CHIP)).toHaveCount(2);
		await expect(page.locator('tbody tr')).toHaveCount(0);

		// Dropping the text bubble leaves the column filter, and the rows return.
		await page.locator(`${CHIP} .chip-remove`).nth(1).click();
		await expect(page.locator(CHIP)).toHaveCount(1);
		await expect(page.locator('tbody tr').first()).toBeVisible();
	});
});

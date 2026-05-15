<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { ApiError, session } from '$lib/session';
	import { slugify, makeDebouncedSlugChecker, type SlugCheck } from '$lib/utils/slug';

	type GeoResponse = { currency: string; base_price: number };

	const SLUG_REASONS: Record<string, string> = {
		slug_too_short: 'Slug must be at least 2 characters.',
		slug_too_long: 'Slug must be at most 63 characters.',
		slug_invalid_chars: 'Only lowercase letters, digits, and hyphens.',
		slug_leading_or_trailing_hyphen: 'No leading or trailing hyphens.',
		slug_reserved: 'This slug is reserved.',
		slug_taken: 'Already taken.',
		lookup_failed: 'Could not verify slug — try again.'
	};

	function describeSlugReason(code: string): string {
		return SLUG_REASONS[code] ?? code;
	}

	let currency = $state('eur');
	let basePrice = $state(15);
	let geoLoaded = $state(false);

	let orgName = $state('');
	let orgSlug = $state('');
	let slugTouched = $state(false);
	let seats = $state(2);

	let slugCheck = $state<SlugCheck>({ kind: 'idle' });
	const scheduleSlugCheck = makeDebouncedSlugChecker((s) => (slugCheck = s));

	let submitting = $state(false);
	let submitError = $state<string | null>(null);

	onMount(async () => {
		// Prefill from query params when the user lands here from the
		// instance-admin Create-Org modal with the toggle off.
		const qsName = $page.url.searchParams.get('name');
		const qsSlug = $page.url.searchParams.get('slug');
		if (qsName) orgName = qsName;
		if (qsSlug) {
			orgSlug = qsSlug;
			slugTouched = true;
			scheduleSlugCheck(qsSlug);
		}

		try {
			const geo = await session.get<GeoResponse>('/v1/billing/geo');
			currency = geo.currency;
			basePrice = geo.base_price;
		} catch {
			// Default to EUR if geo fails
		}
		geoLoaded = true;
	});

	const totalPerMonth = $derived(seats * basePrice);
	const currencySymbol = $derived(currency === 'eur' ? '€' : '$');
	const currencyUpper = $derived(currency.toUpperCase());

	const canSubmit = $derived(
		!submitting &&
			orgName.trim() !== '' &&
			orgSlug.trim() !== '' &&
			slugCheck.kind === 'available' &&
			seats >= 2 &&
			seats <= 20
	);

	function onNameInput(e: Event) {
		const value = (e.currentTarget as HTMLInputElement).value;
		orgName = value;
		if (!slugTouched) {
			orgSlug = slugify(value);
			scheduleSlugCheck(orgSlug);
		}
	}

	function onSlugInput(e: Event) {
		orgSlug = (e.currentTarget as HTMLInputElement).value;
		slugTouched = true;
		scheduleSlugCheck(orgSlug);
	}

	function onSlugBlur() {
		if (orgSlug.trim() === '') {
			slugTouched = false;
			orgSlug = slugify(orgName);
			scheduleSlugCheck(orgSlug);
		}
	}

	async function submit(e: Event) {
		e.preventDefault();
		if (!canSubmit) return;
		submitting = true;
		submitError = null;
		try {
			const res = await session.post<{ url: string }>('/v1/billing/checkout', {
				org_name: orgName.trim(),
				org_slug: orgSlug.trim(),
				seats,
				currency
			});
			window.location.href = res.url;
		} catch (err) {
			if (err instanceof ApiError) {
				const body = err.body as { error?: string } | undefined;
				const code = body?.error ?? `http_${err.status}`;
				if (code === 'slug_taken' || code.startsWith('slug_')) {
					slugCheck = { kind: 'invalid', reason: code };
					submitError = describeSlugReason(code);
				} else {
					submitError = code;
				}
			} else {
				submitError = 'Something went wrong. Please try again.';
			}
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>New Team org — Overslash</title>
</svelte:head>

<div class="page">
	<div class="card">
		<h1>Create a Team org</h1>
		<p class="subtitle">
			Collaborate with your team. Shared connections, secrets, and audit logs.
		</p>

		<form onsubmit={submit}>
			<label>
				<span>Organization name</span>
				<!-- svelte-ignore a11y_autofocus -->
				<input
					type="text"
					value={orgName}
					oninput={onNameInput}
					placeholder="Acme Inc."
					required
					disabled={submitting}
					autofocus
				/>
			</label>

			<label>
				<span>Slug</span>
				<input
					type="text"
					value={orgSlug}
					oninput={onSlugInput}
					onblur={onSlugBlur}
					placeholder="acme"
					pattern="[a-z0-9-]+"
					required
					disabled={submitting}
					aria-invalid={slugCheck.kind === 'invalid'}
				/>
				{#if slugCheck.kind === 'checking'}
					<span class="slug-status checking">Checking…</span>
				{:else if slugCheck.kind === 'available'}
					<span class="slug-status ok">✓ Available</span>
				{:else if slugCheck.kind === 'invalid'}
					<span class="slug-status bad">{describeSlugReason(slugCheck.reason)}</span>
				{:else}
					<span class="hint">Used in the org's subdomain. Lowercase letters, digits, hyphens.</span>
				{/if}
			</label>

			<div class="seats-row">
				<label class="seats-label">
					<span>Seats</span>
					<div class="seats-control">
						<button
							type="button"
							class="seat-btn"
							disabled={seats <= 2 || submitting}
							onclick={() => seats--}
						>−</button>
						<span class="seat-count">{seats}</span>
						<button
							type="button"
							class="seat-btn"
							disabled={seats >= 20 || submitting}
							onclick={() => seats++}
						>+</button>
					</div>
				</label>
				{#if geoLoaded}
					<div class="price-preview">
						<span class="price-amount">{currencySymbol}{totalPerMonth}</span>
						<span class="price-period">/{currencyUpper}/month</span>
						<span class="price-hint">{currencySymbol}{basePrice} × {seats} seats · VAT added at checkout</span>
					</div>
				{/if}
			</div>

			{#if submitError}
				<div class="error">{submitError}</div>
			{/if}

			<button type="submit" class="btn-primary" disabled={!canSubmit}>
				{#if submitting}
					Redirecting to Stripe…
				{:else}
					Continue to payment →
				{/if}
			</button>
		</form>

		<p class="legal">
			Billed monthly. Cancel any time from the Stripe portal.
			OSS, research, or education? <a href="mailto:sales@overslash.com">Email us</a> — we usually say yes.
		</p>
	</div>
</div>

<style>
	.page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem 1rem;
		background: var(--color-bg);
	}

	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 12px;
		padding: 2rem;
		max-width: 480px;
		width: 100%;
		box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
		display: flex;
		flex-direction: column;
		gap: 1.25rem;
	}

	h1 {
		margin: 0;
		font-size: 1.25rem;
		font-weight: 700;
		color: var(--color-text-heading, var(--color-text));
	}

	.subtitle {
		margin: -0.5rem 0 0;
		font-size: 0.875rem;
		color: var(--color-text-muted);
	}

	form {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	label {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
		font-size: 0.85rem;
		color: var(--color-text);
	}

	label span {
		font-weight: 500;
	}

	input {
		padding: 0.5rem 0.65rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-surface);
		color: var(--color-text);
		font-size: 0.9rem;
	}

	input:disabled {
		opacity: 0.6;
	}

	input[aria-invalid='true'] {
		border-color: var(--color-danger, #b00020);
	}

	.hint {
		font-size: 0.75rem;
		color: var(--color-text-muted);
	}

	.slug-status {
		font-size: 0.75rem;
	}
	.slug-status.checking { color: var(--color-text-muted); }
	.slug-status.ok { color: var(--color-success, #1b8a3a); }
	.slug-status.bad { color: var(--color-danger, #b00020); }

	.seats-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		flex-wrap: wrap;
	}

	.seats-label {
		flex: 0 0 auto;
	}

	.seats-control {
		display: flex;
		align-items: center;
		gap: 0.6rem;
		margin-top: 0.3rem;
	}

	.seat-btn {
		width: 2rem;
		height: 2rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-surface);
		color: var(--color-text);
		font-size: 1rem;
		cursor: pointer;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.seat-btn:hover:not(:disabled) {
		background: var(--color-neutral-100, var(--color-border));
	}

	.seat-btn:disabled {
		opacity: 0.4;
		cursor: default;
	}

	.seat-count {
		font-size: 1.1rem;
		font-weight: 600;
		min-width: 2ch;
		text-align: center;
	}

	.price-preview {
		display: flex;
		flex-direction: column;
		align-items: flex-end;
		gap: 0.1rem;
	}

	.price-amount {
		font-size: 1.4rem;
		font-weight: 700;
		color: var(--color-text);
	}

	.price-period {
		font-size: 0.8rem;
		color: var(--color-text-muted);
		margin-top: -0.2rem;
	}

	.price-hint {
		font-size: 0.7rem;
		color: var(--color-text-muted);
	}

	.error {
		padding: 0.5rem 0.75rem;
		background: color-mix(in srgb, var(--color-danger, #b00020) 10%, transparent);
		border: 1px solid color-mix(in srgb, var(--color-danger, #b00020) 30%, transparent);
		border-radius: 6px;
		color: var(--color-danger, #b00020);
		font-size: 0.85rem;
	}

	.btn-primary {
		padding: 0.65rem 1.25rem;
		background: var(--color-primary);
		border: none;
		border-radius: 8px;
		color: #fff;
		font-size: 0.95rem;
		font-weight: 600;
		cursor: pointer;
		transition: filter 0.15s;
	}

	.btn-primary:hover:not(:disabled) {
		filter: brightness(1.08);
	}

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: default;
	}

	.legal {
		font-size: 0.75rem;
		color: var(--color-text-muted);
		text-align: center;
		margin: 0;
	}

	.legal a {
		color: var(--color-primary);
	}
</style>

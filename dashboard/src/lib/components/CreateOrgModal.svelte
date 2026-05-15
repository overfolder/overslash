<script lang="ts">
	import { ApiError, session } from '$lib/session';
	import { slugify, makeDebouncedSlugChecker, type SlugCheck } from '$lib/utils/slug';

	let {
		open,
		onClose
	}: {
		open: boolean;
		onClose: () => void;
	} = $props();

	let orgName = $state('');
	let orgSlug = $state('');
	let slugTouched = $state(false);
	let freeUnlimited = $state(true);
	let submitting = $state(false);
	let submitError = $state<string | null>(null);

	let slugCheck = $state<SlugCheck>({ kind: 'idle' });
	const scheduleSlugCheck = makeDebouncedSlugChecker((s) => (slugCheck = s));

	const canSubmit = $derived(
		orgName.trim() !== '' &&
			orgSlug.trim() !== '' &&
			slugCheck.kind === 'available' &&
			!submitting
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

	function reset() {
		orgName = '';
		orgSlug = '';
		slugTouched = false;
		freeUnlimited = true;
		submitError = null;
		slugCheck = { kind: 'idle' };
	}

	function close() {
		if (submitting) return;
		reset();
		onClose();
	}

	async function submit(e: Event) {
		e.preventDefault();
		if (!canSubmit) return;

		// Toggle off → bounce to the Stripe checkout flow with the form
		// values prefilled. The new endpoint isn't the right surface there.
		if (!freeUnlimited) {
			const params = new URLSearchParams({
				name: orgName.trim(),
				slug: orgSlug.trim()
			});
			window.location.href = `/billing/new-team?${params.toString()}`;
			return;
		}

		submitting = true;
		submitError = null;
		try {
			const res = await session.post<{ redirect_to?: string }>(
				'/v1/orgs/free-unlimited',
				{
					name: orgName.trim(),
					slug: orgSlug.trim()
				}
			);
			if (res.redirect_to) {
				window.location.href = res.redirect_to;
			} else {
				// Drop the submitting flag before close() so the inflight
				// guard there doesn't no-op the dismiss.
				submitting = false;
				reset();
				onClose();
			}
		} catch (err) {
			if (err instanceof ApiError) {
				const body = err.body as { error?: string } | undefined;
				submitError = body?.error ?? `http_${err.status}`;
			} else {
				submitError = 'Something went wrong. Please try again.';
			}
			submitting = false;
		}
	}
</script>

{#if open}
	<div class="backdrop" role="dialog" aria-modal="true" aria-labelledby="com-title">
		<form class="card" onsubmit={submit}>
			<h2 id="com-title">Create org</h2>

			<label class="field">
				<span class="label">Name</span>
				<input
					type="text"
					value={orgName}
					oninput={onNameInput}
					placeholder="Acme Inc."
					required
					disabled={submitting}
				/>
			</label>

			<label class="field">
				<span class="label">Slug</span>
				<input
					type="text"
					value={orgSlug}
					oninput={onSlugInput}
					placeholder="acme"
					required
					disabled={submitting}
				/>
				{#if slugCheck.kind === 'invalid'}
					<span class="hint error">{slugCheck.reason}</span>
				{:else if slugCheck.kind === 'checking'}
					<span class="hint">Checking…</span>
				{:else if slugCheck.kind === 'available'}
					<span class="hint ok">Available</span>
				{/if}
			</label>

			<label class="toggle-row">
				<input type="checkbox" bind:checked={freeUnlimited} disabled={submitting} />
				<span>
					<strong>Free Unlimited</strong>
					<span class="muted">Skip Stripe; create directly with no rate limits.</span>
				</span>
			</label>

			{#if submitError}
				<p class="error" role="alert">{submitError}</p>
			{/if}

			<div class="actions">
				<button class="btn" type="button" disabled={submitting} onclick={close}>
					Cancel
				</button>
				<button class="btn btn-primary" type="submit" disabled={!canSubmit}>
					{submitting ? 'Creating…' : freeUnlimited ? 'Create' : 'Continue to checkout'}
				</button>
			</div>
		</form>
	</div>
{/if}

<style>
	.backdrop {
		position: fixed;
		inset: 0;
		background: rgba(23, 25, 28, 0.45);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
		padding: var(--space-4);
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 16px;
		padding: 24px 28px;
		max-width: 420px;
		width: 100%;
		box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
		display: flex;
		flex-direction: column;
		gap: 14px;
	}
	h2 {
		margin: 0;
		font-weight: 700;
		font-size: 16px;
		color: var(--color-text-heading);
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	.label {
		font-size: 12px;
		color: var(--color-text-muted);
	}
	input[type='text'] {
		padding: 8px 10px;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-bg, var(--color-surface));
		color: var(--color-text);
		font: inherit;
	}
	.hint {
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.hint.ok {
		color: var(--color-success, #1b8a3a);
	}
	.hint.error {
		color: var(--color-danger, #b91c1c);
	}
	.toggle-row {
		display: flex;
		align-items: flex-start;
		gap: 8px;
		font-size: 13px;
	}
	.toggle-row .muted {
		display: block;
		color: var(--color-text-muted);
		font-weight: 400;
	}
	.error {
		color: var(--color-danger, #b91c1c);
		font-size: 13px;
		margin: 0;
	}
	.actions {
		display: flex;
		gap: 8px;
		justify-content: flex-end;
	}
	.btn {
		padding: 10px 16px;
		border-radius: 8px;
		cursor: pointer;
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text);
		font: inherit;
	}
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn-primary {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: #fff;
	}
</style>

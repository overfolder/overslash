<script lang="ts">
	/**
	 * Invitations addressed to the signed-in user, from orgs they haven't
	 * joined. Sits directly above the org switcher because that is where the
	 * org-identity mental model already lives: these are the orgs that could
	 * be in the switcher but aren't yet.
	 *
	 * Data comes in as a prop (from `/auth/me/identity` via the layout load),
	 * not fetched here — same rule as the sidebar's build stamp, so the shell
	 * stays inert in Storybook and screenshot scenarios.
	 */
	import { invalidateAll } from '$app/navigation';
	import { sidebarCollapsed } from '$lib/stores/shell';
	import { pushToast } from '$lib/stores/toasts.svelte';
	import { ApiError } from '$lib/session';
	import {
		acceptInvitation,
		declineInvitation,
		switchOrg,
		type PendingInvitation
	} from '$lib/api/account';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';

	type Props = {
		invitations: PendingInvitation[];
		collapsed?: boolean;
	};

	let { invitations, collapsed = false }: Props = $props();

	/** Id of the invitation currently being accepted, if any. */
	let accepting: string | null = $state(null);
	let declineTarget: PendingInvitation | null = $state(null);
	let declining = $state(false);
	let declineError: string | null = $state(null);

	const REASONS: Record<string, string> = {
		org_requires_idp_signin: 'This org requires signing in through its own provider.'
	};

	function describe(e: unknown, fallback: string): string {
		if (e instanceof ApiError) {
			const body = e.body as { error?: string; message?: string } | undefined;
			const code = body?.error ?? body?.message ?? '';
			if (REASONS[code]) return REASONS[code];
			if (code) return code;
		}
		return e instanceof Error ? e.message : fallback;
	}

	async function accept(inv: PendingInvitation) {
		if (accepting) return;
		accepting = inv.id;
		try {
			await acceptInvitation(inv.id);
			// Land in the org they just joined. `switchOrg` navigates away, so
			// nothing after it runs on the happy path.
			await switchOrg(inv.org_id);
		} catch (e) {
			pushToast('error', describe(e, `Could not join ${inv.org_name}`));
			accepting = null;
		}
	}

	async function confirmDecline() {
		if (!declineTarget) return;
		declining = true;
		declineError = null;
		try {
			await declineInvitation(declineTarget.id);
			const name = declineTarget.org_name;
			declineTarget = null;
			declining = false;
			pushToast('info', `Declined the invitation to ${name}`);
			// Re-runs the layout load, which re-reads `/auth/me/identity`.
			await invalidateAll();
		} catch (e) {
			declineError = describe(e, 'Could not decline the invitation');
			declining = false;
		}
	}
</script>

{#if invitations.length > 0}
	{#if collapsed}
		<button
			class="rail"
			type="button"
			onclick={() => sidebarCollapsed.set(false)}
			title={invitations.length === 1
				? '1 pending invitation'
				: `${invitations.length} pending invitations`}
		>
			<span class="rail-icon" aria-hidden="true">✉</span>
			<span class="count">{invitations.length}</span>
		</button>
	{:else}
		<section class="invites" aria-label="Pending invitations">
			<div class="section-label">INVITATIONS</div>
			{#each invitations as inv (inv.id)}
				<div class="invite">
					<div class="org">{inv.org_name}</div>
					<div class="meta">invited as {inv.role}</div>
					{#if inv.can_accept_in_place}
						<div class="actions">
							<button
								class="accept"
								type="button"
								disabled={accepting !== null}
								onclick={() => accept(inv)}
							>
								{accepting === inv.id ? 'Joining…' : 'Accept'}
							</button>
							<button
								class="decline"
								type="button"
								disabled={accepting !== null}
								onclick={() => (declineTarget = inv)}
							>
								Decline
							</button>
						</div>
					{:else}
						<!-- The org admits members through its own IdP; accepting
						     has to happen on its subdomain. -->
						<a class="signin" href={inv.sign_in_url}>Sign in to accept →</a>
					{/if}
				</div>
			{/each}
		</section>
	{/if}
{/if}

<ConfirmModal
	open={declineTarget !== null}
	title="Decline invitation"
	message={declineTarget
		? `Decline the invitation to ${declineTarget.org_name}? An admin would have to invite you again.`
		: ''}
	confirmLabel="Decline"
	destructive
	busy={declining}
	error={declineError}
	onConfirm={confirmDecline}
	onCancel={() => {
		declineTarget = null;
		declineError = null;
	}}
/>

<style>
	.invites {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}
	/* Mirrors the sidebar's own ADMIN heading. */
	.section-label {
		font-size: 0.6875rem;
		font-weight: 600;
		letter-spacing: 0.06em;
		color: var(--color-text-muted);
		padding: 0.25rem 0.75rem 0.15rem;
	}
	.invite {
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md, 8px);
		background: var(--color-bg);
		padding: 0.5rem 0.6rem;
		display: flex;
		flex-direction: column;
		gap: 0.15rem;
	}
	.org {
		font-size: 0.85rem;
		font-weight: 600;
		color: var(--color-text-heading, var(--color-text));
		/* Org names are user-supplied and the rail is narrow. */
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.meta {
		font-size: 0.7rem;
		color: var(--color-text-muted);
	}
	.actions {
		display: flex;
		gap: 0.35rem;
		margin-top: 0.35rem;
	}
	.actions button {
		flex: 1;
		cursor: pointer;
		border-radius: 6px;
		font-size: 0.75rem;
		padding: 0.3rem 0.4rem;
		border: 1px solid transparent;
	}
	.actions button:disabled {
		cursor: default;
		opacity: 0.6;
	}
	.accept {
		background: var(--color-primary);
		color: #fff;
	}
	.accept:hover:not(:disabled) {
		background: var(--color-primary-hover, var(--color-primary));
	}
	.decline {
		background: transparent;
		border-color: var(--color-border);
		color: var(--color-text-secondary, var(--color-text));
	}
	.decline:hover:not(:disabled) {
		background: var(--color-neutral-100, var(--color-border));
		color: var(--color-text);
	}
	.signin {
		font-size: 0.75rem;
		color: var(--color-primary);
		text-decoration: none;
		margin-top: 0.25rem;
	}
	.signin:hover {
		text-decoration: underline;
	}
	/* Collapsed rail: 64px leaves no room for org names, so show the count
	   and expand the sidebar on click rather than opening a popover. */
	.rail {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.3rem;
		background: transparent;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		color: var(--color-text);
		cursor: pointer;
		padding: 0.35rem;
	}
	.rail:hover {
		background: var(--color-neutral-100, var(--color-border));
	}
	.rail-icon {
		font-size: 0.9rem;
		line-height: 1;
	}
	.count {
		font-size: 0.7rem;
		font-weight: 600;
		background: var(--color-primary);
		color: #fff;
		border-radius: var(--radius-pill, 999px);
		padding: 0 0.35rem;
		line-height: 1.4;
	}
</style>

<script lang="ts">
	import { onMount } from 'svelte';
	import {
		listSessions,
		revokeOtherSessions,
		revokeSession,
		type AccountSession
	} from '$lib/api/account';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import { absoluteTime, relativeTime } from '$lib/utils/time';
	import { describeUserAgent } from '$lib/utils/userAgent';

	let sessions: AccountSession[] = $state([]);
	let loading = $state(true);
	let error: string | null = $state(null);
	let busyId: string | null = $state(null);
	let confirmOthers = $state(false);
	let othersBusy = $state(false);
	let othersError: string | null = $state(null);

	const others = $derived(sessions.filter((s) => !s.current));

	async function load() {
		try {
			sessions = (await listSessions()).sessions;
			error = null;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load sessions';
		} finally {
			loading = false;
		}
	}

	onMount(load);

	async function terminate(s: AccountSession) {
		busyId = s.id;
		error = null;
		try {
			await revokeSession(s.id);
			if (s.current) {
				// Ending this session is a sign-out; the cookie is already cleared.
				window.location.href = '/login';
				return;
			}
			sessions = sessions.filter((x) => x.id !== s.id);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to end session';
		} finally {
			busyId = null;
		}
	}

	async function terminateOthers() {
		othersBusy = true;
		othersError = null;
		try {
			await revokeOtherSessions();
			confirmOthers = false;
			await load();
		} catch (e) {
			othersError = e instanceof Error ? e.message : 'Failed to end sessions';
		} finally {
			othersBusy = false;
		}
	}
</script>

<div class="card" data-testid="sessions-card">
	<div class="head">
		<h2>Sessions</h2>
		{#if others.length > 0}
			<button type="button" class="danger" onclick={() => (confirmOthers = true)}>
				Sign out all other sessions
			</button>
		{/if}
	</div>
	<p class="muted intro">
		Every browser signed in to your account. Ending a session signs that browser out immediately.
	</p>

	{#if loading}
		<p class="muted">Loading…</p>
	{:else if error && sessions.length === 0}
		<p class="error">{error}</p>
	{:else}
		<ul class="sessions">
			{#each sessions as s (s.id)}
				<li class:current={s.current}>
					<div class="s-main">
						<div class="s-head">
							<strong title={s.user_agent ?? ''}>{describeUserAgent(s.user_agent)}</strong>
							{#if s.current}
								<span class="tag current-tag">This session</span>
							{/if}
						</div>
						<div class="s-meta muted">
							<span>{s.org_name}</span>
							{#if s.ip_address}
								<span>·</span>
								<span><code>{s.ip_address}</code></span>
							{/if}
							<span>·</span>
							<span title={absoluteTime(s.last_seen_at)}>
								{s.current ? 'Active now' : `Active ${relativeTime(s.last_seen_at)}`}
							</span>
							<span>·</span>
							<span title={absoluteTime(s.created_at)}>
								Signed in {relativeTime(s.created_at)}
							</span>
						</div>
					</div>
					<button
						type="button"
						class="danger"
						disabled={busyId === s.id}
						onclick={() => terminate(s)}
					>
						{busyId === s.id ? 'Ending…' : s.current ? 'Sign out' : 'End session'}
					</button>
				</li>
			{/each}
		</ul>
		{#if error}
			<p class="error">{error}</p>
		{/if}
	{/if}
</div>

<ConfirmModal
	open={confirmOthers}
	title="Sign out all other sessions?"
	message={`This ends ${others.length} other ${others.length === 1 ? 'session' : 'sessions'}. Those browsers will have to sign in again. This session stays signed in.`}
	confirmLabel="Sign out others"
	destructive
	busy={othersBusy}
	error={othersError}
	onConfirm={terminateOthers}
	onCancel={() => {
		confirmOthers = false;
		othersError = null;
	}}
/>

<style>
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 1rem 1.25rem;
		margin-bottom: 1rem;
	}
	.head {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 0.75rem;
		margin-bottom: 0.25rem;
	}
	h2 {
		margin: 0;
		font-size: 1rem;
	}
	.intro {
		font-size: 0.85rem;
		margin: 0 0 0.75rem 0;
	}
	.sessions {
		list-style: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
	.sessions li {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 0.75rem;
		padding: 0.6rem 0.75rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
	}
	.sessions li.current {
		border-color: var(--color-primary, var(--color-border));
	}
	.s-main {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
		min-width: 0;
	}
	.s-head {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}
	.s-meta {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
		font-size: 0.8rem;
	}
	.tag {
		font-size: 0.65rem;
		padding: 0.05rem 0.4rem;
		background: var(--color-neutral-100, var(--color-border));
		border-radius: 10px;
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	code {
		font-family: ui-monospace, SFMono-Regular, monospace;
		font-size: 0.8rem;
	}
	button {
		flex-shrink: 0;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 4px;
		padding: 0.3rem 0.65rem;
		cursor: pointer;
		font-size: 0.85rem;
	}
	button:hover:not(:disabled) {
		background: var(--color-neutral-100, var(--color-border));
	}
	button.danger {
		color: var(--color-danger, #b00020);
	}
	button:disabled {
		opacity: 0.6;
		cursor: default;
	}
	.error {
		color: var(--color-danger, #b00020);
	}
	.muted {
		color: var(--color-text-muted);
	}
	@media (max-width: 560px) {
		.sessions li {
			flex-direction: column;
			align-items: flex-start;
		}
	}
</style>

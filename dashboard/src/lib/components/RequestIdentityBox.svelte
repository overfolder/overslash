<!--
	"Which organization is this, and who am I here?" — answered the same way on
	all three pages a person reaches from outside the dashboard: the MCP
	enrollment consent screen, the secret-request page, and the service setup
	page.

	All three arrive out of band — a link in a chat message, a browser handed
	off by an MCP client — and all three ask the visitor to hand something over.
	"Which company am I giving this to?" is the first question a careful person
	asks, so it gets the same label, the same position and the same shape
	everywhere rather than being a dropdown on one page, a footnote on another
	and absent from the third.

	The organization is **uneditable text** except on the enrollment screen,
	where a multi-org member genuinely has a choice to make and passes a
	`orgControl` snippet holding the switcher. On the two token-gated pages
	there is nothing to switch to: the signed URL names one org and only one,
	so a control there would offer a choice that does not exist.
-->
<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		orgName,
		userEmail = null,
		/** Replaces the org name with a control. Enrollment only. */
		orgControl,
		/** Rendered under the rows — e.g. the audit-trail note. */
		note
	}: {
		orgName: string;
		userEmail?: string | null;
		orgControl?: Snippet;
		note?: Snippet;
	} = $props();
</script>

<div class="identity-box">
	<div class="row">
		<span class="k">Organization</span>
		{#if orgControl}
			<span class="v control">{@render orgControl()}</span>
		{:else}
			<span class="v name">{orgName}</span>
		{/if}
	</div>
	<div class="row">
		<span class="k">Signed in as</span>
		{#if userEmail}
			<span class="v name">{userEmail}</span>
		{:else}
			<!-- Not an error state. The secret-request and setup pages are
			     reachable without a session by design: the URL's signed token is
			     the capability gate. Saying so is what stops "Signed in as —"
			     reading as a bug. -->
			<span class="v muted">Not signed in</span>
		{/if}
	</div>
	{#if note}
		<p class="note">{@render note()}</p>
	{/if}
</div>

<style>
	.identity-box {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
		background: var(--color-sidebar);
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 0.75rem 1rem;
		margin-bottom: 1rem;
	}
	.row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		font-size: 0.85rem;
	}
	.k {
		font: var(--text-label-sm);
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.06em;
		flex: none;
	}
	.v {
		text-align: right;
		min-width: 0;
		overflow-wrap: anywhere;
	}
	.name {
		font-weight: 600;
		color: var(--color-text-heading);
	}
	.muted {
		color: var(--color-text-muted);
	}
	/* The switcher wants the row's spare width; a name does not. */
	.control {
		flex: 1;
		display: flex;
		justify-content: flex-end;
	}
	.note {
		margin: 0.15rem 0 0;
		font-size: 0.78rem;
		line-height: 1.45;
		color: var(--color-text-muted);
	}
</style>

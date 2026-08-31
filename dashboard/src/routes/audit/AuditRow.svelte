<script lang="ts">
	import IdentityPath from '$lib/components/IdentityPath.svelte';
	import AgentAvatar from '$lib/components/AgentAvatar.svelte';
	import { identityUnits, formatIdentityPath } from '$lib/identityPath';
	import {
		makeIdentityFormatter,
		type IdentityFormatter,
		type IdentityLike
	} from '$lib/identityDisplay';
	import { formatBytes } from '$lib/approvals/format';
	import {
		recordedNames,
		responseCapture,
		transportError,
		upstreamError,
		upstreamResultLabel,
		type AuditEntry
	} from './types';

	let {
		entry,
		expanded,
		ontoggle,
		currentUserId,
		identityById = new Map(),
		fmt = makeIdentityFormatter([]),
		ontagclick
	}: {
		entry: AuditEntry;
		expanded: boolean;
		ontoggle: () => void;
		/** Identity id of the logged-in user, so their own rows show a "Me" pill. */
		currentUserId?: string | null;
		/** Org identities keyed by id, so a path unit can be labelled by email
		 *  rather than by the display name frozen into the SPIFFE path — and so
		 *  an agent unit can carry its client mark. */
		identityById?: Map<
			string,
			IdentityLike & {
				id: string;
				icon_url?: string | null;
				icon_stripe?: string[] | null;
				mcp_client_label?: string | null;
			}
		>;
		/** Identity label formatter pre-bound to the org's allowed domains.
		 *  Defaults to none so the row renders standalone. */
		fmt?: IdentityFormatter;
		/** Narrow the search to a tag. Clicking a chip is the discovery path —
		 *  nobody types `table:warehouse/public.orders` from memory. */
		ontagclick?: (tag: string) => void;
	} = $props();

	// Split the actor's identity path into its owning user and leaf agent so the
	// table can show them in separate columns. `units.user`/`units.leaf` are null
	// when the path lacks that segment (e.g. a human acting directly has no agent).
	const units = $derived(identityUnits(entry.identity_path, entry.identity_path_ids));
	// Match on identity id, not name: similarly-named users across the org are
	// exactly the ambiguity this column split exists to resolve.
	const isMe = $derived(!!currentUserId && units.user?.id === currentUserId);

	// Users are labelled by (domain-stripped) email everywhere in the dashboard;
	// the audit table is no exception. The path only carries the IdP display
	// name, so resolve the unit's id against the org's identities and fall back
	// to the path name when it doesn't resolve (identity outside the fetched
	// set, or a legacy row with no aligned ids).
	const userDisplay = $derived.by(() => {
		const i = units.user?.id ? identityById.get(units.user.id) : null;
		return i ? fmt.format(i) : null;
	});
	// Same rule applied per unit of the chain, for the Agent column's hover:
	// `ada / henry / researcher`. Agents keep their names — `formatIdentity`
	// short-circuits on non-user kinds.
	const labelUnit = (id: string | null, name: string) => {
		const i = id ? identityById.get(id) : null;
		return i ? fmt.format(i).primary : name;
	};
	const chainTitle = $derived(
		formatIdentityPath(entry.identity_path, entry.identity_path_ids, labelUnit)
	);

	// The row records its actors' names as of write time; the SPIFFE path carries
	// their current ones. The table shows what was recorded — an operator who
	// searches for a name they can see has to find the row — and the live chain
	// stays one hover (or one expand) away. See D59.
	//
	// `names.actor` follows the leaf for an agent row and the user unit for a
	// human acting directly, so a renamed user is reported too; comparing
	// against the leaf alone would never fire for them.
	// The leaf actor's mark, resolved by id against the same identities map the
	// labels use. A leaf outside the fetched set (or a legacy row with no
	// aligned ids) simply has no icon, and the link renders alone as before.
	const leafIcon = $derived(units.leaf?.id ? identityById.get(units.leaf.id) : null);
	const names = $derived(recordedNames(entry, units));
	const renamedSince = $derived(names.actor.renamed);
	const leafLabel = $derived(names.actor.label);
	const leafTitle = $derived(
		renamedSince ? `now ${names.actor.live} — ${chainTitle}` : chainTitle
	);
	// The User column normally renders an *email* resolved live by id, and an
	// email does not move when a display name does — so it is only marked when
	// it has fallen back to rendering the path's name, which is the value that
	// actually changed.
	const userNameIsLive = $derived(!userDisplay && names.user.renamed);

	function relativeTime(iso: string): string {
		const then = new Date(iso).getTime();
		if (!Number.isFinite(then)) return iso || '—';
		const now = Date.now();
		const diff = Math.max(0, now - then);
		const s = Math.floor(diff / 1000);
		if (s < 60) return `${s}s ago`;
		const m = Math.floor(s / 60);
		if (m < 60) return `${m}m ago`;
		const h = Math.floor(m / 60);
		if (h < 24) return `${h}h ago`;
		return new Date(iso).toLocaleString();
	}

	function fullTime(iso: string): string {
		const d = new Date(iso);
		if (!Number.isFinite(d.getTime())) return iso || '';
		return `${d.toISOString()}\n${d.toLocaleString()}`;
	}

	interface DisclosedField {
		label: string;
		value: string | null;
		error: string | null;
		truncated: boolean;
	}

	// Legacy sentinel: before the disclosure runner learned to omit fields
	// whose filter yields zero values, an absent optional field (the canonical
	// `.foo // empty` idiom) was recorded with this exact error and shows up as
	// a useless "extract failed" row. The runner no longer emits it, but it's
	// frozen into older audit_log.detail rows — drop it at read time so history
	// renders cleanly. Genuine extraction errors carry a different message and
	// are still shown.
	const LEGACY_NO_VALUES_ERROR = 'filter produced no values';

	// Extract the labeled disclosure slice from `detail.disclosed` if present.
	// Runs for both approval.created (where the slice lives alongside summary)
	// and action.executed / action.streamed (where it's the main add-on).
	function disclosedFrom(detail: unknown): DisclosedField[] {
		if (!detail || typeof detail !== 'object') return [];
		const d = (detail as Record<string, unknown>).disclosed;
		if (!Array.isArray(d)) return [];
		return d
			.filter(
				(e): e is DisclosedField =>
					!!e && typeof e === 'object' && typeof (e as DisclosedField).label === 'string'
			)
			.filter((e) => e.error !== LEGACY_NO_VALUES_ERROR);
	}

	const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
	function detailUuid(detail: unknown, key: string): string | null {
		if (!detail || typeof detail !== 'object') return null;
		const v = (detail as Record<string, unknown>)[key];
		return typeof v === 'string' && UUID_RE.test(v) ? v : null;
	}
	function detailStr(detail: unknown, key: string): string | null {
		if (!detail || typeof detail !== 'object') return null;
		const v = (detail as Record<string, unknown>)[key];
		return typeof v === 'string' ? v : null;
	}
	function detailStrArr(detail: unknown, key: string): string[] {
		if (!detail || typeof detail !== 'object') return [];
		const v = (detail as Record<string, unknown>)[key];
		return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
	}

	// `approval.resolved` carries the resolver (approver) in `detail.resolved_by_*`,
	// enriched by the audit API. The row's own identity is the approval's
	// *subject* (approvee). When the approver is itself an agent, surface it
	// inline in the Agent column as "approvee (approver)"; a user resolver is
	// shown only in the expanded "Resolved by" row.
	const AGENT_KINDS = ['agent', 'sub_agent'];
	const resolvedById = $derived(detailUuid(entry.detail, 'resolved_by_identity_id'));
	const resolvedByName = $derived(detailStr(entry.detail, 'resolved_by_name'));
	const resolvedByPath = $derived(detailStr(entry.detail, 'resolved_by_path'));
	const resolvedByPathIds = $derived(detailStrArr(entry.detail, 'resolved_by_path_ids'));
	const approverAgentName = $derived(
		AGENT_KINDS.includes(detailStr(entry.detail, 'resolved_by_kind') ?? '')
			? (resolvedByName ?? resolvedById)
			: null
	);

	// Collect cross-event references that warrant their own clickable link in
	// the expanded pane. Each link goes to a destination the user can navigate
	// to without leaving the dashboard:
	//   - approvals open the dedicated approval page;
	//   - executions don't have a route of their own, so clicking pivots the
	//     audit log itself to the `uuid =` filter — surfacing every event tied
	//     to that execution in chronological order.
	function references(e: AuditEntry): { label: string; value: string; href: string }[] {
		const out: { label: string; value: string; href: string }[] = [];
		const replayed = detailUuid(e.detail, 'replayed_from_approval');
		if (replayed) {
			out.push({ label: 'Replayed from approval', value: replayed, href: `/approvals/${replayed}` });
		}
		const exec = detailUuid(e.detail, 'execution_id');
		if (exec) {
			out.push({ label: 'Execution', value: exec, href: `/audit?uuid=${exec}` });
		}
		return out;
	}

	function resourceHref(type: string | null, id: string | null): string | null {
		if (!type || !id) return null;
		if (type === 'approval') return `/approvals/${id}`;
		return null;
	}

	// Upstream-error presence for execution events (detail.is_error) —
	// drives the row pill and the expanded "Result" line.
	const hasUpstreamError = $derived(upstreamError(entry));
	const resultLabel = $derived(upstreamResultLabel(entry));

	// Captured upstream response (detail.response) + transport-failure
	// summary (detail.error) — present when the org's audit settings
	// enabled capture / the upstream never answered.
	const response = $derived(responseCapture(entry));
	const transportErr = $derived(transportError(entry));

	// Deferred-download rows describe a file, not a payload. There is no body
	// to preview (the bytes stream straight through), so the useful thing to
	// show is what left and how often the capability was redeemed — a
	// use_count well past 1 is the signal that a download URL leaked.
	const download = $derived(downloadSummary(entry));

	// Upload rows describe a file too, but the useful thing to show is
	// different: declared vs measured. The gateway verifies what was pushed
	// against what was approved, and a divergence between the two columns is
	// the entire signal — this row is the only place it survives.
	const upload = $derived(uploadSummary(entry));

	function uploadSummary(e: AuditEntry) {
		if (e.action !== 'action.uploaded') return null;
		const d = (e.detail ?? {}) as Record<string, unknown>;
		const str = (k: string) => (typeof d[k] === 'string' ? (d[k] as string) : null);
		const num = (k: string) => (typeof d[k] === 'number' ? (d[k] as number) : null);
		return {
			filename: str('declared_filename'),
			mime: str('declared_mime'),
			storedPath: str('stored_media_path'),
			declaredSize: num('declared_size_bytes'),
			measuredSize: num('measured_size_bytes'),
			declaredSha: str('declared_sha256'),
			measuredSha: str('measured_sha256'),
			error: str('error')
		};
	}

	function downloadSummary(e: AuditEntry) {
		if (e.action !== 'action.downloaded') return null;
		const d = (e.detail ?? {}) as Record<string, unknown>;
		return {
			filename: typeof d.filename === 'string' ? d.filename : null,
			mime: typeof d.mime === 'string' ? d.mime : null,
			size: typeof d.size_bytes === 'number' ? d.size_bytes : null,
			uses: typeof d.use_count === 'number' ? d.use_count : null
		};
	}


	// Pretty-print the captured body when it parses as JSON; truncated
	// captures usually don't, and fall back to the raw text.
	function prettyBody(body: string): string {
		try {
			return JSON.stringify(JSON.parse(body), null, 2);
		} catch {
			return body;
		}
	}
</script>

<tr
	class="row"
	class:expanded
	data-event-id={entry.id}
	onclick={ontoggle}
>
	<td class="ts" title={fullTime(entry.created_at)}>{relativeTime(entry.created_at)}</td>
	<td class="identity user">
		{#if units.user && isMe}
			<a
				class="me-pill"
				href={units.user.href}
				title={userDisplay?.title ?? units.user.name}
				onclick={(e) => e.stopPropagation()}
			>Me</a>
		{:else if units.user}
			<a
				class="identity-link"
				class:renamed={userNameIsLive}
				href={units.user.href}
				title={userNameIsLive ? `recorded as ${names.user.recorded}` : userDisplay?.title}
				onclick={(e) => e.stopPropagation()}
			>{userDisplay?.primary ?? units.user.name}</a>
		{:else if entry.owner_user_name}
			<!-- No live chain (deleted identity): the recorded name is all the
			     log has left, and it is exactly what it was written down for. -->
			<span class="mono" title="name recorded at the time">{entry.owner_user_name}</span>
		{:else}
			<span class="muted">—</span>
		{/if}
	</td>
	<td class="identity">
		{#if units.leaf}
			{#if leafIcon?.icon_url}
				<AgentAvatar
					name={leafLabel ?? units.leaf.name}
					iconUrl={leafIcon.icon_url}
					stripe={leafIcon.icon_stripe}
					clientLabel={leafIcon.mcp_client_label}
					size={16}
				/>
			{/if}
			<a
				class="identity-link"
				class:renamed={renamedSince}
				href={units.leaf.href}
				title={leafTitle}
				onclick={(e) => e.stopPropagation()}
			>{leafLabel}</a>
		{:else if !entry.identity_path && entry.identity_id && entry.identity_name}
			<!-- Chain unresolved: fall back to the bare leaf identity. -->
			<a
				class="identity-link"
				href={`/agents/${entry.identity_id}`}
				onclick={(e) => e.stopPropagation()}
			>{entry.identity_name}</a>
		{:else if !entry.identity_path && entry.identity_name}
			<span class="mono">{entry.identity_name}</span>
		{:else}
			<span class="muted">—</span>
		{/if}
		{#if approverAgentName}
			<span class="approver" title="resolved by agent {approverAgentName}">({approverAgentName})</span>
		{/if}
		{#if entry.impersonated_by_identity_id}
			<span class="via-imp" title="via impersonation by {entry.impersonated_by_name ?? entry.impersonated_by_identity_id}">imp</span>
		{/if}
	</td>
	<td>
		<code class="badge">{entry.action}</code>
		{#if hasUpstreamError}
			<span class="upstream-error" title={resultLabel}>error</span>
		{/if}
	</td>
	<td class="resource">
		{#if entry.resource_type}
			<span class="rtype">{entry.resource_type}</span>
			{#if entry.resource_id}
				<span class="rid mono">{entry.resource_id.slice(0, 8)}</span>
			{/if}
		{:else}
			<span class="muted">—</span>
		{/if}
	</td>
	<td class="desc">{entry.description ?? ''}</td>
	<td class="ip mono">{entry.ip_address ?? ''}</td>
</tr>
{#if expanded}
	<tr class="detail-row">
		<td colspan="7">
			<div class="detail">
				<dl>
					<dt>Event ID</dt>
					<dd class="mono">{entry.id}</dd>
					<dt>Timestamp</dt>
					<dd class="mono">{entry.created_at}</dd>
					{#if entry.tags.length}
						<dt>Tags</dt>
						<dd class="tags">
							{#each entry.tags as t (t)}
								<button
									type="button"
									class="tag-chip"
									title={`Filter by ${t}`}
									onclick={(e) => {
										e.stopPropagation();
										ontagclick?.(t);
									}}>{t}</button
								>
							{/each}
						</dd>
					{/if}
					{#if resultLabel}
						<dt>Result</dt>
						<dd class={hasUpstreamError ? 'result-err' : 'result-ok'}>{resultLabel}</dd>
					{/if}
					{#if transportErr}
						<dt>Error</dt>
						<dd class="result-err mono">{transportErr.kind}: {transportErr.message}</dd>
					{/if}
					{#if entry.identity_path}
						<dt>Identity</dt>
						<dd>
							<IdentityPath
								path={entry.identity_path}
								pathIds={entry.identity_path_ids}
							/>
						</dd>
					{:else if entry.identity_id}
						<dt>Identity</dt>
						<dd>
							<a
								class="identity-link"
								href={`/agents/${entry.identity_id}`}
								onclick={(e) => e.stopPropagation()}
							>{entry.identity_name ?? entry.identity_id}</a>
						</dd>
					{/if}
					{#if renamedSince}
						<dt>Recorded as</dt>
						<dd title="the name this identity had when the event was written">
							{names.actor.recorded}
						</dd>
					{/if}
					{#if names.actorIsAgent && names.user.renamed}
						<!-- Only for agent rows: on a row where the human acted
						     directly this is the same identity as the actor, and
						     the line above has already said it. -->
						<dt>Recorded user as</dt>
						<dd title="the name the owning user had when the event was written">
							{names.user.recorded}
						</dd>
					{/if}
					{#if entry.impersonated_by_path}
						<dt>Impersonated by</dt>
						<dd class="impersonation-badge">
							<IdentityPath
								path={entry.impersonated_by_path}
								pathIds={entry.impersonated_by_path_ids}
							/>
						</dd>
					{:else if entry.impersonated_by_identity_id}
						<dt>Impersonated by</dt>
						<dd class="mono impersonation-badge" title={entry.impersonated_by_identity_id}>
							{entry.impersonated_by_name ?? entry.impersonated_by_identity_id}
						</dd>
					{/if}
					{#if resolvedByPath}
						<dt>Resolved by</dt>
						<dd>
							<IdentityPath path={resolvedByPath} pathIds={resolvedByPathIds} />
						</dd>
					{:else if resolvedById}
						<dt>Resolved by</dt>
						<dd>
							<a
								class="identity-link"
								href={`/agents/${resolvedById}`}
								onclick={(e) => e.stopPropagation()}
							>{resolvedByName ?? resolvedById}</a>
						</dd>
					{/if}
					{#if entry.description}
						<dt>Description</dt>
						<dd>{entry.description}</dd>
					{/if}
					{#if entry.resource_type}
						<dt>Resource</dt>
						{#if entry.resource_id && resourceHref(entry.resource_type, entry.resource_id)}
							<dd class="mono">
								<span>{entry.resource_type} / </span>
								<a
									href={resourceHref(entry.resource_type, entry.resource_id)}
									onclick={(e) => e.stopPropagation()}
								>{entry.resource_id}</a>
							</dd>
						{:else}
							<dd class="mono">{entry.resource_type}{entry.resource_id ? ` / ${entry.resource_id}` : ''}</dd>
						{/if}
					{/if}
					{#if entry.ip_address}
						<dt>IP</dt>
						<dd class="mono">{entry.ip_address}</dd>
					{/if}
					{#each references(entry) as ref}
						<dt>{ref.label}</dt>
						<dd class="mono">
							<a href={ref.href} onclick={(e) => e.stopPropagation()}>{ref.value}</a>
						</dd>
					{/each}
				</dl>
				{#if disclosedFrom(entry.detail).length > 0}
					<dl class="disclosed">
						{#each disclosedFrom(entry.detail) as f}
							<dt>{f.label}</dt>
							{#if f.error}
								<dd class="err">extract failed: {f.error}</dd>
							{:else if f.value !== null && f.value !== undefined}
								<dd>{f.value}{#if f.truncated}<span class="trunc"> (truncated)</span>{/if}</dd>
							{:else}
								<dd class="muted">—</dd>
							{/if}
						{/each}
					</dl>
				{/if}
				{#if download}
					<dl class="disclosed">
						<dt>File</dt>
						<dd class="mono">{download.filename ?? '—'}</dd>
						{#if download.mime}
							<dt>Type</dt>
							<dd class="mono">{download.mime}</dd>
						{/if}
						{#if download.size !== null}
							<dt>Size</dt>
							<dd>{formatBytes(download.size)}</dd>
						{/if}
						{#if download.uses !== null}
							<dt>Redemptions</dt>
							<dd>{download.uses}</dd>
						{/if}
					</dl>
				{/if}
				{#if upload}
					<dl class="disclosed">
						<dt>File</dt>
						<dd class="mono">{upload.filename ?? '—'}</dd>
						{#if upload.mime}
							<dt>Type</dt>
							<dd class="mono">{upload.mime}</dd>
						{/if}
						{#if upload.measuredSize !== null || upload.declaredSize !== null}
							<dt>Size</dt>
							<dd>
								{upload.measuredSize !== null ? formatBytes(upload.measuredSize) : '—'}
								{#if upload.declaredSize !== null && upload.declaredSize !== upload.measuredSize}
									<span class="trunc"> (declared {formatBytes(upload.declaredSize)})</span>
								{/if}
							</dd>
						{/if}
						{#if upload.measuredSha || upload.declaredSha}
							<dt>SHA-256</dt>
							<dd class="mono">
								{upload.measuredSha ?? '—'}
								{#if upload.declaredSha && upload.declaredSha !== upload.measuredSha}
									<span class="trunc"> (declared {upload.declaredSha})</span>
								{/if}
							</dd>
						{/if}
						{#if upload.storedPath}
							<dt>Stored as</dt>
							<dd class="mono">{upload.storedPath}</dd>
						{/if}
						{#if upload.error}
							<dt>Refused</dt>
							<dd>{upload.error}</dd>
						{/if}
					</dl>
				{/if}
				{#if response && !download && !upload}
					<div class="json-block">
						<div class="json-label">
							response body
							{#if response.content_type}
								<span class="resp-meta mono">{response.content_type}</span>
							{/if}
							{#if response.truncated}
								<span class="resp-trunc">(truncated)</span>
							{/if}
						</div>
						{#if response.skipped === 'streamed'}
							<div class="muted resp-skipped">streamed — body not captured</div>
						{:else if response.body}
							<pre>{prettyBody(response.body)}</pre>
						{:else if typeof response.body === 'string'}
							<div class="muted resp-skipped">empty body</div>
						{/if}
					</div>
				{/if}
				<div class="json-block">
					<div class="json-label">detail</div>
					<pre>{JSON.stringify(entry.detail ?? {}, null, 2)}</pre>
				</div>
			</div>
		</td>
	</tr>
{/if}

<style>
	.row {
		cursor: pointer;
	}
	.row:hover {
		background: var(--color-bg-elevated);
	}
	.row.expanded {
		background: var(--color-bg-elevated);
	}
	td {
		padding: var(--space-3) var(--space-4);
		border-bottom: 1px solid var(--color-border);
		vertical-align: top;
	}
	.ts {
		white-space: nowrap;
		color: var(--color-text-muted);
		font-size: 0.85rem;
	}
	.badge {
		font-family: var(--font-mono, monospace);
		font-size: 0.8rem;
		padding: 2px 6px;
		border-radius: var(--radius-sm, 4px);
		background: var(--color-bg);
		border: 1px solid var(--color-border);
	}
	.resource .rtype {
		font-size: 0.85rem;
	}
	.resource .rid {
		color: var(--color-text-muted);
		font-size: 0.8rem;
		margin-left: 4px;
	}
	.desc {
		max-width: 360px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.muted {
		color: var(--color-text-muted);
	}
	/* Emails are longer than the display names this column used to hold, and
	   `member+tag@example.com` wraps mid-token when left alone. Clip to one
	   line — the `title` carries the full address. Only the User cell: the
	   Agent cell trails badges (approver, `imp`) that must stay visible. */
	.identity.user {
		max-width: 220px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	/* The mark is an inline-level column (tile over stripe) dropped into a cell
	   that is otherwise inline text and trailing badges. Centring it on the text
	   box keeps the row from growing a ragged baseline. */
	.identity :global(.agent-avatar) {
		vertical-align: middle;
		margin-right: 5px;
	}
	.identity-link {
		color: var(--color-text);
		text-decoration: none;
		font-family: var(--font-mono, monospace);
		font-size: 0.85rem;
		border-radius: 3px;
		padding: 0 0.1rem;
	}

	/* The identity has been renamed since this row was written. Marked, not
	   corrected: the recorded name is the one the log stands behind, and the
	   current one is in the hover title and the expanded pane. */
	.identity-link.renamed {
		text-decoration: underline dotted;
		text-underline-offset: 3px;
	}
	.identity-link:hover {
		color: var(--color-primary);
		text-decoration: underline;
	}
	.me-pill {
		display: inline-block;
		padding: 1px 8px;
		border-radius: 999px;
		background: color-mix(in srgb, var(--color-primary, #3b82f6) 14%, transparent);
		color: var(--color-primary, #3b82f6);
		font-size: 0.75rem;
		font-weight: 600;
		letter-spacing: 0.02em;
		text-decoration: none;
	}
	.me-pill:hover {
		background: color-mix(in srgb, var(--color-primary, #3b82f6) 24%, transparent);
	}
	.mono {
		font-family: var(--font-mono, monospace);
	}
	.detail-row td {
		background: var(--color-bg);
		padding: var(--space-4);
	}
	.detail {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	dl {
		display: grid;
		grid-template-columns: max-content 1fr;
		gap: 6px var(--space-4);
		margin: 0;
	}
	dt {
		color: var(--color-text-muted);
		font-size: var(--text-label, 0.75rem);
	}
	dd {
		margin: 0;
	}
	.tags {
		display: flex;
		flex-wrap: wrap;
		gap: 4px;
	}
	.tag-chip {
		font-family: var(--font-mono, monospace);
		font-size: var(--text-label, 0.75rem);
		padding: 1px 6px;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm, 4px);
		background: var(--color-bg-subtle, transparent);
		color: var(--color-text-muted);
		cursor: pointer;
	}
	.tag-chip:hover {
		border-color: var(--color-primary, #3b82f6);
		color: var(--color-text);
	}
	.json-block {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	.json-label {
		font-size: var(--text-label, 0.75rem);
		color: var(--color-text-muted);
	}
	pre {
		margin: 0;
		padding: var(--space-3);
		background: var(--color-bg-elevated);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm, 4px);
		overflow-x: auto;
		font-size: 0.8rem;
	}
	.disclosed {
		padding: var(--space-3);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm, 4px);
		background: rgba(46, 125, 50, 0.04);
		font-size: 0.85rem;
	}
	.disclosed dd {
		white-space: pre-wrap;
		word-break: break-word;
	}
	.disclosed .err {
		color: #d14343;
		font-style: italic;
	}
	.disclosed .trunc {
		color: var(--color-text-muted);
		font-size: 0.75rem;
	}
	.upstream-error {
		display: inline-block;
		margin-left: 6px;
		padding: 1px 5px;
		border-radius: var(--radius-sm, 4px);
		background: color-mix(in srgb, var(--color-danger, #d14343) 15%, transparent);
		color: var(--color-danger, #b91c1c);
		font-size: 0.7rem;
		font-weight: 600;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		vertical-align: middle;
		cursor: help;
	}
	.result-err {
		color: var(--color-danger, #b91c1c);
		font-weight: 600;
	}
	.resp-meta {
		margin-left: 6px;
		color: var(--color-text-muted);
		font-size: 0.7rem;
	}
	.resp-trunc {
		margin-left: 6px;
		color: var(--color-warning, #b45309);
		font-size: 0.7rem;
	}
	.resp-skipped {
		font-size: 0.85rem;
		font-style: italic;
	}
	.result-ok {
		color: var(--color-success, #15803d);
	}
	.via-imp {
		display: inline-block;
		margin-left: 6px;
		padding: 1px 5px;
		border-radius: var(--radius-sm, 4px);
		background: color-mix(in srgb, var(--color-warning, #f59e0b) 15%, transparent);
		color: var(--color-warning, #b45309);
		font-size: 0.7rem;
		font-weight: 600;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		vertical-align: middle;
		cursor: help;
	}
	.impersonation-badge {
		color: var(--color-warning, #b45309);
	}
	.approver {
		margin-left: 4px;
		color: var(--color-text-muted, #64748b);
		font-size: 0.85em;
		cursor: help;
	}
</style>

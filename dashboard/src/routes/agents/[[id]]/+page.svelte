<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import {
		listIdentities,
		listPermissions,
		listApprovals,
		createIdentity,
		updateIdentity,
		deleteIdentity,
		deletePermission,
		updatePermissionExpiry,
		type CreateIdentityRequest
	} from '$lib/identityApi';
	import type {
		Identity,
		McpConnection,
		PermissionRule
	} from '$lib/types';
	import { session, ApiError, type ApprovalResponse } from '$lib/session';
	import { makeIdentityFormatter, providerLabel } from '$lib/identityDisplay';
	import ConfirmModal from '$lib/components/ConfirmModal.svelte';
	import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
	import ApprovalRow from '$lib/components/approval/ApprovalRow.svelte';
	import ExpiryControl from '$lib/components/approval/ExpiryControl.svelte';
	import { collapse, motionDuration } from '$lib/utils/motion';
	import { flip } from 'svelte/animate';
	import { ttlRemaining } from '$lib/utils/time';

	// User identities are labelled by email, not by the IdP display name — see
	// `$lib/identityDisplay`. The org's allowed sign-in domains come from the
	// root layout load and decide whether the domain is stripped off.
	let { data }: { data: { allowedDomains: string[] } } = $props();
	const fmt = $derived(makeIdentityFormatter(data.allowedDomains));

	let identities = $state<Identity[]>([]);
	let approvals = $state<ApprovalResponse[]>([]);
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	let collapsed = $state(new Set<string>());
	let selectedId = $state<string | null>(null);

	// All per-agent UI state lives on a single object keyed by `agentId`.
	// It is replaced wholesale in `selectIdentity` so that any in-flight
	// async handler can compare `detail?.agentId === capturedId` to drop
	// stale results, and so a stuck error / loading flag from one agent
	// cannot bleed onto the next selection.
	interface AgentDetailState {
		agentId: string;
		rules: PermissionRule[];
		approvals: ApprovalResponse[];
		loading: boolean;
		error: string | null;
		mcp: McpConnection | null;
		mcpError: string | null;
		togglingElicitation: boolean;
		elicitationError: string | null;
		togglingSelfApprove: boolean;
		selfApproveError: string | null;
		togglingAutoCall: boolean;
		autoCallError: string | null;
		confirmDisconnect: boolean;
		disconnecting: boolean;
		disconnectError: string | null;
		deleteModalOpen: boolean;
		deleteModalBusy: boolean;
	}

	function freshDetail(agentId: string): AgentDetailState {
		return {
			agentId,
			rules: [],
			approvals: [],
			loading: false,
			error: null,
			mcp: null,
			mcpError: null,
			togglingElicitation: false,
			elicitationError: null,
			togglingSelfApprove: false,
			selfApproveError: null,
			togglingAutoCall: false,
			autoCallError: null,
			confirmDisconnect: false,
			disconnecting: false,
			disconnectError: null,
			deleteModalOpen: false,
			deleteModalBusy: false
		};
	}

	let detail = $state<AgentDetailState | null>(null);

	let createOpen = $state(false);
	let createParentId = $state<string | null>(null);
	let createInherit = $state(false);
	let kebabFor = $state<string | null>(null);
	let moveOpen = $state(false);
	// Opt-in reveal of archived identities in the tree (hidden by default).
	let showArchived = $state(false);

	const selected = $derived(identities.find((i) => i.id === selectedId) ?? null);
	// Tree is built from `visibleIdentities`, not the full set, so archived nodes
	// are hidden by default. `selected`/`scopedUser` stay on the full `identities`
	// array so the detail pane still resolves an archived selection. Hiding an
	// archived parent drops its whole branch from the render walk — safe because
	// cascade-archive marks the entire subtree, so no *live* node is orphaned.
	const visibleIdentities = $derived(
		showArchived ? identities : identities.filter((i) => !i.archived_at)
	);
	const childrenOf = $derived.by(() => {
		const m = new Map<string | null, Identity[]>();
		for (const ident of visibleIdentities) {
			const arr = m.get(ident.parent_id) ?? [];
			arr.push(ident);
			m.set(ident.parent_id, arr);
		}
		return m;
	});
	const roots = $derived(childrenOf.get(null) ?? []);
	// Unfiltered parent→children map over ALL identities (incl. archived). Used
	// for counts that must match the server's cascade delete, which ignores the
	// display-only "Show archived" filter — otherwise the delete dialog would
	// undercount and risk unexpected data loss.
	const allChildrenOf = $derived.by(() => {
		const m = new Map<string | null, Identity[]>();
		for (const ident of identities) {
			const arr = m.get(ident.parent_id) ?? [];
			arr.push(ident);
			m.set(ident.parent_id, arr);
		}
		return m;
	});
	const pendingByIdentity = $derived.by(() => {
		const m = new Map<string, number>();
		for (const a of approvals) m.set(a.identity_id, (m.get(a.identity_id) ?? 0) + 1);
		return m;
	});

	const meIdentityId = $derived(($page.data as { user?: { identity_id?: string } })?.user?.identity_id ?? null);

	const isAdmin = $derived(
		($page.data as { user?: { is_org_admin?: boolean } })?.user?.is_org_admin === true
	);
	// `?user=<id>` (admin-only) scopes the forest to one user's subtree. Set when
	// an admin drills in from the Users list. Ignored for non-admins or an
	// unknown id — the page then shows the full org forest as before.
	const userFilter = $derived($page.url.searchParams.get('user'));
	const scopedUser = $derived(
		userFilter && isAdmin
			? identities.find((i) => i.id === userFilter && i.kind === 'user') ?? null
			: null
	);
	// When scoped to one user, that user is the only root. Honor the archived
	// filter here too: an archived scoped user is hidden from the tree unless
	// "Show archived" is on (the banner still names them so the scope is clear).
	const displayRoots = $derived(
		scopedUser
			? showArchived || !scopedUser.archived_at
				? [scopedUser]
				: []
			: roots
	);

	function clearUserFilter() {
		const url = new URL($page.url);
		url.searchParams.delete('user');
		void goto(`${url.pathname}${url.search}`, { keepFocus: true, noScroll: true });
	}

	function kindLabel(kind: string): string {
		return kind === 'sub_agent' ? 'sub-agent' : kind;
	}

	/** Count all descendants of an identity */
	function descendantCount(id: string): number {
		// Count over ALL descendants (incl. archived) so the delete confirmation
		// matches the server's cascade, not the filtered tree.
		const kids = allChildrenOf.get(id) ?? [];
		let count = kids.length;
		for (const k of kids) count += descendantCount(k.id);
		return count;
	}

	async function loadAll() {
		loading = true;
		loadError = null;
		try {
			const [ids, apr] = await Promise.all([listIdentities(), listApprovals()]);
			identities = ids;
			approvals = apr;
			if (selectedId && !ids.find((i) => i.id === selectedId)) selectedId = null;
		} catch (e) {
			loadError = e instanceof Error ? e.message : String(e);
		} finally {
			loading = false;
		}
	}

	async function loadDetail(id: string) {
		// Refresh data on the live `detail` object. Bail if the user has
		// already switched away or if no detail is mounted yet — the
		// `selectIdentity` path is responsible for creating it.
		if (!detail || detail.agentId !== id) return;
		detail.loading = true;
		detail.error = null;
		// A successful refresh wipes any stale error from previous handlers
		// (failed setElicitation, failed disconnect) — otherwise an error
		// from a now-resolved condition would keep rendering on top of an
		// otherwise healthy card after a polling tick fixes things up.
		detail.mcpError = null;
		detail.elicitationError = null;
		detail.selfApproveError = null;
		detail.autoCallError = null;
		detail.disconnectError = null;
		try {
			const [rules, apr, mcpResp] = await Promise.all([
				listPermissions(id),
				listApprovals(id),
				session
					.get<{ connection: McpConnection | null }>(
						`/v1/identities/${encodeURIComponent(id)}/mcp-connection`
					)
					.then((r) => ({ ok: true as const, connection: r.connection }))
					.catch((e) => ({ ok: false as const, error: e }))
			]);
			if (detail?.agentId !== id) return;
			detail.rules = rules;
			detail.approvals = apr;
			if (mcpResp.ok) {
				detail.mcp = mcpResp.connection;
				detail.mcpError = null;
			} else if (
				mcpResp.error instanceof ApiError &&
				(mcpResp.error.status === 404 || mcpResp.error.status === 403)
			) {
				detail.mcp = null;
				detail.mcpError = null;
			} else {
				detail.mcp = null;
				detail.mcpError =
					mcpResp.error instanceof ApiError
						? `Error ${mcpResp.error.status}`
						: 'Network error';
			}
		} catch (e) {
			if (detail?.agentId !== id) return;
			detail.error = e instanceof Error ? e.message : String(e);
		} finally {
			if (detail?.agentId === id) detail.loading = false;
		}
	}

	async function setAutoCallOnApprove(next: boolean) {
		if (!detail) return;
		const targetId = detail.agentId;
		detail.togglingAutoCall = true;
		detail.autoCallError = null;
		try {
			// Hits the per-identity endpoint; works for any agent (REST,
			// MCP, white-label) regardless of whether an MCP client is
			// bound. Returns the refreshed identity row.
			const updated = await session.patch<Identity>(
				`/v1/identities/${encodeURIComponent(targetId)}/auto-call-on-approve`,
				{ enabled: next }
			);
			if (detail?.agentId === targetId) {
				identities = identities.map((i) => (i.id === targetId ? updated : i));
			}
		} catch (e) {
			if (detail?.agentId === targetId) {
				detail.autoCallError = e instanceof ApiError ? `Error ${e.status}` : 'Network error';
			}
		} finally {
			if (detail?.agentId === targetId) {
				detail.togglingAutoCall = false;
			}
		}
	}

	async function setElicitation(next: boolean) {
		if (!detail || !detail.mcp) return;
		const targetId = detail.agentId;
		detail.togglingElicitation = true;
		detail.elicitationError = null;
		try {
			const resp = await session.patch<{ connection: McpConnection | null }>(
				`/v1/identities/${encodeURIComponent(targetId)}/mcp-connection`,
				{ elicitation_enabled: next }
			);
			if (detail?.agentId === targetId) {
				if (resp.connection) {
					detail.mcp = resp.connection;
				} else {
					// The binding vanished between the GET that rendered the
					// switch and this PATCH (e.g. another tab disconnected the
					// client). Collapse the card and surface why via mcpError
					// — that path renders the dashed error box instead of the
					// blank "no connection" state, so the user knows the
					// toggle didn't silently no-op.
					detail.mcp = null;
					detail.mcpError = 'The MCP connection is no longer bound to this agent.';
				}
			}
		} catch (e) {
			if (detail?.agentId === targetId) {
				if (e instanceof ApiError && e.status === 404) {
					// 404 here means the binding was deleted (e.g. another tab
					// hit Disconnect) before our PATCH landed. This is the
					// same "vanished binding" case the success path handles
					// when `connection: null` comes back — surface it through
					// `mcpError` so the prominent error box renders, not a
					// small warning under the toggle. Drop any prior toggle
					// error so a later polling refresh that resurrects the
					// connection doesn't render the now-stale message.
					detail.mcp = null;
					detail.mcpError = 'The MCP connection is no longer bound to this agent.';
					detail.elicitationError = null;
				} else {
					detail.elicitationError =
						e instanceof ApiError ? `Error ${e.status}` : 'Network error';
				}
			}
		} finally {
			if (detail?.agentId === targetId) {
				detail.togglingElicitation = false;
			}
		}
	}

	async function setSelfApprove(next: boolean) {
		if (!detail || !detail.mcp) return;
		const targetId = detail.agentId;
		detail.togglingSelfApprove = true;
		detail.selfApproveError = null;
		try {
			const resp = await session.patch<{ connection: McpConnection | null }>(
				`/v1/identities/${encodeURIComponent(targetId)}/mcp-connection`,
				{ self_approve_enabled: next }
			);
			if (detail?.agentId === targetId) {
				if (resp.connection) {
					detail.mcp = resp.connection;
				} else {
					detail.mcp = null;
					detail.mcpError = 'The MCP connection is no longer bound to this agent.';
				}
			}
		} catch (e) {
			if (detail?.agentId === targetId) {
				if (e instanceof ApiError && e.status === 404) {
					detail.mcp = null;
					detail.mcpError = 'The MCP connection is no longer bound to this agent.';
					detail.selfApproveError = null;
				} else {
					detail.selfApproveError =
						e instanceof ApiError ? `Error ${e.status}` : 'Network error';
				}
			}
		} finally {
			if (detail?.agentId === targetId) {
				detail.togglingSelfApprove = false;
			}
		}
	}

	async function doDisconnect() {
		if (!detail) return;
		const targetId = detail.agentId;
		detail.disconnecting = true;
		detail.disconnectError = null;
		try {
			await session.post(
				`/v1/identities/${encodeURIComponent(targetId)}/mcp-connection/disconnect`,
				{}
			);
			if (detail?.agentId === targetId) {
				detail.mcp = null;
				detail.confirmDisconnect = false;
			}
		} catch (e) {
			// Surface failures in the modal instead of silently freezing it:
			// the user clicked Disconnect, got a stopped spinner, and would
			// otherwise have no idea whether the binding was removed.
			console.error('disconnect failed', e);
			if (detail?.agentId === targetId) {
				detail.disconnectError =
					e instanceof ApiError ? `Disconnect failed (${e.status}).` : 'Disconnect failed.';
			}
		} finally {
			if (detail?.agentId === targetId) {
				detail.disconnecting = false;
			}
		}
	}

	function fmtDate(iso: string | null | undefined): string {
		if (!iso) return '—';
		try {
			return new Date(iso).toLocaleString();
		} catch {
			return iso;
		}
	}

	const clientLabel = $derived.by(() => {
		const m = detail?.mcp;
		if (!m) return '';
		const info = m.client_info ?? {};
		const name = m.client_name ?? info.name ?? m.software_id ?? m.client_id;
		const version = info.version ?? m.software_version;
		return version ? `${name} · v${version}` : name;
	});

	function selectIdentity(id: string) {
		selectedId = id;
		// Replace the detail object wholesale so any in-flight handler from
		// the previous agent will see `detail.agentId !== capturedId` and
		// drop its result instead of clobbering the new selection.
		detail = freshDetail(id);
		void loadDetail(id);
		writeSelectionToUrl(id);
	}

	function writeSelectionToUrl(id: string | null) {
		// Mirror the current selection into the URL as `/agents/<id>` (or
		// `/agents` when nothing is selected). Preserve query/hash.
		const target = id ? `/agents/${id}` : '/agents';
		const search = $page.url.search;
		const hash = $page.url.hash;
		const next = `${target}${search}${hash}`;
		if (next === `${$page.url.pathname}${search}${hash}`) return;
		void goto(next, { replaceState: true, noScroll: true, keepFocus: true });
	}

	async function onApprovalResolved(updated: ApprovalResponse) {
		// Drop the resolved approval from both the agent-scoped and the global
		// lists so badge counts refresh immediately. Also refetch permissions
		// for the selected agent — an "Allow & Remember" resolution creates
		// new permission rules that should show up in the Rules table.
		approvals = approvals.filter((a) => a.id !== updated.id);
		if (detail) {
			const targetId = detail.agentId;
			detail.approvals = detail.approvals.filter((a) => a.id !== updated.id);
			try {
				const rules = await listPermissions(targetId);
				if (detail?.agentId === targetId) {
					detail.rules = rules;
				}
			} catch {
				// Non-fatal — the approval itself was already resolved.
			}
		}
	}

	// URL → selection sync. The route is `/agents/[[id]]` so `params.id` is
	// either a UUID or undefined. Drives the selection from the URL, both on
	// initial load (deep-link) and on browser back/forward. Selection → URL
	// is handled by `selectIdentity` via `writeSelectionToUrl`.
	const paramId = $derived($page.params.id ?? null);
	$effect(() => {
		const target = paramId;
		// Wait for the first identities load before validating — otherwise
		// we'd nuke a deep-link URL on the initial render before we know
		// whether the id resolves.
		if (loading && identities.length === 0) return;
		if (target === selectedId) return;

		if (target === null) {
			// URL has no id — clear any in-memory selection.
			selectedId = null;
			detail = null;
			return;
		}
		const found = identities.find((i) => i.id === target);
		if (found) {
			selectedId = target;
			detail = freshDetail(target);
			void loadDetail(target);
		} else {
			// Stale or invalid id. Drop selection and replace the URL with
			// `/agents` (preserving query/hash).
			selectedId = null;
			detail = null;
			void goto(`/agents${$page.url.search}${$page.url.hash}`, {
				replaceState: true,
				noScroll: true,
				keepFocus: true
			});
		}
	});

	function toggle(id: string) {
		const next = new Set(collapsed);
		if (next.has(id)) next.delete(id);
		else next.add(id);
		collapsed = next;
	}

	async function handleCreate(e: SubmitEvent) {
		e.preventDefault();
		const form = e.target as HTMLFormElement;
		const fd = new FormData(form);
		const parentId = String(fd.get('parent_id') ?? '');
		const parent = identities.find((i) => i.id === parentId);
		const kind: 'agent' | 'sub_agent' = parent?.kind === 'user' ? 'agent' : 'sub_agent';
		const req: CreateIdentityRequest = {
			name: String(fd.get('name') ?? '').trim(),
			kind
		};
		if (parentId) req.parent_id = parentId;
		req.inherit_permissions = createInherit;
		try {
			const created = await createIdentity(req);
			createOpen = false;
			await loadAll();
			selectIdentity(created.id);
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
		}
	}

	// Whether the current admin can remove a given user identity from the org.
	// Not yourself (leaving is a separate self-service flow), and admin-only.
	function canRemoveUser(node: Identity): boolean {
		return isAdmin && node.kind === 'user' && node.id !== meIdentityId;
	}

	function requestDelete() {
		if (!selected || !detail) return;
		// Agents/sub-agents are always deletable here; user identities are only
		// removable when the viewer is an admin and the target isn't themselves.
		if (selected.kind === 'user' && !canRemoveUser(selected)) return;
		detail.deleteModalOpen = true;
	}

	async function confirmDelete() {
		if (!selected || !detail) return;
		const targetId = detail.agentId;
		detail.deleteModalBusy = true;
		try {
			await deleteIdentity(selected.id);
			selectedId = null;
			detail = null;
			writeSelectionToUrl(null);
			await loadAll();
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
			if (detail?.agentId === targetId) {
				detail.deleteModalBusy = false;
				detail.deleteModalOpen = false;
			}
		}
	}

	async function handleToggleInherit(checked: boolean) {
		if (!selected) return;
		try {
			await updateIdentity(selected.id, { inherit_permissions: checked });
			await loadAll();
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
		}
	}

	async function handleRevokeRule(id: string) {
		try {
			await deletePermission(id);
			if (selected) await loadDetail(selected.id);
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
		}
	}

	// Reset a rule's expiry from the inline dropdown. 'forever' clears it; any
	// other option resets expiry to now + that duration. Refresh mirrors revoke.
	async function handleUpdateRuleExpiry(id: string, optionValue: string) {
		try {
			await updatePermissionExpiry(id, optionValue === 'forever' ? null : optionValue);
			if (selected) await loadDetail(selected.id);
		} catch (e) {
			alert(e instanceof Error ? e.message : String(e));
		}
	}

	function copy(text: string) {
		void navigator.clipboard.writeText(text);
	}

	// Eligible parents for the create form — any live identity can be a parent.
	// Archived identities are excluded: the server rejects creating a child under
	// an archived parent.
	const createEligibleParents = $derived(
		identities.filter((i) => ['user', 'agent', 'sub_agent'].includes(i.kind) && !i.archived_at)
	);

	// Parent identity for the selected node
	const parentIdentity = $derived(
		selected?.parent_id ? identities.find((i) => i.id === selected.parent_id) ?? null : null
	);

	onMount(() => {
		void loadAll();
		const interval = setInterval(() => {
			void loadAll();
			if (selectedId) void loadDetail(selectedId);
		}, 10000);
		return () => clearInterval(interval);
	});
</script>

<svelte:head>
	<title>Agents · Overslash</title>
</svelte:head>

<div class="page">
	<header class="page-header">
		<h1>Agents</h1>
	</header>

	{#if loadError}
		<div class="error-bar">{loadError}</div>
	{/if}

	{#if scopedUser}
		{@const owner = fmt.format(scopedUser)}
		<div class="filter-banner">
			<span
				>Viewing agents owned by <strong title={owner.title}>{owner.primary}</strong>{#if owner.secondary}
					· {owner.secondary}{/if}</span
			>
			<button type="button" onclick={clearUserFilter}>Clear</button>
		</div>
	{/if}

	<div class="panels" data-mobile-pane={selected ? 'detail' : 'tree'}>
		<!-- Left: Agent tree -->
		<aside class="tree-panel">
			<div class="tree-head">
				<span>Agents</span>
				<label class="archived-toggle">
					<ToggleSwitch
						checked={showArchived}
						onchange={(next) => (showArchived = next)}
						size="sm"
						label="Show archived"
					/>
					Show archived
				</label>
			</div>
			{#if loading && identities.length === 0}
				<p class="muted tree-empty">Loading…</p>
			{:else if displayRoots.length === 0}
				<p class="muted tree-empty">No agents found.</p>
			{:else}
				<div class="tree">
					{#each displayRoots as root (root.id)}
						{@render treeNode(root, 0)}
					{/each}
				</div>
			{/if}
			<button
				class="add-row"
				onclick={() => {
					createOpen = true;
					createParentId = selectedId ?? meIdentityId;
				}}
			>
				<span class="add-icon">+</span> Add agent…
			</button>
		</aside>

		<!-- Right: Detail panel -->
		<main class="detail-panel">
			{#if selected}
				{@const sel = fmt.format(selected)}
				<!-- Mobile: back-to-list affordance -->
				<button
					class="back-to-list"
					type="button"
					onclick={() => {
						selectedId = null;
						detail = null;
						writeSelectionToUrl(null);
					}}
				>
					‹ All agents
				</button>
				<!-- Header -->
				<div class="detail-header">
					<span class="status-dot active"></span>
					<h2 class="detail-name" title={sel.title}>
						{selected.kind === 'user' ? sel.primary : `agent:${selected.name}`}
					</h2>
					{#if selected.kind !== 'user'}
						<span class="pill pill-active">Active</span>
						<span class="pill pill-neutral">user-created</span>
					{/if}
				</div>

				{#if detail?.error}
					<div class="error-bar">{detail.error}</div>
				{/if}

				<!-- Permission Rules — shared by the agent branch and the user (Human)
				     branch. A Human's rules are their remembered approvals, the same
				     rows the profile page lists; `detail.rules` is populated for users
				     too, so the only thing needed to surface them here is rendering. -->
				{#snippet rulesSection()}
					<h3 class="section-title">Permission Rules</h3>
					{#if !detail || (detail.loading && detail.rules.length === 0)}
						<p class="muted" style="font-size:0.85rem;">Loading rules…</p>
					{:else if detail.rules.length === 0}
						<p class="muted" style="font-size:0.85rem;">No rules.</p>
					{:else}
						<table class="rules-table">
							<thead>
								<tr>
									<th>Rule</th>
									<th>Source</th>
									<th>Expires</th>
									<th></th>
								</tr>
							</thead>
							<tbody>
								{#each detail.rules as r (r.id)}
									<tr>
										<td>
											<!-- The sentence leads; the key stays visible underneath because it is
											     what an operator copies into a rule or greps the audit log for. -->
											{#if r.description}
												<div class="rule-desc">{r.description}</div>
												<div class="rule-key mono">{r.action_pattern}</div>
											{:else}
												<div class="rule-desc mono">{r.action_pattern}</div>
											{/if}
										</td>
										<td>
											<span class="pill pill-source">{r.effect === 'allow' ? 'Approval' : r.effect}</span>
										</td>
										<td>
											<ExpiryControl
												displayLabel={ttlRemaining(r.expires_at)}
												onselect={(v) => handleUpdateRuleExpiry(r.id, v)}
											/>
										</td>
										<td>
											<button class="revoke-link" onclick={() => handleRevokeRule(r.id)}>Revoke</button>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					{/if}
				{/snippet}

				{#if selected.kind === 'user'}
					<!-- User root: read-only identity fields, but its remembered rules
					     (permission grants) are shown and editable per backend auth.
					     The tree labels users by email, so this pane is where the IdP
					     display name, the full unstripped address, and the provider
					     live. -->
					<div class="field-row">
						<span class="field-label">Kind</span>
						<span class="field-value">user</span>
					</div>
					{#if selected.email}
						<div class="field-row">
							<span class="field-label">Email</span>
							<span class="field-value">{selected.email}</span>
						</div>
					{/if}
					{#if sel.secondary}
						<div class="field-row">
							<span class="field-label">Display name</span>
							<span class="field-value user-name">
								{#if selected.picture}
									<img class="user-avatar" src={selected.picture} alt="" referrerpolicy="no-referrer" />
								{/if}
								{sel.secondary}
							</span>
						</div>
					{/if}
					<div class="field-row">
						<span class="field-label">Identity provider</span>
						<span class="field-value">{providerLabel(selected.provider)}</span>
					</div>
					{#if selected.id === meIdentityId}
						<p class="muted" style="font-size:0.85rem;">This is the logged-in user. User identities are read-only.</p>
					{:else}
						<p class="muted" style="font-size:0.85rem;">User identity.</p>
					{/if}
					<div style="margin-top:0.5rem; display:flex; gap:0.5rem; flex-wrap:wrap;">
						<button
							class="btn-new"
							onclick={() => {
								createOpen = true;
								createParentId = selected!.id;
							}}
						>
							+ Add Agent
						</button>
						{#if canRemoveUser(selected)}
							<button class="btn-danger" onclick={requestDelete}>Remove from org</button>
						{/if}
					</div>

					{@render rulesSection()}
				{:else}
					<!-- Agent detail fields -->
					{@const parent = parentIdentity ? fmt.format(parentIdentity) : null}
					<div class="field-row">
						<span class="field-label">Parent</span>
						<span class="field-value" title={parent?.title}>{parent?.primary ?? '—'}{parentIdentity?.id === meIdentityId ? ' (you)' : ''}</span>
					</div>
					<div class="field-row">
						<span class="field-label">Inherits Permissions</span>
						<span class="field-value">
							<ToggleSwitch
								checked={selected.inherit_permissions}
								onchange={handleToggleInherit}
								label="Inherit permissions from parent"
							/>
						</span>
					</div>
					<div class="field-row">
						<span class="field-label" id="opt-auto-call-label">Auto-execute on approval</span>
						<span class="field-value field-value-stack">
							<ToggleSwitch
								checked={selected.auto_call_on_approve ?? true}
								disabled={detail?.togglingAutoCall ?? false}
								labelledby="opt-auto-call-label"
								onchange={(v) => setAutoCallOnApprove(v)}
							/>
							<span class="field-help">
								When on (default), approving a request immediately replays the call and the
								result lands on the execution record. When off, the request waits in
								"deferred execution" mode until something calls
								<code class="mono">POST /v1/approvals/&#123;id&#125;/call</code>.
							</span>
							{#if detail?.autoCallError}
								<span class="opt-warn">{detail.autoCallError}</span>
							{/if}
						</span>
					</div>

					<!-- Pending Approvals -->
					{#if detail && detail.approvals.length > 0}
						<h3 class="section-title">Pending Approvals</h3>
						<div class="approval-list">
							{#each detail.approvals as a (a.id)}
								<div
									animate:flip={{ duration: motionDuration(130) }}
									out:collapse={{ duration: 130 }}
								>
									<ApprovalRow approval={a} onResolved={onApprovalResolved} />
								</div>
							{/each}
						</div>
					{/if}

					{@render rulesSection()}

					<!-- MCP Connection -->
					<h3 class="section-title">MCP Connection</h3>
					{#if detail?.mcpError}
						<div class="mcp-empty mcp-error">
							<p>Could not load MCP connection: {detail.mcpError}</p>
						</div>
					{:else if !detail?.mcp}
						<div class="mcp-empty">
							<p>
								No MCP server bound to this identity. Run
								<code class="mono">overslash mcp login</code> from your editor or CLI to register an
								MCP client and bind it to this agent.
							</p>
						</div>
					{:else}
						<div class="mcp-card">
							<div class="mcp-head">
								<div class="mcp-main">
									<div class="mcp-title">
										<span class="mcp-glyph" aria-hidden="true">◫</span>
										<code class="mono">{detail.mcp.client_name ?? detail.mcp.client_id}</code>
										<span class="pill pill-active">connected</span>
									</div>
									<dl class="kv">
										<dt>Client</dt>
										<dd>{clientLabel}</dd>
										{#if detail.mcp.session_id}
											<dt>Session</dt>
											<dd><code class="mono">{detail.mcp.session_id}</code></dd>
										{/if}
										<dt>Connected</dt>
										<dd>{fmtDate(detail.mcp.connected_at)}</dd>
										<dt>Last seen</dt>
										<dd>{fmtDate(detail.mcp.last_seen_at)}</dd>
										{#if detail.mcp.protocol_version}
											<dt>Protocol</dt>
											<dd><code class="mono">{detail.mcp.protocol_version}</code></dd>
										{/if}
									</dl>
								</div>
								<button
									type="button"
									class="btn-delete"
									onclick={() => {
										if (detail) detail.confirmDisconnect = true;
									}}
								>
									Disconnect
								</button>
							</div>

							<div class="mcp-options-head">Connection Options</div>
							<div class="mcp-option">
								<div class="mcp-option-text">
									<div class="opt-title" id="opt-elicitation-label">Elicitation approvals</div>
									<div class="opt-desc">
										Elicitation allows approving in line but stops the approval from being async.
									</div>
									{#if !detail.mcp.elicitation_supported}
										<div class="opt-warn">
											This MCP client did not declare elicitation support at connect time.
										</div>
									{/if}
									{#if detail.elicitationError}
										<div class="opt-warn">{detail.elicitationError}</div>
									{/if}
								</div>
								<ToggleSwitch
									checked={detail.mcp.elicitation_enabled}
									disabled={!detail.mcp.elicitation_supported || detail.togglingElicitation}
									labelledby="opt-elicitation-label"
									onchange={(v) => setElicitation(v)}
								/>
							</div>
							<div class="mcp-option">
								<div class="mcp-option-text">
									<div class="opt-title" id="opt-self-approve-label">Allow self-approval</div>
									<div class="opt-desc">
										Lets the agent on this connection resolve its own approval
										requests. Surfaces the <code>overslash_approve_self</code>
										MCP tool and skips the human-approval check on agent-initiated
										actions. Only enable when a trusted human is at the keyboard
										reviewing each call. <a href="/docs/claude-code">See the
										recommended Claude Code rules</a>.
									</div>
									{#if detail.selfApproveError}
										<div class="opt-warn">{detail.selfApproveError}</div>
									{/if}
								</div>
								<ToggleSwitch
									checked={detail.mcp.self_approve_enabled}
									disabled={detail.togglingSelfApprove}
									labelledby="opt-self-approve-label"
									onchange={(v) => setSelfApprove(v)}
								/>
							</div>
						</div>
					{/if}

					<!-- Delete Agent -->
					<div class="detail-footer">
						<button class="btn-delete" onclick={requestDelete}>Delete Agent</button>
					</div>
				{/if}
			{:else}
				<p class="muted detail-empty">Select an agent to view details.</p>
			{/if}
		</main>
	</div>
</div>

{#snippet treeNode(node: Identity, depth: number)}
	{@const kids = childrenOf.get(node.id) ?? []}
	{@const isCollapsed = collapsed.has(node.id)}
	{@const pending = pendingByIdentity.get(node.id) ?? 0}
	{@const isSelected = selectedId === node.id}
	{@const label = fmt.format(node)}
	<div
		class="tree-node"
		class:selected={isSelected}
		class:archived={!!node.archived_at}
		style:padding-left={`${depth * 20 + 16}px`}
		role="treeitem"
		aria-selected={isSelected}
		tabindex={isSelected ? 0 : -1}
		onclick={() => selectIdentity(node.id)}
		onkeydown={(e) => {
			if (e.key === 'Enter' || e.key === ' ') {
				e.preventDefault();
				selectIdentity(node.id);
			}
		}}
	>
		<span class="tree-toggle-slot">
			{#if kids.length > 0}
				<button class="tree-toggle" onclick={(e) => { e.stopPropagation(); toggle(node.id); }}>
					{isCollapsed ? '▶' : '▼'}
				</button>
			{/if}
		</span>
		<span class="status-dot" class:active={node.kind !== 'user' || true}></span>
		<span class="tree-label" title={label.title}>{label.primary}</span>
		{#if node.id === meIdentityId}
			<span class="tree-you">(you)</span>
		{/if}
		{#if pending > 0}
			<span class="tree-badge">{pending}</span>
		{/if}
		<button
			class="node-action add-child"
			onclick={(e) => {
				e.stopPropagation();
				createOpen = true;
				createParentId = node.id;
			}}
			aria-label="Add child"
			title={node.kind === 'user' ? 'Add agent' : 'Add sub-agent'}>+</button
		>
		{#if node.kind !== 'user' || canRemoveUser(node)}
			<button
				class="node-action kebab"
				onclick={(e) => {
					e.stopPropagation();
					kebabFor = kebabFor === node.id ? null : node.id;
				}}
				aria-label="More">⋮</button
			>
			{#if kebabFor === node.id}
				<div class="menu" role="menu">
					{#if node.kind !== 'user'}
						<button onclick={() => { selectIdentity(node.id); moveOpen = true; kebabFor = null; }}>Move…</button>
					{/if}
					<button class="danger" onclick={() => { selectIdentity(node.id); kebabFor = null; requestDelete(); }}>
						{node.kind === 'user' ? 'Remove from org' : 'Delete'}
					</button>
				</div>
			{/if}
		{/if}
	</div>
	{#if !isCollapsed && kids.length > 0}
		{#each kids as child (child.id)}
			{@render treeNode(child, depth + 1)}
		{/each}
	{/if}
{/snippet}

{#if createOpen}
	<div class="modal-backdrop" onclick={() => (createOpen = false)} role="presentation">
		<div
			class="modal"
			role="dialog"
			tabindex={-1}
			onclick={(e) => e.stopPropagation()}
			onkeydown={(e) => {
				if (e.key === 'Escape') {
					e.stopPropagation();
					createOpen = false;
				}
			}}
		>
			<div class="modal-head">
				<h2>New Agent</h2>
				<button class="modal-close" onclick={() => (createOpen = false)}>✕</button>
			</div>
			<form onsubmit={handleCreate}>
				<label>
					Agent Name
					<input name="name" required placeholder="e.g. henry, research-bot" />
				</label>
				<label>
					Parent
					<select name="parent_id" required value={createParentId ?? ''}>
						<option value="" disabled>Choose a parent…</option>
						{#each createEligibleParents as p (p.id)}
							{@const d = fmt.format(p)}
							<option value={p.id} title={d.title}>{d.primary}{p.id === meIdentityId ? ' (you)' : ''}</option>
						{/each}
					</select>
				</label>
				<div class="check">
					<ToggleSwitch
						checked={createInherit}
						onchange={(v) => (createInherit = v)}
						labelledby="create-inherit-label"
					/>
					<span id="create-inherit-label">Inherits Permissions — inherit parent's current and future rules</span>
				</div>
				<div class="modal-actions">
					<button type="button" class="btn-secondary" onclick={() => (createOpen = false)}>Cancel</button>
					<button type="submit" class="btn-new">Create Agent</button>
				</div>
			</form>
		</div>
	</div>
{/if}

{#if selected && detail}
	{@const totalDescendants = descendantCount(selected.id)}
	{@const isUser = selected.kind === 'user'}
	<ConfirmModal
		open={detail.deleteModalOpen}
		title={isUser ? 'Remove user from org?' : 'Delete agent?'}
		message={isUser
			? `Remove ${selected.email ?? selected.name} from this org? This archives ${totalDescendants > 0 ? `their ${totalDescendants} agent${totalDescendants === 1 ? '' : 's'} and ` : ''}revokes all their API keys, and removes their access to the org.`
			: totalDescendants > 0
				? `Delete agent:${selected.name}? This will also delete ${totalDescendants} sub-agent${totalDescendants === 1 ? '' : 's'} and revoke all their API keys.`
				: `Delete agent:${selected.name}? This cannot be undone.`}
		confirmLabel={isUser ? 'Remove user' : 'Delete Agent'}
		destructive={true}
		busy={detail.deleteModalBusy}
		onConfirm={confirmDelete}
		onCancel={() => {
			if (detail) detail.deleteModalOpen = false;
		}}
	/>
{/if}

<ConfirmModal
	open={detail?.confirmDisconnect ?? false}
	title="Disconnect MCP client?"
	message="This removes the binding between this agent and its MCP client. The client will need to re-run the OAuth flow to reconnect."
	confirmLabel="Disconnect"
	destructive={true}
	busy={detail?.disconnecting ?? false}
	error={detail?.disconnectError ?? null}
	onConfirm={doDisconnect}
	onCancel={() => {
		if (detail) {
			detail.confirmDisconnect = false;
			detail.disconnectError = null;
		}
	}}
/>

<style>
	/* ── Page layout ── */
	.page {
		height: 100%;
		display: flex;
		flex-direction: column;
		overflow: hidden;
	}
	.page-header {
		display: none;
	}

	.filter-banner {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3, 0.75rem);
		padding: var(--space-2, 0.5rem) var(--space-3, 0.75rem);
		margin: 0 0 var(--space-3, 0.75rem);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md, 8px);
		background: color-mix(in srgb, var(--color-primary, #6366f1) 8%, transparent);
		font-size: 0.85rem;
	}
	.filter-banner button {
		padding: 4px 10px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		border-radius: var(--radius-sm, 4px);
		cursor: pointer;
	}

	.error-bar {
		background: var(--badge-bg-danger, rgba(229, 56, 54, 0.12));
		color: var(--color-danger, #e53836);
		padding: 0.5rem 1rem;
		font-size: 0.85rem;
		border-radius: 6px;
		margin: 0.5rem 1rem;
	}

	/* ── Two-panel layout (Figma: 320 / flex) ── */
	.panels {
		flex: 1;
		display: flex;
		min-height: 0;
		overflow: hidden;
	}
	.tree-panel {
		width: 320px;
		min-width: 260px;
		background: var(--color-surface);
		border-right: 1px solid var(--color-border);
		display: flex;
		flex-direction: column;
		overflow-y: auto;
	}
	.detail-panel {
		flex: 1;
		background: var(--color-surface);
		overflow-y: auto;
		padding: 24px;
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	@media (max-width: 1024px) {
		.tree-panel {
			width: 280px;
			min-width: 240px;
		}
		.detail-panel {
			padding: 20px;
		}
	}
	@media (max-width: 767px) {
		.panels {
			flex-direction: column;
		}
		.tree-panel {
			width: 100%;
			min-width: 0;
			border-right: none;
			border-bottom: 1px solid var(--color-border);
			max-height: none;
		}
		.detail-panel {
			padding: 16px;
		}
		/* Master/detail: only show one pane at a time, driven by whether
		   an agent is selected (mirrored to data-mobile-pane on the wrapper). */
		.panels[data-mobile-pane='tree'] .detail-panel {
			display: none;
		}
		.panels[data-mobile-pane='detail'] .tree-panel {
			display: none;
		}
	}

	/* Back-to-list button (mobile only) */
	.back-to-list {
		display: none;
		align-items: center;
		gap: 4px;
		background: transparent;
		border: 0;
		padding: 4px 6px 8px;
		margin: 0 0 4px -6px;
		font: var(--text-label);
		color: var(--color-text-secondary);
		cursor: pointer;
		border-radius: 6px;
	}
	.back-to-list:hover {
		color: var(--color-text);
	}
	@media (max-width: 767px) {
		.back-to-list {
			display: inline-flex;
		}
	}

	/* ── Agent tree ── */
	.tree-head {
		font: var(--text-body-medium);
		color: var(--color-text-heading);
		padding: 16px 16px 8px;
		font-weight: 600;
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.tree-empty {
		padding: 16px;
		font-size: 0.85rem;
	}
	.tree {
		flex: 1;
		overflow-y: auto;
	}
	.tree-node {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 5px 16px;
		cursor: pointer;
		border-radius: 4px;
		margin: 0 8px;
		border-bottom: 1px solid var(--color-border, #e8e8ee);
		position: relative;
	}
	.tree > .tree-node:last-child {
		border-bottom: none;
	}
	.tree-node:hover {
		background: var(--neutral-100);
	}
	.tree-node.selected {
		background: var(--primary-50);
	}
	.tree-node.selected .tree-label {
		color: var(--color-primary);
		font-weight: 600;
	}
	.tree-node.archived {
		opacity: 0.5;
	}
	.tree-node.archived .tree-label {
		text-decoration: line-through;
	}
	.archived-toggle {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		font: var(--text-body-small);
		font-weight: 400;
		color: var(--color-text-muted);
		cursor: pointer;
	}
	.tree-toggle-slot {
		width: 12px;
		flex-shrink: 0;
		display: inline-flex;
		align-items: center;
		justify-content: center;
	}
	.tree-toggle {
		background: none;
		border: none;
		cursor: pointer;
		font-size: 0.55rem;
		color: var(--color-text-muted);
		padding: 0;
	}
	.status-dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		background: var(--neutral-400);
		flex-shrink: 0;
	}
	.status-dot.active {
		background: var(--success-500, #21b86b);
	}
	.tree-label {
		font-size: 13px;
		color: var(--color-text);
	}
	.tree-you {
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.tree-badge {
		margin-left: auto;
		min-width: 18px;
		height: 18px;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		padding: 0 5px;
		border-radius: 999px;
		font-size: 10px;
		font-weight: 600;
		background: var(--color-danger, #e53836);
		color: #fff;
	}
	.node-action {
		background: none;
		border: none;
		cursor: pointer;
		padding: 0 0.4rem;
		color: var(--color-text-muted);
		opacity: 0;
		transition: opacity 0.1s;
	}
	.tree-node:hover .node-action,
	.node-action:focus-visible {
		opacity: 1;
	}
	.kebab {
		font-size: 1.1rem;
	}
	.add-child {
		font-size: 1.1rem;
		font-weight: 600;
	}
	.add-child:hover {
		color: var(--color-primary);
	}
	.menu {
		position: absolute;
		right: 8px;
		top: 100%;
		background: var(--color-surface, #fff);
		border: 1px solid var(--color-border);
		border-radius: 6px;
		box-shadow: var(--shadow-lg, 0 4px 12px rgba(0, 0, 0, 0.08));
		z-index: 10;
		min-width: 120px;
		display: flex;
		flex-direction: column;
	}
	.menu button {
		background: none;
		border: none;
		text-align: left;
		padding: 0.5rem 0.75rem;
		cursor: pointer;
		font-size: 0.85rem;
		color: var(--color-text);
	}
	.menu button:hover {
		background: var(--neutral-100);
	}
	.menu button.danger {
		color: var(--color-danger, #e53836);
	}
	.add-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		width: calc(100% - 16px);
		padding: 0.45rem 0.75rem;
		margin: 0.25rem 8px 0;
		background: none;
		border: 1px dashed var(--color-border, #e8e8ee);
		border-radius: 6px;
		cursor: pointer;
		font-size: 0.85rem;
		color: var(--color-text-muted);
		transition: background 0.1s, color 0.1s;
	}
	.add-row:hover {
		background: var(--neutral-50, #fafafa);
		color: var(--color-primary);
		border-color: var(--primary-300, #b0abef);
	}
	.add-icon {
		font-size: 1rem;
		font-weight: 600;
		line-height: 1;
	}

	/* ── Detail panel ── */
	.detail-empty {
		padding: 2rem;
		text-align: center;
		font-size: 0.9rem;
	}
	.detail-header {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 12px;
	}
	.detail-name {
		margin: 0;
		font-size: 18px;
		font-weight: 600;
		color: var(--color-text-heading);
	}

	/* ── Pills / badges ── */
	.pill {
		display: inline-block;
		padding: 2px 8px;
		border-radius: 9999px;
		font-size: 11px;
		font-weight: 500;
	}
	.pill-active {
		background: var(--badge-bg-success, rgba(33, 184, 107, 0.12));
		color: #15803d;
	}
	.pill-neutral {
		background: var(--badge-bg-muted, #f5f5f7);
		color: var(--color-text-secondary);
	}
	.pill-source {
		background: rgba(99, 90, 217, 0.12);
		color: var(--color-primary);
	}

	/* ── Field rows ── */
	.field-row {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 4px 0;
	}
	.field-label {
		width: 170px;
		flex-shrink: 0;
		font-size: 13px;
		font-weight: 500;
		color: var(--color-text-muted);
	}
	.field-value {
		font-size: 13px;
		color: var(--color-text);
	}
	.field-value-stack {
		display: flex;
		flex-direction: column;
		gap: 6px;
		flex: 1;
	}
	.user-name {
		display: inline-flex;
		align-items: center;
		gap: 6px;
	}
	.user-avatar {
		width: 20px;
		height: 20px;
		border-radius: 50%;
		flex: none;
	}
	.field-help {
		font-size: 12px;
		color: var(--color-text-muted);
		line-height: 1.4;
	}

	/* ── Section titles ── */
	.section-title {
		font-size: 14px;
		font-weight: 600;
		color: var(--color-text-heading);
		margin: 16px 0 8px;
	}

	/* ── Approval rows (same component as the /approvals queue) ── */
	.approval-list {
		display: flex;
		flex-direction: column;
		margin-bottom: 8px;
	}

	/* ── Permission rules table ── */
	.rules-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 12px;
	}
	.rules-table th {
		text-align: left;
		font-size: 11px;
		font-weight: 500;
		color: var(--color-text-muted);
		padding: 6px 0;
		border-bottom: 1px solid var(--color-border);
	}
	.rules-table td {
		padding: 6px 0;
		color: var(--color-text);
		vertical-align: middle;
	}
	.rules-table td:first-child {
		padding-right: 16px;
	}
	.rule-desc {
		color: var(--color-text);
	}
	.rule-key {
		margin-top: 2px;
		font-size: 11px;
		color: var(--color-text-muted);
		word-break: break-all;
	}
	.revoke-link {
		background: none;
		border: none;
		color: var(--color-danger, #e53836);
		font-size: 12px;
		font-weight: 500;
		cursor: pointer;
		padding: 0;
	}

	/* ── Delete Agent ── */
	.detail-footer {
		display: flex;
		justify-content: flex-end;
		margin-top: 24px;
		padding-top: 16px;
	}
	.btn-delete {
		background: var(--color-danger, #e53836);
		color: #fff;
		padding: 6px 12px;
		border-radius: 6px;
		border: none;
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
	}

	/* ── Buttons ── */
	.btn-new {
		background: var(--color-primary);
		color: #fff;
		padding: 6px 12px;
		border-radius: 6px;
		border: none;
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
	}
	.btn-secondary {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		color: var(--color-text);
		padding: 6px 12px;
		border-radius: 6px;
		font-size: 13px;
		cursor: pointer;
	}
	.btn-secondary:hover {
		background: var(--neutral-100);
	}
	.btn-danger {
		background: var(--color-surface);
		border: 1px solid var(--color-danger, #e53836);
		color: var(--color-danger, #e53836);
		padding: 6px 12px;
		border-radius: 6px;
		font-size: 13px;
		cursor: pointer;
	}
	.btn-danger:hover {
		background: var(--color-danger, #e53836);
		color: #fff;
	}

	/* ── Mono text ── */
	.mono {
		font-family: var(--font-mono);
		font-size: 12px;
	}
	.muted {
		color: var(--color-text-muted);
	}

	/* ── Modal (matches Figma New Agent modal) ── */
	.modal-backdrop {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.4);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 100;
	}
	.modal {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 16px;
		padding: 28px;
		min-width: 400px;
		max-width: 520px;
		width: 100%;
		box-shadow: var(--shadow-xl);
	}
	.modal-head {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 20px;
	}
	.modal-head h2 {
		margin: 0;
		font-size: 18px;
		font-weight: 700;
		color: var(--color-text-heading);
	}
	.modal-close {
		background: none;
		border: none;
		cursor: pointer;
		font-size: 18px;
		color: var(--color-text-muted);
		padding: 4px;
	}
	.modal form {
		display: flex;
		flex-direction: column;
		gap: 16px;
	}
	.modal label {
		display: flex;
		flex-direction: column;
		gap: 6px;
		font-size: 13px;
		font-weight: 500;
		color: var(--color-text);
	}
	.modal input,
	.modal select {
		padding: 10px 12px;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		font-size: 14px;
		background: var(--color-bg);
		color: var(--color-text);
	}
	.modal .check {
		display: flex;
		flex-direction: row;
		align-items: center;
		gap: 8px;
		font-weight: 400;
		font-size: 14px;
		color: var(--color-text-secondary);
	}
	.modal-actions {
		display: flex;
		gap: 8px;
		justify-content: flex-end;
		margin-top: 8px;
	}

	/* ── MCP Connection card ── */
	.mcp-empty {
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		padding: 16px;
		color: var(--color-text-muted);
		font-size: 13px;
	}
	.mcp-empty p {
		margin: 0;
	}
	.mcp-empty.mcp-error {
		border-color: var(--color-danger, #b91c1c);
		color: var(--color-danger, #b91c1c);
	}
	.mcp-empty code {
		background: var(--color-bg);
		padding: 0 4px;
		border-radius: 4px;
	}
	.mcp-card {
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 16px;
		display: flex;
		flex-direction: column;
		gap: 12px;
	}
	.mcp-head {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: 12px;
	}
	.mcp-main {
		display: flex;
		flex-direction: column;
		gap: 8px;
		min-width: 0;
	}
	.mcp-title {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: 13px;
	}
	.mcp-glyph {
		color: var(--color-text-muted);
	}
	.kv {
		display: grid;
		grid-template-columns: 110px 1fr;
		gap: 4px 12px;
		margin: 0;
		font-size: 12px;
	}
	.kv dt {
		color: var(--color-text-muted);
	}
	.kv dd {
		margin: 0;
		color: var(--color-text);
		word-break: break-all;
	}
	.mcp-options-head {
		text-transform: uppercase;
		font-size: 10px;
		letter-spacing: 0.04em;
		color: var(--color-text-muted);
		border-top: 1px solid var(--color-border);
		padding-top: 12px;
	}
	.mcp-option {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: 12px;
	}
	.mcp-option-text {
		display: flex;
		flex-direction: column;
		gap: 2px;
		min-width: 0;
	}
	.opt-title {
		font-size: 13px;
		font-weight: 500;
		color: var(--color-text);
	}
	.opt-desc {
		font-size: 12px;
		color: var(--color-text-muted);
	}
	.opt-warn {
		font-size: 11px;
		color: var(--color-danger, #b91c1c);
	}

</style>

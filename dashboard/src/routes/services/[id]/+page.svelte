<script lang="ts">
	import { onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { ApiError, apiErrorReason, session } from '$lib/session';
	import {
		getService,
		getServiceActions,
		getTemplate,
		listConnections,
		listServiceGroups,
		initiateOAuth,
		resyncMcpService,
		updateService,
		setServiceStatus,
		deleteService,
		upgradeConnectionScopes
	} from '$lib/api/services';
	import { groupsApi, type Group, type GroupGrantPick } from '$lib/api/groups';
	import GroupGrantPicker from '$lib/components/groups/GroupGrantPicker.svelte';
	import type {
		ActionSummary,
		ConnectionSummary,
		Identity,
		SecretSummary,
		SecretSlot,
		ServiceAuth,
		ServiceGroupRef,
		ServiceInstanceDetail,
		ServiceStatus,
		TemplateDetail
	} from '$lib/types';
	import { listSecrets } from '$lib/api/secrets';
	import StatusBadge from '$lib/components/services/StatusBadge.svelte';
	import ConfirmDialog from '$lib/components/services/ConfirmDialog.svelte';
	import SecretNamePicker from '$lib/components/SecretNamePicker.svelte';
	import ServiceCredentials from '$lib/components/ServiceCredentials.svelte';
	import ServiceInstanceConfig from '$lib/components/ServiceInstanceConfig.svelte';
	import { cleanServiceMap } from '$lib/service-maps';
	import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
	import AutoApproveSelect from '$lib/components/AutoApproveSelect.svelte';


	const id = $derived($page.params.id ?? '');
	const isAdmin = $derived(($page as any).data?.user?.is_org_admin === true);
	const currentUserId = $derived(($page as any).data?.user?.identity_id as string | undefined);

	let svc = $state<ServiceInstanceDetail | null>(null);
	let template = $state<TemplateDetail | null>(null);
	let actions = $state<ActionSummary[]>([]);
	let connections = $state<ConnectionSummary[]>([]);
	let identities = $state<Identity[]>([]);
	let serviceGroups = $state<ServiceGroupRef[]>([]);
	let allGroups = $state<Group[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);

	let editName = $state('');
	let editConnection = $state('');
	let editSecret = $state('');
	// Per-scheme secret bindings, keyed by the template's securityScheme keys
	// ("gateway", "mailbox"). Seeded from svc.credentials with the legacy
	// scalar secret_name mapped into its instance-source slot for display.
	let editCredentials = $state<Record<string, string>>({});
	let editConfig = $state<Record<string, string>>({});
	let editUrl = $state('');
	let editUseDefaultConnection = $state(true);
	let availableSecrets = $state<SecretSummary[]>([]);
	let secretsLoading = $state(false);
	let secretsLoaded = false;
	let saving = $state(false);
	let connecting = $state(false);
	let reconnectAbort: AbortController | null = null;
	let resyncing = $state(false);
	let resyncError = $state<string | null>(null);

	function isNeedsAuth(e: unknown): boolean {
		return (
			e instanceof ApiError &&
			e.status === 401 &&
			!!e.body &&
			typeof e.body === 'object' &&
			(e.body as { error?: unknown }).error === 'needs_authentication'
		);
	}

	async function doResync() {
		if (!svc) return;
		await resyncMcpService(svc.id);
		// Refresh actions + the instance itself to reflect the resync: actions
		// come from the instance id (not name/key) so user-shadows-org can't
		// surface a different instance's actions, and `svc.discovered_at`
		// drives the "last resync" line.
		actions = await getServiceActions(svc.id);
		svc = await getService(svc.id);
	}

	async function resyncMcpTools() {
		if (!svc) return;
		resyncing = true;
		resyncError = null;
		try {
			await doResync();
		} catch (e) {
			// OAuth instance with no/expired connection: drive the same connect
			// popup the reconnect button uses, then retry the resync once.
			if (isNeedsAuth(e) && oauthProvider) {
				await reconnect();
				if (error) {
					resyncError = error;
					error = null;
					return;
				}
				try {
					await doResync();
				} catch (e2) {
					resyncError = (e2 instanceof ApiError ? apiErrorReason(e2) : null) ?? String(e2);
				}
			} else {
				resyncError = (e instanceof ApiError ? apiErrorReason(e) : null) ?? String(e);
			}
		} finally {
			resyncing = false;
		}
	}
	let loadAbort: AbortController | null = null;
	let destroyed = false;
	let confirmDelete = $state(false);
	// When the service is bound to a connection, offer to preserve it. Default
	// off → the backend cleans up the connection if nothing else uses it.
	let keepConnection = $state(false);
	type Tab = 'overview' | 'credentials' | 'actions';
	const TABS: Tab[] = ['overview', 'credentials', 'actions'];

	// `?tab=` deep-link. The API's `needs_authentication` envelope hands agents a
	// `hint_url` pointing straight at the credentials form of the instance that
	// isn't configured, so the tab has to be addressable — landing on Overview
	// and making the user hunt for it would defeat the hint.
	function tabFromUrl(): Tab {
		const t = $page.url.searchParams.get('tab');
		return TABS.includes(t as Tab) ? (t as Tab) : 'overview';
	}

	let activeTab = $state<Tab>(tabFromUrl());

	function selectTab(t: Tab) {
		activeTab = t;
		// Keep the URL in step so the tab survives a reload and stays shareable.
		// replaceState: a tab switch isn't a navigation worth a back-button entry.
		const url = new URL($page.url);
		if (t === 'overview') url.searchParams.delete('tab');
		else url.searchParams.set('tab', t);
		goto(url, { replaceState: true, noScroll: true, keepFocus: true });
	}

	// Group-assignment form state
	let savingGroup = $state(false);

	const oauthAuth = $derived(
		(template?.auth ?? []).find((a: any) => a?.type === 'oauth') as any
	);
	const isMcp = $derived(template?.runtime === 'mcp');
	// MCP-runtime templates with `auth.kind: oauth` (D24) resolve through the
	// same provider connection as HTTP OAuth, so they reuse the whole connect
	// surface. `oauthProvider`/`oauthScopes` unify both sources.
	const mcpOAuthProvider = $derived(
		isMcp && template?.mcp?.auth_kind === 'oauth' ? template?.mcp?.provider : undefined
	);
	const oauthProvider = $derived<string | undefined>(oauthAuth?.provider ?? mcpOAuthProvider);
	// MCP-oauth scopes live on the mcp block; without them the connect flow would
	// request nothing and mint a token missing every permission.
	const oauthScopes = $derived<string[]>(oauthAuth?.scopes ?? template?.mcp?.scopes ?? []);
	const usesOAuth = $derived(!!oauthProvider);
	// Every credential slot the template declares — one picker each, bound
	// independently via `credentials[slot]`. A template may declare several
	// (email's org-wide `gateway` key plus the per-instance mailbox username
	// and password its header joins).
	const secretSlots = $derived((template?.secrets ?? []) as SecretSlot[]);
	const usesSecret = $derived(
		secretSlots.length > 0 || (template?.auth ?? []).some((a: any) => a?.type === 'secret')
	);
	// An API from before credential slots sends no `secrets` — fall back to the
	// legacy single scalar field in that case.
	const schemeKeyed = $derived(usesSecret && secretSlots.length > 0);
	const isSystem = $derived(!!svc?.is_system);
	// Non-secret per-instance values the template lets an org pin (e.g. the
	// mailbox gateway's IMAP/SMTP endpoint). System services are not editable.
	const hasInstanceConfig = $derived(
		!isSystem && (template?.instance_config_params ?? []).length > 0
	);
	// An org layer's default endpoint, shown as the placeholder so leaving the
	// field blank visibly means "inherit the org's deployment".
	const inheritedUrl = $derived(template?.instance_defaults?.url
	);
	// A template that names no host has nothing to fall back to, so blanking the
	// field breaks the instance. Mirrors the create form (D44) — reachable via
	// `servers: []` or a `${VAR?}` endpoint the deployment left unset.
	const editUrlRequired = $derived(
		(template?.hosts?.length ?? 0) === 0 && !inheritedUrl
	);
	const ownerDisplay = $derived.by(() => {
		const s = svc;
		if (!s) return '';
		const ownerId = s.owner_identity_id;
		if (!ownerId) return 'Org';
		if (currentUserId && ownerId === currentUserId) return 'You';
		const match = identities.find((i) => i.id === ownerId);
		return match?.name ?? 'user';
	});
	const assignedGroupIds = $derived(new Set(serviceGroups.map((g) => g.group_id)));
	// Filter out Myself groups for the "add a group" picker — Myself grants are
	// auto-managed and only ever target their owner's services. Surfacing them
	// in a generic picker would let an admin try to grant alice's service to
	// bob's Myself, which the API rejects with the self-group guard.
	const unassignedGroups = $derived(
		allGroups
			.filter((g) => !assignedGroupIds.has(g.id))
			.filter((g) => g.system_kind !== 'self')
	);
	// The owner's own Myself group, if it has a grant on this service. The
	// owner can manage this grant inline even when they aren't an org admin.
	function isOwnerOfGrant(g: ServiceGroupRef): boolean {
		const grp = allGroups.find((x) => x.id === g.group_id);
		return (
			!!grp &&
			grp.system_kind === 'self' &&
			!!currentUserId &&
			grp.owner_identity_id === currentUserId
		);
	}
	function canRemoveGrant(g: ServiceGroupRef): boolean {
		// Owner manages their own Myself grant; org admins manage everything
		// else (excluding system services where the table is read-only).
		if (isSystem) return false;
		if (isOwnerOfGrant(g)) return true;
		return isAdmin;
	}
	const ownerSelfGroup = $derived(
		currentUserId && svc?.owner_identity_id === currentUserId
			? allGroups.find(
					(g) => g.system_kind === 'self' && g.owner_identity_id === currentUserId
				)
			: undefined
	);
	const ownerSelfGrantMissing = $derived(
		!!ownerSelfGroup && !assignedGroupIds.has(ownerSelfGroup.id)
	);
	let restoringSelf = $state(false);
	let restoreAbort: AbortController | null = null;
	async function restoreSelfGrant() {
		if (!ownerSelfGroup || !svc) return;
		restoreAbort?.abort();
		const ctrl = new AbortController();
		restoreAbort = ctrl;
		restoringSelf = true;
		error = null;
		try {
			await groupsApi.addGrant(ownerSelfGroup.id, {
				service_instance_id: svc.id,
				access_level: 'admin',
				auto_approve_level: 'read'
			});
			const fresh = await listServiceGroups(svc.id, ctrl.signal);
			if (ctrl.signal.aborted || destroyed) return;
			serviceGroups = fresh;
		} catch (e) {
			if (ctrl.signal.aborted || destroyed) return;
			error = e instanceof ApiError ? e.message : String(e);
		} finally {
			if (restoreAbort === ctrl) restoreAbort = null;
			if (!ctrl.signal.aborted && !destroyed) restoringSelf = false;
		}
	}
	const matchingConnections = $derived(
		oauthProvider ? connections.filter((c) => c.provider_key === oauthProvider) : connections
	);
	const currentConnection = $derived.by(() => {
		const cid = svc?.connection_id;
		return cid ? (connections.find((c) => c.id === cid) ?? null) : null;
	});

	function connectionLabel(c: ConnectionSummary): string {
		if (c.account_email) return c.account_email;
		return `Unlabeled (${c.id.slice(0, 8)}…)`;
	}

	// The template's superset scopes — what it *might* want at full power.
	// If the connection's granted scopes don't cover this set, the dashboard
	// prompts for an incremental upgrade.
	const templateScopes = $derived<string[]>(oauthScopes);
	const missingScopes = $derived.by<string[]>(() => {
		if (!currentConnection || templateScopes.length === 0) return [];
		const granted = new Set(currentConnection.scopes);
		return templateScopes.filter((s: string) => !granted.has(s));
	});
	let upgrading = $state(false);
	let upgradeAbort: AbortController | null = null;

	// Build the editable per-slot map: one entry per credential slot, seeded
	// from svc.credentials. A legacy row (empty map, scalar secret_name set)
	// shows its scalar in the sole instance-source slot so nothing looks
	// unbound that isn't — and only when there IS a sole slot, since the
	// scalar never stood for one half of a composed credential.
	function seedCredentials(
		tpl: TemplateDetail | null,
		s: ServiceInstanceDetail
	): Record<string, string> {
		const slots = ((tpl?.secrets ?? []) as SecretSlot[]).filter((sl) => !!sl.key);
		const map: Record<string, string> = {};
		for (const sl of slots) map[sl.key] = s.credentials?.[sl.key] ?? '';
		const instanceSlots = slots.filter((sl) => (sl.source ?? 'instance') === 'instance');
		if (instanceSlots.length === 1 && !map[instanceSlots[0].key] && s.secret_name) {
			map[instanceSlots[0].key] = s.secret_name;
		}
		return map;
	}

	// Seed one entry per instance-pinnable param with the instance's stored
	// value, so the form shows what is actually pinned rather than a blank.
	function seedConfig(
		tpl: TemplateDetail | null,
		s: ServiceInstanceDetail
	): Record<string, string> {
		const map: Record<string, string> = {};
		for (const p of tpl?.instance_config_params ?? []) {
			map[p.name] = s.config?.[p.name] ?? '';
		}
		return map;
	}


	async function load() {
		// Cancel any in-flight load from a previous service navigation so
		// stale responses can't clobber the newly-loaded state.
		loadAbort?.abort();
		const ctrl = new AbortController();
		loadAbort = ctrl;
		// Reset per-service UI state when navigating between detail pages.
		reconnectAbort?.abort();
		reconnectAbort = null;
		connecting = false;
		// Not an unconditional 'overview': this also runs on first load, and a
		// `?tab=credentials` deep-link has to survive it.
		activeTab = tabFromUrl();
		loading = true;
		error = null;
		try {
			const fresh = await getService(id, ctrl.signal);
			if (ctrl.signal.aborted) return;
			svc = fresh;
			editName = fresh.name;
			editConnection = fresh.connection_id ?? '';
			editSecret = fresh.secret_name ?? '';
			editUrl = fresh.url ?? '';
			editUseDefaultConnection = fresh.use_default_connection;
			const [tpl, acts, conns, ids, sGroups, gs] = await Promise.all([
				getTemplate(fresh.template_key, ctrl.signal).catch(() => null),
				// Use svc.id (not name) so user-shadows-org can't return actions
				// from a same-named user instance.
				getServiceActions(fresh.id, ctrl.signal).catch(() => [] as ActionSummary[]),
				// Scope to the service owner so an admin viewing another user's
				// service sees that user's (bindable) connections, not their own.
				listConnections(
					{ ownerIdentityId: fresh.owner_identity_id },
					ctrl.signal
				).catch(() => [] as ConnectionSummary[]),
				session
					.get<Identity[]>('/v1/identities', ctrl.signal)
					.catch(() => [] as Identity[]),
				listServiceGroups(fresh.id, ctrl.signal).catch(() => [] as ServiceGroupRef[]),
				// Include Myself groups so the owner can see and manage their
				// auto-created `system_kind = 'self'` grant inline. The default
				// listing hides them — see groupsApi.list — so we use the
				// explicit variant here.
				groupsApi.listIncludingSelf(ctrl.signal).catch(() => [] as Group[])
			]);
			if (ctrl.signal.aborted) return;
			template = tpl;
			editCredentials = seedCredentials(tpl, fresh);
			editConfig = seedConfig(tpl, fresh);
			actions = acts;
			connections = conns;
			identities = ids;
			serviceGroups = sGroups;
			allGroups = gs;
		} catch (e) {
			if (ctrl.signal.aborted) return;
			error = e instanceof ApiError ? `Failed to load service (${e.status})` : 'Failed to load service';
		} finally {
			if (loadAbort === ctrl) loadAbort = null;
			if (!ctrl.signal.aborted) loading = false;
		}
	}

	async function save() {
		if (!svc) return;
		const trimmedName = editName.trim();
		if (!trimmedName) {
			error = 'Name cannot be empty.';
			return;
		}
		editName = trimmedName;
		saving = true;
		error = null;
		try {
			// Per-scheme bindings ride the `credentials` map (the server mirrors
			// the legacy scalar). The scalar `secret_name` is only sent on the
			// paths that still edit it directly — MCP bearer, or a secret
			// template from an API without scheme keys — never alongside the
			// map, so the two can't conflict.
			const sendCredentials = schemeKeyed && !usesOAuth && !isSystem;
			const updated = await updateService(svc.id, {
				name: trimmedName !== svc.name ? trimmedName : undefined,
				connection_id:
					editConnection !== (svc.connection_id ?? '')
						? editConnection || null
						: undefined,
				credentials: sendCredentials ? cleanServiceMap(editCredentials) : undefined,
				config: hasInstanceConfig ? cleanServiceMap(editConfig) : undefined,
				secret_name:
					!sendCredentials && editSecret !== (svc.secret_name ?? '')
						? editSecret || null
						: undefined,
				url:
					editUrl !== (svc.url ?? '') ? editUrl.trim() || null : undefined,
				use_default_connection:
					editUseDefaultConnection !== svc.use_default_connection
						? editUseDefaultConnection
						: undefined
			});
			svc = updated;
			editCredentials = seedCredentials(template, updated);
			editConfig = seedConfig(template, updated);
		} catch (e) {
			error = e instanceof ApiError ? `Save failed (${e.status})` : 'Save failed';
		} finally {
			saving = false;
		}
	}

	async function changeStatus(next: ServiceStatus) {
		if (!svc) return;
		try {
			svc = await setServiceStatus(svc.id, next);
		} catch (e) {
			error = e instanceof ApiError ? `Status change failed (${e.status})` : 'Status change failed';
		}
	}

	async function reconnect() {
		if (!oauthProvider) return;
		// Cancel any prior in-flight polling loop.
		reconnectAbort?.abort();
		const ctrl = new AbortController();
		reconnectAbort = ctrl;
		connecting = true;
		error = null;
		try {
			const beforeIds = new Set(connections.map((c) => c.id));
			const resp = await initiateOAuth(
				{ provider: oauthProvider, scopes: oauthScopes },
				ctrl.signal
			);
			if (ctrl.signal.aborted) return;
			const popup = window.open(resp.auth_url, 'oss_oauth', 'width=520,height=680');
			if (!popup) {
				error = 'Pop-up blocked. Allow pop-ups and try again.';
				return;
			}
			const deadline = Date.now() + 90_000;
			while (Date.now() < deadline) {
				if (ctrl.signal.aborted) {
					try {
						popup.close();
					} catch {
						/* ignore */
					}
					return;
				}
				await new Promise((r) => setTimeout(r, 1500));
				if (ctrl.signal.aborted) return;
				try {
					connections = await listConnections(
							{ ownerIdentityId: svc?.owner_identity_id },
							ctrl.signal
						);
				} catch {
					if (ctrl.signal.aborted) return;
				}
				const fresh = connections.find(
					(c) => !beforeIds.has(c.id) && c.provider_key === oauthProvider
				);
				if (fresh) {
					editConnection = fresh.id;
					try {
						popup.close();
					} catch {
						/* ignore */
					}
					return;
				}
				if (popup.closed) break;
			}
			if (!ctrl.signal.aborted) {
				error = 'OAuth did not complete in time.';
			}
		} catch (e) {
			if (ctrl.signal.aborted) return;
			error = e instanceof ApiError ? `OAuth failed (${e.status})` : 'OAuth failed';
		} finally {
			// Same pattern as services/new: clear connecting on the abort path
			// too, but only if we're still the active controller.
			if (reconnectAbort === ctrl) {
				reconnectAbort = null;
				connecting = false;
			}
		}
	}

	async function startScopeUpgrade() {
		if (!currentConnection || missingScopes.length === 0) return;
		// Snapshot the id once so the polling loop stays stable even if the
		// user navigates and `currentConnection` re-derives to null mid-flight.
		const connectionIdAtStart = currentConnection.id;
		upgradeAbort?.abort();
		const ctrl = new AbortController();
		upgradeAbort = ctrl;
		upgrading = true;
		error = null;
		try {
			const beforeScopes = new Set(currentConnection.scopes);
			const resp = await upgradeConnectionScopes(
				connectionIdAtStart,
				missingScopes,
				ctrl.signal
			);
			if (ctrl.signal.aborted) return;
			const popup = window.open(resp.auth_url, 'oss_oauth_upgrade', 'width=520,height=680');
			// `auth_url` is the Overslash-gated `/connect-authorize?id=…` page —
			// the popup hits that first, then the gate redirects to the
			// upstream provider after the session check.
			if (!popup) {
				error = 'Pop-up blocked. Allow pop-ups and try again.';
				return;
			}
			const deadline = Date.now() + 90_000;
			while (Date.now() < deadline) {
				if (ctrl.signal.aborted) {
					try { popup.close(); } catch { /* ignore */ }
					return;
				}
				await new Promise((r) => setTimeout(r, 1500));
				if (ctrl.signal.aborted) return;
				try {
					connections = await listConnections(
							{ ownerIdentityId: svc?.owner_identity_id },
							ctrl.signal
						);
				} catch {
					if (ctrl.signal.aborted) return;
				}
				const updated = connections.find((c) => c.id === connectionIdAtStart);
				if (updated && updated.scopes.some((s) => !beforeScopes.has(s))) {
					try { popup.close(); } catch { /* ignore */ }
					return;
				}
				if (popup.closed) break;
			}
			if (!ctrl.signal.aborted) {
				error = 'Scope upgrade did not complete in time.';
			}
		} catch (e) {
			if (ctrl.signal.aborted) return;
			error = e instanceof ApiError ? `Upgrade failed (${e.status})` : 'Upgrade failed';
		} finally {
			if (upgradeAbort === ctrl) {
				upgradeAbort = null;
				upgrading = false;
			}
		}
	}

	async function doDelete() {
		if (!svc) return;
		confirmDelete = false;
		try {
			await deleteService(svc.id, { keepConnection });
			await goto('/services');
		} catch (e) {
			if (e instanceof ApiError && e.status === 403) {
				error =
					apiErrorReason(e) ??
					'You do not have permission to delete this service — admin access required.';
			} else {
				error = e instanceof ApiError ? `Delete failed (${e.status})` : 'Delete failed';
			}
		}
	}

	async function addGroupGrant(pick: GroupGrantPick) {
		if (!svc) return;
		const ctrl = new AbortController();
		savingGroup = true;
		error = null;
		try {
			await groupsApi.addGrant(pick.group_id, {
				service_instance_id: svc.id,
				access_level: pick.access_level,
				auto_approve_level: pick.auto_approve_level
			});
			if (destroyed) return;
			const fresh = await listServiceGroups(svc.id, ctrl.signal);
			if (destroyed || ctrl.signal.aborted) return;
			serviceGroups = fresh;
		} catch (e) {
			if (destroyed || ctrl.signal.aborted) return;
			error = e instanceof ApiError ? `Failed to add group (${e.status})` : 'Failed to add group';
		} finally {
			savingGroup = false;
		}
	}

	async function removeGroupGrant(ref: ServiceGroupRef) {
		if (!svc) return;
		try {
			await groupsApi.removeGrant(ref.group_id, ref.grant_id);
			serviceGroups = serviceGroups.filter((g) => g.grant_id !== ref.grant_id);
		} catch (e) {
			error = e instanceof ApiError ? `Failed to remove group (${e.status})` : 'Failed to remove group';
		}
	}

	async function changeGrantAutoApproveLevel(ref: ServiceGroupRef, auto_approve_level: string) {
		if (auto_approve_level === ref.auto_approve_level) return;
		try {
			const fresh = await groupsApi.patchGrant(ref.group_id, ref.grant_id, { auto_approve_level });
			serviceGroups = serviceGroups.map((g) =>
				g.grant_id === ref.grant_id
					? { ...g, auto_approve_level: fresh.auto_approve_level }
					: g
			);
		} catch (e) {
			error = e instanceof ApiError ? `Failed to update grant (${e.status})` : 'Failed to update grant';
			// Force a re-render so any control whose DOM diverged from the
			// prop snaps back to the unchanged grant value.
			serviceGroups = [...serviceGroups];
		}
	}

	async function changeGrantAccessLevel(ref: ServiceGroupRef, access_level: string) {
		if (access_level === ref.access_level) return;
		try {
			const fresh = await groupsApi.patchGrant(ref.group_id, ref.grant_id, { access_level });
			// Lowering the ceiling clamps `auto_approve_level` server-side, so
			// fold both fields back — not just the one we asked to change.
			serviceGroups = serviceGroups.map((g) =>
				g.grant_id === ref.grant_id
					? {
							...g,
							access_level: fresh.access_level,
							auto_approve_level: fresh.auto_approve_level
						}
					: g
			);
		} catch (e) {
			error = e instanceof ApiError ? `Failed to update grant (${e.status})` : 'Failed to update grant';
			// `<select value={...}>` is one-way; without forcing a re-render
			// the dropdown would keep showing the rejected value the user
			// picked, even though the underlying grant didn't change.
			serviceGroups = [...serviceGroups];
		}
	}

	$effect(() => {
		// Re-run when the route param changes (client-side nav between services).
		if (id && !destroyed) {
			secretsLoaded = false;
			availableSecrets = [];
			void load();
		}
	});

	// Lazy-fetch secrets list once the loaded template indicates the secret-name
	// field will render. Soft-fails: on error the picker still works as
	// free-text entry.
	$effect(() => {
		if (secretsLoaded || !svc || isSystem) return;
		const fieldVisible =
			(usesSecret && !usesOAuth) ||
			(isMcp && template?.mcp?.auth_kind === 'bearer');
		if (!fieldVisible) return;
		secretsLoaded = true;
		secretsLoading = true;
		listSecrets()
			.then((s) => {
				availableSecrets = s;
			})
			.catch(() => {
				/* leave empty — picker still works as free-text input */
			})
			.finally(() => {
				secretsLoading = false;
			});
	});

	$effect(() => {
		// System services don't expose a credentials tab — snap back to overview
		// if state somehow landed on credentials (e.g. rapid nav between
		// instances, or a ?tab=credentials deep-link at a system service).
		// Assign directly rather than via selectTab: routing the URL rewrite
		// through here would make `$page` a dependency of an effect that also
		// writes the state it reads.
		if (isSystem && activeTab === 'credentials') {
			activeTab = 'overview';
		}
	});

	onDestroy(() => {
		destroyed = true;
		reconnectAbort?.abort();
		loadAbort?.abort();
	});
</script>

<svelte:head><title>{svc?.name ?? 'Service'} - Services - Overslash</title></svelte:head>

<div class="page">
	<a href="/services" class="back">← Back to services</a>

	{#if loading}
		<p class="muted">Loading…</p>
	{:else if !svc}
		<p class="muted">Service not found.</p>
	{:else}
		<header class="head">
			<div>
				<h1>{svc.name}</h1>
				<div class="sub">
					<span class="mono">{svc.template_key}</span>
					<StatusBadge variant={svc.template_source as 'global' | 'org' | 'user'} />
					<StatusBadge variant={svc.status} />
					{#if svc.credentials_status === 'needs_reconnect'}
						<StatusBadge variant="needs-reconnect" label="needs reconnection" />
					{:else if svc.credentials_status === 'partially_degraded'}
						<StatusBadge variant="partially-degraded" label="partial scopes" />
					{/if}
				</div>
			</div>
			<div class="head-actions">
				{#if isSystem}
					<StatusBadge variant="built-in" />
				{:else}
					<button
						type="button"
						class="btn"
						title="Open in API Explorer"
						onclick={() => goto(`/services?tab=api-explorer&service=${encodeURIComponent(svc?.id ?? '')}`)}
					>
						⌘ Try it
					</button>
					{#if svc.status !== 'archived'}
						<button type="button" class="btn" onclick={() => changeStatus('archived')}>Archive</button>
					{:else}
						<button type="button" class="btn" onclick={() => changeStatus('active')}>Restore</button>
					{/if}
					{#if svc.status === 'draft'}
						<button type="button" class="btn primary" onclick={() => changeStatus('active')}>
							Activate
						</button>
					{/if}
					<button
						type="button"
						class="btn danger"
						onclick={() => {
							keepConnection = false;
							confirmDelete = true;
						}}>Delete</button
					>
				{/if}
			</div>
		</header>

		{#if error}
			<div class="error">{error}</div>
		{/if}

		<nav class="tabs">
			{#each (isSystem ? TABS.filter((t) => t !== 'credentials') : TABS) as t}
				<button
					type="button"
					class="tab"
					class:active={activeTab === t}
					onclick={() => selectTab(t)}
				>
					{t}
				</button>
			{/each}
		</nav>

		{#if activeTab === 'overview'}
			<div class="card">
				<label class="field">
					<span class="label">Name</span>
					<input type="text" bind:value={editName} required minlength="1" disabled={isSystem} />
				</label>
				{#if isMcp && !isSystem}
					<label class="field">
						<span class="label">MCP server URL</span>
						<input
							type="text"
							bind:value={editUrl}
							placeholder={inheritedUrl ?? template?.mcp?.url ?? 'http://host:8081/mcp'}
						/>
						{#if inheritedUrl}
							<small>Leave blank to use your org's deployment ({inheritedUrl}).</small>
						{:else if template?.mcp?.url}
							<small>Leave blank to use the template's default.</small>
						{:else}
							<small>The URL of the MCP server endpoint.</small>
						{/if}
					</label>
				{:else if template?.configurable_url && !isSystem}
					<label class="field">
						<span class="label">Endpoint URL</span>
						<input
							type="text"
							bind:value={editUrl}
							placeholder={inheritedUrl ??
								(template?.hosts?.[0]
									? `https://${template.hosts[0]}`
									: 'https://service.your-org.com')}
						/>
						{#if editUrlRequired}
							<small>Required — this template has no default endpoint.</small>
						{:else if inheritedUrl}
							<small>Leave blank to use your org's deployment ({inheritedUrl}).</small>
						{:else}
							<small>Point this instance at your own deployment. Leave blank to use the default.</small>
						{/if}
					</label>
				{/if}
				{#if hasInstanceConfig}
					<ServiceInstanceConfig
						params={template?.instance_config_params ?? []}
						bind:config={editConfig}
						inherited={template?.instance_defaults?.config}
						idPrefix="edit-service-config"
					/>
				{/if}
				{#if usesSecret && !usesOAuth && !isSystem && schemeKeyed}
					<ServiceCredentials
						slots={secretSlots}
						bind:credentials={editCredentials}
						available={availableSecrets}
						loading={secretsLoading}
						idPrefix="edit-service-cred"
					/>
				{:else if (usesSecret && !usesOAuth && !isSystem) || (isMcp && template?.mcp?.auth_kind === 'bearer' && !isSystem)}
					<div class="field">
						<label class="label" for="edit-service-secret">{#if isMcp}Bearer token secret name{:else}Secret name{/if}</label>
						<SecretNamePicker
							id="edit-service-secret"
							bind:value={editSecret}
							available={availableSecrets}
							loading={secretsLoading}
						/>
					</div>
				{/if}
				<div class="row">
					<span class="label">Owner</span>
					<span title={svc.owner_identity_id ?? ''}>{ownerDisplay}</span>
				</div>
				<div class="row">
					<span class="label">Created</span>
					<span class="mono">{svc.created_at}</span>
				</div>
				<div class="row">
					<span class="label">Updated</span>
					<span class="mono">{svc.updated_at}</span>
				</div>
				{#if !isSystem}
					<div class="actions">
						<button type="button" class="btn primary" onclick={save} disabled={saving}>
							{saving ? 'Saving…' : 'Save changes'}
						</button>
					</div>
				{/if}
			</div>

			<div class="card">
				<div class="section-head">
					<h2>Groups</h2>
					<p class="muted small">Groups with a grant on this service. Members of these groups can reach its actions, subject to agent permissions.</p>
				</div>
				{#if serviceGroups.length === 0}
					<p class="muted">No groups have access to this service yet.</p>
				{:else}
					<table>
						<thead>
							<tr>
								<th>Group</th>
								<th>Access</th>
								<th>Auto-approve</th>
								{#if !isSystem}<th class="actions-col"></th>{/if}
							</tr>
						</thead>
						<tbody>
							{#each serviceGroups as g (g.grant_id)}
								<tr>
									<td>
										{#if isOwnerOfGrant(g)}
											<span title="Auto-managed grant for the service owner">Myself</span>
										{:else}
											<a class="link" href={`/org/groups/${g.group_id}`}>{g.group_name}</a>
										{/if}
									</td>
									<td>
										{#if canRemoveGrant(g)}
											<select
												class="access-select"
												value={g.access_level}
												onchange={(e) =>
													changeGrantAccessLevel(g, (e.currentTarget as HTMLSelectElement).value)}
												aria-label="Access level"
											>
												<option value="read">read</option>
												<option value="write">write</option>
												<option value="admin">admin</option>
											</select>
										{:else}
											<span class="mono">{g.access_level}</span>
										{/if}
									</td>
									<td>
										{#if canRemoveGrant(g)}
											<AutoApproveSelect
												value={g.auto_approve_level}
												accessLevel={g.access_level}
												onchange={(level) => changeGrantAutoApproveLevel(g, level)}
											/>
										{:else}
											{g.auto_approve_level}
										{/if}
									</td>
									{#if !isSystem}
										<td class="actions-col">
											{#if canRemoveGrant(g)}
												<button
													type="button"
													class="btn small danger"
													onclick={() => removeGroupGrant(g)}
												>
													Remove
												</button>
											{/if}
										</td>
									{/if}
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
				{#if ownerSelfGrantMissing}
					<div class="restore-self">
						<p class="muted small">
							You removed your Myself grant on this service. Restore it to use
							the service again — agents you own get auto-approved reads via
							the Myself group.
						</p>
						<button
							type="button"
							class="btn primary"
							onclick={restoreSelfGrant}
							disabled={restoringSelf}
						>
							{restoringSelf ? 'Restoring…' : 'Restore Myself grant'}
						</button>
					</div>
				{/if}
				{#if isAdmin && !isSystem}
					{#if unassignedGroups.length > 0}
						<GroupGrantPicker
							groups={allGroups}
							excludeIds={[...assignedGroupIds]}
							busy={savingGroup}
							onadd={addGroupGrant}
						/>
					{:else if allGroups.length === 0}
						<p class="muted small">No groups exist yet. Create one in <a href="/org/groups" class="link">Org → Groups</a>.</p>
					{:else}
						<p class="muted small">All groups already have access to this service.</p>
					{/if}
				{/if}
			</div>
		{:else if activeTab === 'credentials'}
			<div class="card">
				{#if usesOAuth}
					<div class="row">
						<span class="label">Provider</span>
						<span>{oauthProvider}</span>
					</div>
					<div class="row">
						<span class="label">Status</span>
						{#if currentConnection}
							<StatusBadge variant="connected" />
							<span class="muted">{connectionLabel(currentConnection)}</span>
						{:else}
							<StatusBadge variant="needs-setup" />
						{/if}
					</div>
					{#if currentConnection && currentConnection.scopes.length > 0}
						<div class="row scope-row">
							<span class="label">Scopes</span>
							<div class="scope-chips">
								{#each currentConnection.scopes as s}
									<span class="scope-chip">{s}</span>
								{/each}
							</div>
						</div>
					{/if}
					{#if currentConnection && missingScopes.length > 0}
						<div class="scope-warning">
							<div>
								<strong>Missing scopes.</strong> This connection doesn't cover
								everything the template declares:
								<ul>
									{#each missingScopes as s}
										<li class="mono small">{s}</li>
									{/each}
								</ul>
								Actions that need these scopes will fail until the connection
								is upgraded — the provider will skip the consent screen for
								scopes you've already granted.
							</div>
							<button
								type="button"
								class="btn"
								onclick={startScopeUpgrade}
								disabled={upgrading}
							>
								{upgrading ? 'Waiting…' : 'Request additional access'}
							</button>
						</div>
					{/if}
					<div class="field">
						<span class="label">Connection</span>
						<select bind:value={editConnection}>
							<option value="">— None —</option>
							{#each matchingConnections as c}
								<option value={c.id}>{connectionLabel(c)}</option>
							{/each}
						</select>
					</div>
					{#if !isSystem}
						<div class="field toggle-field">
							<ToggleSwitch
								checked={editUseDefaultConnection}
								onchange={(v) => (editUseDefaultConnection = v)}
								labelledby="edit-use-default-connection-label"
							/>
							<span id="edit-use-default-connection-label">
								Fall back to the default connection for this provider when none is pinned
							</span>
						</div>
						{#if !editUseDefaultConnection}
							<small class="hint">
								Off: calls fail with <code>needs_authentication</code> until a connection is
								explicitly bound. Used for white-label services with a dedicated connection.
							</small>
						{/if}
					{/if}
					<div class="actions">
						<button type="button" class="btn" onclick={reconnect} disabled={connecting}>
							{connecting ? 'Waiting…' : 'Connect new'}
						</button>
						<button type="button" class="btn primary" onclick={save} disabled={saving}>
							{saving ? 'Saving…' : 'Save'}
						</button>
					</div>
				{:else if usesSecret && schemeKeyed}
					<ServiceCredentials
						slots={secretSlots}
						bind:credentials={editCredentials}
						available={availableSecrets}
						loading={secretsLoading}
						idPrefix="cred-tab"
					/>
					<div class="actions">
						<button type="button" class="btn primary" onclick={save} disabled={saving}>
							{saving ? 'Saving…' : 'Save'}
						</button>
					</div>
				{:else if usesSecret || (isMcp && template?.mcp?.auth_kind === 'bearer')}
					<div class="field">
						<label class="label" for="edit-service-secret">{#if isMcp}Bearer token secret name{:else}Secret name{/if}</label>
						<SecretNamePicker
							id="edit-service-secret"
							bind:value={editSecret}
							available={availableSecrets}
							loading={secretsLoading}
						/>
					</div>
					<div class="actions">
						<button type="button" class="btn primary" onclick={save} disabled={saving}>
							{saving ? 'Saving…' : 'Save'}
						</button>
					</div>
				{:else}
					<p class="muted">This template doesn't require credentials.</p>
				{/if}
			</div>
		{:else}
			<div class="card">
				{#if template?.runtime === 'mcp'}
					<div class="mcp-header">
						<div class="mcp-meta">
							<span class="mono">MCP · {svc?.url ?? template.mcp?.url ?? ''}</span>
							<span class="muted">
								{#if template.mcp?.autodiscover === false}
									discovery disabled
								{:else if svc?.discovered_at}
									last resync: {svc.discovered_at}
								{:else}
									never resynced
								{/if}
							</span>
						</div>
						<!-- Resync runs against this instance (which carries the url/
						     secret or OAuth connection), so it works for global-template
						     instances and OAuth servers too — offer it whenever autodiscover
						     is on and an effective URL exists. -->
						{#if template.mcp?.autodiscover !== false && (svc?.url || template.mcp?.url)}
							<button
								type="button"
								class="btn"
								disabled={resyncing}
								onclick={resyncMcpTools}
							>
								{resyncing ? 'Resyncing…' : 'Resync tools'}
							</button>
						{/if}
					</div>
					{#if resyncError}
						<p class="error">{resyncError}</p>
					{/if}
				{/if}
				{#if actions.length === 0}
					<p class="muted">No actions defined.</p>
				{:else if template?.runtime === 'mcp'}
					<table>
						<thead>
							<tr>
								<th>Tool</th>
								<th>Description</th>
								<th>Risk</th>
								<th></th>
							</tr>
						</thead>
						<tbody>
							{#each actions as a}
								<tr class:disabled={a.disabled}>
									<td><span class="mono">{a.mcp_tool ?? a.key}</span></td>
									<!-- The one-line label; the full agent-facing description can run to
									     a paragraph, so it rides as the hover title instead of the cell. -->
									<td title={a.summary ? a.description : undefined}
										>{a.summary ?? a.description}</td
									>
									<td
										><span
											class="mono"
											title={a.risk === 'dynamic'
												? 'Classified per call: the SQL is parsed — read-only SELECTs run as read, anything else routes to approval'
												: undefined}>{a.risk}</span
										></td
									>
									<td>
										{#if a.disabled}<span class="pill pill-muted">hidden</span>{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{:else}
					<table>
						<thead>
							<tr>
								<th>Method</th>
								<th>Path</th>
								<th>Description</th>
								<th>Risk</th>
							</tr>
						</thead>
						<tbody>
							{#each actions as a}
								<tr>
									<td><span class="method">{a.method}</span></td>
									<td><span class="mono">{a.path}</span></td>
									<td title={a.summary ? a.description : undefined}
										>{a.summary ?? a.description}</td
									>
									<td
										><span
											class="mono"
											title={a.risk === 'dynamic'
												? 'Classified per call: the SQL is parsed — read-only SELECTs run as read, anything else routes to approval'
												: undefined}>{a.risk}</span
										></td
									>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			</div>
		{/if}
	{/if}
</div>

<ConfirmDialog
	open={confirmDelete}
	title="Delete service?"
	message={svc
		? `Delete ${svc.name}? Agents using this service will lose access. This cannot be undone.` +
			(svc.connection_id
				? ' Its OAuth connection is also removed if no other service uses it.'
				: '')
		: ''}
	confirmLabel="Delete"
	danger
	onconfirm={doDelete}
	oncancel={() => (confirmDelete = false)}
>
	{#if svc?.connection_id}
		<label class="keep-conn">
			<input type="checkbox" bind:checked={keepConnection} />
			<span>Keep the OAuth connection (don't remove even if unused)</span>
		</label>
	{/if}
</ConfirmDialog>

<style>
	.keep-conn {
		display: flex;
		align-items: flex-start;
		gap: 0.5rem;
		margin: -0.5rem 0 1.25rem;
		font-size: 0.85rem;
		color: var(--color-text-muted);
		cursor: pointer;
	}
	.keep-conn input {
		margin-top: 0.15rem;
	}
	.page {
		max-width: 1000px;
	}
	.back {
		display: inline-block;
		font-size: 0.85rem;
		color: var(--color-text-muted);
		text-decoration: none;
		margin-bottom: 0.5rem;
	}
	.head {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: 1rem;
		margin-bottom: 1rem;
	}
	h1 {
		font: var(--text-h1);
		margin: 0 0 0.35rem;
	}
	.sub {
		display: flex;
		gap: 0.5rem;
		align-items: center;
		flex-wrap: wrap;
	}
	.head-actions {
		display: flex;
		gap: 0.4rem;
	}
	.error {
		background: rgba(220, 38, 38, 0.08);
		border: 1px solid rgba(220, 38, 38, 0.3);
		color: #b91c1c;
		border-radius: 6px;
		padding: 0.6rem 0.9rem;
		margin-bottom: 1rem;
		font-size: 0.85rem;
	}
	.tabs {
		display: flex;
		gap: 0.25rem;
		border-bottom: 1px solid var(--color-border);
		margin-bottom: 1rem;
	}
	.tab {
		background: none;
		border: none;
		padding: 0.6rem 1rem;
		cursor: pointer;
		font: inherit;
		color: var(--color-text-muted);
		text-transform: capitalize;
		border-bottom: 2px solid transparent;
		font-size: 0.88rem;
	}
	.tab.active {
		color: var(--color-text);
		border-bottom-color: var(--color-primary, #6366f1);
	}
	.card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 1.5rem;
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}
	.field input[type='text'],
	.field select,
	.access-select {
		padding: 0.5rem 0.7rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: inherit;
		font: inherit;
		font-size: 0.9rem;
	}
	.label {
		font-size: 0.72rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.row {
		display: flex;
		gap: 0.6rem;
		align-items: center;
		font-size: 0.88rem;
	}
	.row .label {
		min-width: 80px;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.82rem;
	}
	.muted {
		color: var(--color-text-muted);
	}
	.mcp-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		padding: 0 0 0.75rem 0;
		border-bottom: 1px solid var(--color-border);
		margin-bottom: 0.75rem;
	}
	.mcp-meta {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
	}
	tr.disabled {
		opacity: 0.55;
	}
	.pill {
		display: inline-block;
		padding: 0.1rem 0.5rem;
		border-radius: 999px;
		font-size: 0.7rem;
		border: 1px solid transparent;
	}
	.pill-muted {
		background: rgba(120, 120, 120, 0.12);
		color: var(--color-text-muted);
		border-color: rgba(120, 120, 120, 0.25);
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
	}
	.btn {
		padding: 0.5rem 1rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: var(--color-text);
		cursor: pointer;
		font: inherit;
		font-size: 0.85rem;
	}
	.btn:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.btn.primary {
		background: var(--color-primary, #6366f1);
		color: white;
		border-color: var(--color-primary, #6366f1);
	}
	.btn.danger {
		color: #b91c1c;
		border-color: rgba(220, 38, 38, 0.35);
	}
	table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.85rem;
	}
	th,
	td {
		padding: 0.6rem 0.7rem;
		text-align: left;
		border-bottom: 1px solid var(--color-border);
	}
	th {
		font-size: 0.72rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--color-text-muted);
	}
	tbody tr:last-child td {
		border-bottom: none;
	}
	.method {
		display: inline-block;
		padding: 0.1rem 0.45rem;
		border-radius: 4px;
		background: var(--color-bg);
		border: 1px solid var(--color-border);
		font-family: var(--font-mono);
		font-size: 0.72rem;
	}
	p {
		margin: 0;
		font-size: 0.9rem;
	}
	.section-head h2 {
		margin: 0 0 0.25rem;
		font-size: 0.95rem;
	}
	.section-head .small {
		font-size: 0.8rem;
	}
	.small {
		font-size: 0.75rem;
	}
	.link {
		color: var(--color-primary, #6366f1);
		text-decoration: none;
	}
	.link:hover {
		text-decoration: underline;
	}
	.actions-col {
		text-align: right;
		white-space: nowrap;
	}
	.restore-self {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.75rem;
		padding-top: 0.5rem;
		margin-top: 0.5rem;
		border-top: 1px dashed var(--color-border);
	}
	.restore-self p {
		margin: 0;
		flex: 1 1 240px;
	}
	.scope-row {
		align-items: flex-start;
	}
	.scope-chips {
		display: flex;
		flex-wrap: wrap;
		gap: 0.3rem;
	}
	.scope-chip {
		background: var(--color-bg);
		border: 1px solid var(--color-border);
		border-radius: 999px;
		padding: 0.1rem 0.55rem;
		font-family: var(--font-mono);
		font-size: 0.72rem;
		color: var(--color-text-muted);
	}
	.scope-warning {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: 1rem;
		background: rgba(245, 158, 11, 0.08);
		border: 1px solid rgba(245, 158, 11, 0.3);
		border-radius: 8px;
		padding: 0.75rem 0.9rem;
		margin: 0.5rem 0;
		font-size: 0.85rem;
		color: #92400e;
	}
	.scope-warning ul {
		margin: 0.3rem 0;
		padding-left: 1.2rem;
	}
</style>

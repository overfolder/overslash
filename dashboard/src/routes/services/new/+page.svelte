<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { ApiError, type MeIdentity } from '$lib/session';
	import {
		listTemplates,
		getTemplate,
		listConnections,
		initiateOAuth,
		createService,
		createByocCredential,
		activateService,
		runActivate,
		updateService
	} from '$lib/api/services';
	import type {
		ConnectionSummary,
		OAuthProviderInfo,
		SecretSummary,
		SecretSlot,
		ServiceAuth,
		ServiceInstanceDetail,
		ServiceTestResponse,
		TemplateDetail,
		TemplateSummary,
		SecretNameConflictBody
	} from '$lib/types';
	import { listSecrets, putSecret } from '$lib/api/secrets';
	import { connectViaPopup, PopupBlockedError } from '$lib/oauth-connect';
	import ServiceIcon from '$lib/components/ServiceIcon.svelte';
	import TemplateCard from '$lib/components/services/TemplateCard.svelte';
	import StatusBadge from '$lib/components/services/StatusBadge.svelte';
	import TestResult from '$lib/components/services/TestResult.svelte';
	import ByocSection from '$lib/components/services/ByocSection.svelte';
	import SearchBar, {
		emptySearch,
		filterTerms,
		matchesAllText, type SearchKey, type SearchValue
	} from '$lib/components/SearchBar.svelte';
	import SecretNamePicker from '$lib/components/SecretNamePicker.svelte';
	import SecretValueField from '$lib/components/secrets/SecretValueField.svelte';
	import ServiceCredentials from '$lib/components/ServiceCredentials.svelte';
	import ServiceInstanceConfig from '$lib/components/ServiceInstanceConfig.svelte';
	import ConfirmDialog from '$lib/components/services/ConfirmDialog.svelte';
	import { cleanServiceMap } from '$lib/service-maps';
	import { probeRejected } from '$lib/public-request';
	import { credentialLabel, failureKind } from '$lib/setup-outcome';
	import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
	import GroupGrantPicker from '$lib/components/groups/GroupGrantPicker.svelte';
	import type { Group, GroupGrantPick } from '$lib/api/groups';


	let { data }: { data: { user: MeIdentity | null; providers: OAuthProviderInfo[]; providersLoaded: boolean; groups: Group[] } } = $props();

	let templates = $state<TemplateSummary[]>([]);
	let connections = $state<ConnectionSummary[]>([]);
	const providers = $derived(data.providers);
	const providersLoaded = $derived(data.providersLoaded);
	let loadingTemplates = $state(true);
	let error = $state<string | null>(null);

	// BYOC form state — reset whenever the selected template changes.
	let byocClientId = $state('');
	let byocClientSecret = $state('');

	let searchValue = $state<SearchValue>(emptySearch());

	let selectedKey = $state<string | null>(null);
	let selectedDetail = $state<TemplateDetail | null>(null);
	let loadingDetail = $state(false);

	// Step 2 form state
	let step = $state<'pick' | 'configure'>('pick');
	let nameInput = $state('');
	let connectionId = $state<string>('');
	let secretName = $state('');
	// Per-scheme secret bindings, keyed by the template's securityScheme keys.
	let credentialsInput = $state<Record<string, string>>({});
	let configInput = $state<Record<string, string>>({});
	let urlInput = $state('');
	let userLevel = $state(true);
	// Org-level instances have no Myself group to fall back on, so the API
	// requires at least one group grant — and one the creator belongs to.
	let groupGrants = $state<GroupGrantPick[]>([]);
	let useDefaultConnection = $state(true);
	let submitting = $state(false);
	let connectingOAuth = $state(false);
	let oauthAbort: AbortController | null = null;

	// Post-create verification. The instance exists but is *not* live: a
	// template with a probe is created `pending_setup`, and only a green
	// verdict promotes it. `created` doubles as the "we are past creation"
	// flag, and `created.status` is the answer to "is it usable yet" — never
	// the verdict, which is absent on a forced activation.
	let created = $state<ServiceInstanceDetail | null>(null);
	// The 409 body from a refused create, held while the confirm dialog is up.
	// Non-null is what opens the dialog, so clearing it is how the dialog closes.
	let secretConflict = $state<SecretNameConflictBody | null>(null);
	let testing = $state(false);
	let testResult = $state<ServiceTestResponse | null>(null);
	// The reopen panel: edit the credential value and the instance's own
	// fields, then check again. Inline rather than a rewind to `configure`,
	// because that form's submit *creates* — reusing it would mean forking
	// every branch of `submit()` on create-vs-update, including the OAuth
	// pre-flight, which must not run twice.
	let reopened = $state(false);
	let saving = $state(false);
	let promoting = $state(false);
	let confirmingForce = $state(false);
	// Credential *values*, keyed by slot. Separate from `credentialsInput`,
	// which holds vault *names* — the two are different questions and the
	// wizard has always been able to answer only the first.
	let credentialValues = $state<Record<string, string>>({});

	const live = $derived(created?.status === 'active');
	const kind = $derived(failureKind(testResult));

	let availableSecrets = $state<SecretSummary[]>([]);
	let secretsLoading = $state(false);
	let secretsLoaded = false;

	// MCP-derived helpers
	const isMcp = $derived(selectedDetail?.runtime === 'mcp');
	// An org layer's default endpoint counts as a default, same as at execution:
	// leaving the field blank inherits it, so the URL is not "required".
	const layerDefaults = $derived(selectedDetail?.instance_defaults);
	const inheritedUrl = $derived(layerDefaults?.url);
	const mcpNeedsUrl = $derived(isMcp && !selectedDetail?.mcp?.url && !inheritedUrl);
	const mcpNeedsSecret = $derived(
		isMcp &&
		selectedDetail?.mcp?.auth_kind === 'bearer' &&
		!selectedDetail?.mcp?.has_default_secret_name
	);

	// HTTP gateways (e.g. the `email` Mailbox Gateway) set their endpoint per
	// instance too — reveal the same URL field the MCP path uses.
	const httpNeedsUrl = $derived(!isMcp && selectedDetail?.configurable_url === true);

	// …and when the template names no host at all, the field is not an override
	// but the only endpoint this instance will ever have. Two ways to get here:
	// `servers: []`, or a `${VAR?}` endpoint the deployment left unset (D44 —
	// e.g. self-hosted Metabase). The server rejects a blank one, so say so
	// here rather than letting the form post and bounce.
	const httpUrlRequired = $derived(
		httpNeedsUrl && (selectedDetail?.hosts?.length ?? 0) === 0 && !inheritedUrl
	);

	// Non-secret values the org pins per instance (e.g. the mailbox gateway's
	// IMAP/SMTP endpoint). Declared by the template via
	// `x-overslash-instance-config`; empty for templates that declare none.
	const instanceConfigParams = $derived(selectedDetail?.instance_config_params ?? []);

	// Group-grant bookkeeping for the org-level path.
	const availableGroups = $derived(data.groups ?? []);
	const groupById = $derived(new Map(availableGroups.map((g) => [g.id, g])));
	const pickedGroupIds = $derived(groupGrants.map((g) => g.group_id));
	// The server rejects an org-level create whose groups the caller isn't in,
	// so say so here rather than posting and bouncing off a 400.
	const groupsSatisfied = $derived(
		userLevel ||
			(groupGrants.length > 0 &&
				groupGrants.some((g) => groupById.get(g.group_id)?.is_member !== false))
	);
	const groupHint = $derived.by(() => {
		if (userLevel) return null;
		if (groupGrants.length === 0)
			return 'An org-level service must be shared with at least one group you belong to — nothing can reach it otherwise.';
		if (!groupsSatisfied) return 'You must be a member of at least one of the selected groups.';
		return null;
	});

	function addGroupGrant(pick: GroupGrantPick) {
		groupGrants = [...groupGrants, pick];
	}
	function removeGroupGrant(groupId: string) {
		groupGrants = groupGrants.filter((g) => g.group_id !== groupId);
	}
	function groupName(groupId: string): string {
		return groupById.get(groupId)?.name ?? groupId;
	}

	const searchKeys = $derived<SearchKey[]>([
		{
			name: 'tier',
			operators: ['=', '!='],
			values: ['global', 'org', 'user'],
			hint: 'Template tier'
		},
		{
			name: 'category',
			operators: ['=', '~'],
			values: () =>
				Promise.resolve([
					...new Set(templates.map((t) => t.category ?? '').filter((c) => c))
				]),
			hint: 'Template category'
		}
	]);

	function templateMatches(t: TemplateSummary, expr: { key: string; op: string; value: string }): boolean {
		const v = expr.value.toLowerCase();
		let field = '';
		switch (expr.key) {
			case 'tier': field = t.tier; break;
			case 'category': field = (t.category ?? '').toString(); break;
			default: return true;
		}
		field = field.toLowerCase();
		switch (expr.op) {
			case '=': return field === v;
			case '!=': return field !== v;
			case '~': return field.includes(v);
		}
		return true;
	}

	const filteredTemplates = $derived(
		templates.filter((t) => {
			for (const expr of filterTerms(searchValue)) {
				if (!templateMatches(t, expr)) return false;
			}
			return matchesAllText([t.key, t.display_name, t.description ?? ''], searchValue);
		})
	);

	// Auth modes available on the selected template (oauth or secret)
	const authModes = $derived(
		(selectedDetail?.auth ?? []).map((a: any) => a?.type as string).filter(Boolean)
	);
	const usesSecret = $derived(authModes.includes('secret'));
	// Every credential slot the template declares — one picker each, bound via
	// `credentials[slot]` (e.g. email's `gateway` plus its mailbox username
	// and password).
	const secretSlots = $derived((selectedDetail?.secrets ?? []) as SecretSlot[]);
	// An API from before credential slots sends no `secrets` — fall back to the
	// legacy single scalar field in that case.
	const schemeKeyed = $derived(usesSecret && secretSlots.length > 0);
	// An HTTP `oauth` scheme, or an MCP-runtime `auth.kind: oauth` provider
	// (D24) normalized to the same {provider, scopes} shape so the connect
	// surface below is shared. MCP OAuth declares no template-level scopes.
	const oauthProvider = $derived.by(() => {
		const httpOauth = (selectedDetail?.auth ?? []).find((a: any) => a?.type === 'oauth') as any;
		if (httpOauth) return httpOauth;
		if (isMcp && selectedDetail?.mcp?.auth_kind === 'oauth' && selectedDetail?.mcp?.provider) {
			return {
				type: 'oauth',
				provider: selectedDetail.mcp.provider,
				scopes: (selectedDetail.mcp.scopes ?? []) as string[]
			};
		}
		return undefined;
	});
	const usesOAuth = $derived(!!oauthProvider);
	const matchingConnections = $derived(
		oauthProvider
			? connections.filter((c) => c.provider_key === oauthProvider.provider)
			: connections
	);
	// Dashboard-side reuse heuristic: prefer a connection that is (1) not
	// already bound to a service from this template, (2) already carries the
	// scopes the template wants, (3) most recently created. When everything's
	// already bound we still offer the most recent one — the user can always
	// flip to "Connect new" if they want a fresh account.
	function rankConnection(c: ConnectionSummary, tplKey: string, wantedScopes: string[]): number {
		const alreadyUsed = c.used_by_service_templates.includes(tplKey) ? 0 : 1;
		const granted = new Set(c.scopes);
		const covered = wantedScopes.every((s) => granted.has(s)) ? 1 : 0;
		return alreadyUsed * 10 + covered * 5;
	}
	const preferredConnection = $derived.by<ConnectionSummary | null>(() => {
		if (!oauthProvider || !selectedDetail) return null;
		const tplKey = selectedDetail.key;
		const wanted: string[] = oauthProvider.scopes ?? [];
		const ranked = [...matchingConnections].sort((a, b) => {
			const rb = rankConnection(b, tplKey, wanted);
			const ra = rankConnection(a, tplKey, wanted);
			if (rb !== ra) return rb - ra;
			// tiebreak: most recently created first
			return b.created_at.localeCompare(a.created_at);
		});
		return ranked[0] ?? null;
	});
	type ConnectionChoice = 'existing' | 'new';
	let connectionChoice = $state<ConnectionChoice>('new');
	// One-shot guard: the default-selection effect below should pick an initial
	// choice once per configure-step entry, never reactively override the user's
	// manual radio selection (setting connectionId would otherwise re-trigger it).
	let connectionDefaultsApplied = $state(false);
	function connectionLabel(c: ConnectionSummary): string {
		if (c.account_email) return c.account_email;
		return `Unlabeled (${c.id.slice(0, 8)}…)`;
	}
	function connectionUsageHint(c: ConnectionSummary, tplKey: string): string {
		// Flag only when another active service from *this same template* already
		// uses this connection — that's the case where reusing it would create
		// a duplicate. Cross-template reuse (Drive + Calendar on the same Google
		// connection) is the whole point of this feature, so stay quiet there.
		return c.used_by_service_templates.includes(tplKey) ? '(already connected)' : '';
	}
	// Lazy-fetch the secrets list the first time the secret-name field would
	// render. Soft-fails: on error the picker still works as free-text entry.
	$effect(() => {
		if (step !== 'configure') return;
		if (secretsLoaded) return;
		if (!((usesSecret && !usesOAuth) || mcpNeedsSecret)) return;
		secretsLoaded = true;
		secretsLoading = true;
		listSecrets()
			.then((s) => {
				availableSecrets = s;
			})
			.catch(() => {
				/* leave list empty — picker still works as free-text input */
			})
			.finally(() => {
				secretsLoading = false;
			});
	});

	// When we enter the configure step with matching connections available,
	// default to the existing-connection path and pre-select the best match.
	$effect(() => {
		if (step !== 'configure' || !oauthProvider) return;
		if (connectionDefaultsApplied) return;
		connectionDefaultsApplied = true;
		if (matchingConnections.length > 0) {
			connectionChoice = 'existing';
			if (preferredConnection) {
				connectionId = preferredConnection.id;
			}
		} else {
			connectionChoice = 'new';
		}
	});
	const providerInfo = $derived(
		oauthProvider ? providers.find((p) => p.key === oauthProvider.provider) ?? null : null
	);
	/**
	 * The scope set the OAuth flow will actually request: the template's
	 * service-specific scopes plus the provider's identity scopes (always
	 * merged on the backend so the callback can resolve account_email).
	 * Surfaced here so the user sees the full request before clicking Connect.
	 */
	const effectiveOAuthScopes = $derived(
		Array.from(
			new Set<string>([
				...((oauthProvider?.scopes ?? []) as string[]),
				...(providerInfo?.default_identity_scopes ?? [])
			])
		)
	);
	const hasFallback = $derived(
		providerInfo
			? providerInfo.has_org_credential
				|| providerInfo.has_system_credential
				|| providerInfo.has_user_byoc_credential
			: false
	);
	// When we've confirmed (via a successful provider fetch) that no org/system
	// creds AND no prior user BYOC exist, the user MUST provide their own. If
	// the provider catalog failed to load, we DON'T force BYOC — the backend
	// cascade will resolve credentials at connect time (Sentry review feedback).
	const byocRequired = $derived(!!oauthProvider && providersLoaded && !hasFallback);

	async function loadTemplates() {
		loadingTemplates = true;
		try {
			const [t, c] = await Promise.all([listTemplates(), listConnections()]);
			templates = t;
			connections = c;
		} catch (e) {
			error = e instanceof ApiError ? `Failed to load templates (${e.status})` : 'Failed to load templates';
		} finally {
			loadingTemplates = false;
		}
	}

	function resetByoc() {
		byocClientId = '';
		byocClientSecret = '';
	}

	async function selectTemplate(t: TemplateSummary) {
		selectedKey = t.key;
		loadingDetail = true;
		resetByoc();
		// New template → recompute the connection default on next configure entry.
		connectionDefaultsApplied = false;
		connectionId = '';
		try {
			selectedDetail = await getTemplate(t.key);
			nameInput = t.key;
			// Seed one entry per secret scheme so the per-scheme pickers bind
			// to defined slots on the configure step's first render.
			const seeded: Record<string, string> = {};
			for (const a of selectedDetail?.auth ?? []) {
				if (a.type === 'secret' && a.scheme) seeded[a.scheme] = '';
			}
			credentialsInput = seeded;
			// Same for instance-pinned config: a stale value from a previously
			// selected template must not carry into this one's form.
			const seededConfig: Record<string, string> = {};
			for (const p of selectedDetail?.instance_config_params ?? []) {
				seededConfig[p.name] = '';
			}
			configInput = seededConfig;
		} catch (e) {
			error = e instanceof ApiError ? `Failed to load template (${e.status})` : 'Failed to load template';
		} finally {
			loadingDetail = false;
		}
	}

	function proceedToConfigure() {
		if (!selectedDetail) return;
		step = 'configure';
	}

	async function startOAuth() {
		if (!oauthProvider) return;
		// Validate BYOC first so we don't open a popup that will fail at
		// cascade resolution with a cryptic error.
		const wantsByoc = byocClientId.trim() || byocClientSecret.trim();
		if (byocRequired && !(byocClientId.trim() && byocClientSecret.trim())) {
			error = 'Client ID and Client Secret are required — no org or system credentials are configured for this provider.';
			return;
		}
		if (wantsByoc && !(byocClientId.trim() && byocClientSecret.trim())) {
			error = 'Provide both Client ID and Client Secret, or leave both blank.';
			return;
		}
		oauthAbort?.abort();
		const ctrl = new AbortController();
		oauthAbort = ctrl;
		connectingOAuth = true;
		error = null;
		try {
			// If BYOC fields are filled, persist them as a user-owned BYOC
			// credential before kicking off OAuth. The cascade resolver picks
			// it up at tier 1 for this identity (SPEC §7).
			let byocCredentialId: string | undefined;
			if (wantsByoc && data.user?.identity_id) {
				try {
					const created = await createByocCredential({
						provider: oauthProvider.provider,
						client_id: byocClientId.trim(),
						client_secret: byocClientSecret.trim(),
						identity_id: data.user.identity_id
					});
					byocCredentialId = created.id;
				} catch (e) {
					if (e instanceof ApiError && e.status === 409) {
						// Pre-existing BYOC for this identity+provider will win at
						// tier 1 of the cascade without pinning — continue without
						// an explicit id.
					} else {
						throw e;
					}
				}
			}
			const beforeIds = new Set(connections.map((c) => c.id));
			const resp = await initiateOAuth(
				{
					provider: oauthProvider.provider,
					scopes: effectiveOAuthScopes,
					byoc_credential_id: byocCredentialId
				},
				ctrl.signal
			);
			if (ctrl.signal.aborted) return;
			let fresh: ConnectionSummary | null;
			try {
				fresh = await connectViaPopup({
					authUrl: resp.auth_url,
					provider: oauthProvider.provider,
					beforeIds,
					signal: ctrl.signal,
					// Keep the reuse picker fresh as rows arrive.
					onPoll: (rows) => {
						connections = rows;
					}
				});
			} catch (e) {
				if (e instanceof PopupBlockedError) {
					error = e.message;
					return;
				}
				throw e;
			}
			if (ctrl.signal.aborted) return;
			if (fresh) {
				connectionId = fresh.id;
				return;
			}
			error = 'OAuth did not complete in time. Try again.';
		} catch (e) {
			if (ctrl.signal.aborted) return;
			error = e instanceof ApiError ? `OAuth failed (${e.status})` : 'OAuth failed';
		} finally {
			// If a newer startOAuth call has replaced us, leave its state alone.
			// Otherwise always clear connectingOAuth — including the abort path,
			// so the user can retry after clicking Back.
			if (oauthAbort === ctrl) {
				oauthAbort = null;
				connectingOAuth = false;
			}
		}
	}

	onDestroy(() => {
		oauthAbort?.abort();
	});

	/**
	 * `force` is only ever passed by the overwrite confirm dialog below. The
	 * first attempt never forces: the server's refusal is what tells us there
	 * is something to confirm, and asking before we know would put a scary
	 * dialog in front of every create.
	 */
	async function submit(force = false) {
		if (!selectedDetail) return;
		submitting = true;
		error = null;
		try {
			// "Connect a new account" path: run OAuth as part of submit so the
			// service is created already bound to a connection. Otherwise the
			// user would need a separate click on "+ Connect new" first and the
			// service lands in "Needs Setup".
			if (usesOAuth && connectionChoice === 'new' && !connectionId) {
				await startOAuth();
				if (!connectionId) {
					// startOAuth already set `error` on popup-blocked / timeout /
					// abort / BYOC-missing. Don't create a half-bound service.
					submitting = false;
					return;
				}
			}
			// Per-scheme bindings ride the `credentials` map (the server mirrors
			// the legacy scalar); the scalar `secret_name` is only sent for the
			// paths still editing it directly (MCP bearer, pre-scheme APIs).
			const cleanedCredentials = cleanServiceMap(credentialsInput);
			const sendCredentials =
				schemeKeyed && !usesOAuth && Object.keys(cleanedCredentials).length > 0;
			const cleanedConfig = cleanServiceMap(configInput);
			const sendConfig = Object.keys(cleanedConfig).length > 0;

			// Values first, names second. A vault secret left stranded with no
			// service is harmless and reusable; the reverse — an instance
			// pointing at a name that holds nothing — is exactly the
			// `needs_authentication` shape the probe would then report as a
			// setup bug. Sequential, and the first failure aborts before
			// anything is created.
			await writeCredentialValues(cleanedCredentials);

			// `verify` rather than a `status`: the server's own rule gates only
			// when it mints a setup link, and this wizard probes either way —
			// including on the path where the user named an existing vault
			// secret, where no link exists. Sent only when the template can
			// actually answer, because `verify: true` on a probeless template
			// is a 400 by design.
			const instance = await createService({
				template_key: selectedDetail.key,
				name: nameInput.trim() || undefined,
				connection_id: connectionId || undefined,
				credentials: sendCredentials ? cleanedCredentials : undefined,
				secret_name: !sendCredentials ? secretName.trim() || undefined : undefined,
				config: sendConfig ? cleanedConfig : undefined,
				url: urlInput.trim() || undefined,
				verify: selectedDetail.test_action ? true : undefined,
				user_level: userLevel,
				groups: userLevel ? undefined : groupGrants,
				use_default_connection: useDefaultConnection,
				force: force || undefined
			});
			created = instance;
			submitting = false;
			// No probe declared — nothing this step could say, and the server
			// left the instance live. Go straight to the service.
			if (!instance.test_action) {
				await goto(`/services/${instance.id}`);
				return;
			}
			// A credential slot is still unfilled, so the probe's answer is a
			// foregone "no usable credential yet". Show the link to forward
			// instead and leave the button for when it has been used.
			if (!instance.setup) await runTest();
		} catch (e) {
			// A name collision is a question, not a failure: the instance was
			// not created, nothing was overwritten, and the one person who can
			// say whether replacing the credential is intended is looking at
			// the screen. Everything else stays an inline error.
			if (e instanceof ApiError && e.status === 409 && isSecretNameConflict(e.body)) {
				secretConflict = e.body;
				submitting = false;
				return;
			}
			error = e instanceof ApiError
				? `Failed to create service (${e.status}): ${JSON.stringify(e.body)}`
				: 'Failed to create service';
			submitting = false;
		}
	}

	function isSecretNameConflict(body: unknown): body is SecretNameConflictBody {
		return (
			typeof body === 'object' &&
			body !== null &&
			(body as { error?: unknown }).error === 'secret_name_conflict' &&
			Array.isArray((body as { conflicts?: unknown }).conflicts)
		);
	}

	/** Prose for the dialog: one secret reads better than a list of one. */
	const conflictMessage = $derived.by(() => {
		const c = secretConflict?.conflicts ?? [];
		if (c.length === 0) return '';
		const names = c.map((x) => `${x.secret_name} (v${x.current_version})`).join(', ');
		return c.length === 1
			? `A secret named ${names} already exists. Creating this service will hand out a setup link that replaces its current value — which may be the credential another service is already using. The old version stays restorable from the Secrets page.`
			: `These secrets already exist: ${names}. Creating this service will hand out setup links that replace their current values. The old versions stay restorable from the Secrets page.`;
	});

	/**
	 * Write every credential value the user typed, under the name its slot is
	 * bound to. Throws on the first failure, so the caller aborts rather than
	 * half-writing a vault.
	 *
	 * A blank value is not an erasure — it means "I did not supply this one",
	 * which is the shape of both an existing vault secret the user is reusing
	 * and a slot they intend to fill through a setup link.
	 */
	async function writeCredentialValues(names: Record<string, string>) {
		for (const [slot, value] of Object.entries(credentialValues)) {
			if (!value) continue;
			const name = names[slot] ?? secretName.trim();
			if (!name) continue;
			await putSecret(name, value);
		}
	}

	/**
	 * Run the probe and, on a green verdict, make the instance callable.
	 *
	 * Activation rather than a bare probe: this is the screen where the user
	 * is standing up the service, so finishing is the point. `status` off the
	 * response is authoritative — a forced activation carries no verdict at
	 * all, and `not_supported` promotes on a verdict that never reached an
	 * upstream.
	 */
	async function runTest() {
		if (!created) return;
		testing = true;
		testResult = null;
		confirmingForce = false;
		try {
			const res = await runActivate(created.id);
			testResult = res.verdict ?? null;
			created = { ...created, status: res.status };
		} finally {
			testing = false;
		}
	}

	/** Open the reopen panel, seeded from the instance as the server stored it. */
	function reopen() {
		if (!created) return;
		nameInput = created.name;
		urlInput = created.url ?? '';
		configInput = { ...(created.config ?? {}) };
		credentialsInput = { ...(created.credentials ?? {}) };
		// Seeded with a key per slot, not left empty. `SecretValueField`'s
		// `value` is `$bindable('')`, and Svelte 5 throws `props_invalid_value`
		// on `bind:` to an absent member — so an unseeded map takes the whole
		// panel down rather than rendering a blank field.
		credentialValues = Object.fromEntries(
			(schemeKeyed && !usesOAuth ? secretSlots.map((s) => s.key) : ['']).map((k) => [k, ''])
		);
		reopened = true;
		// Deliberately *not* clearing `testResult`. Opening the panel to
		// re-read the error and closing it again must leave the verdict where
		// it was; clearing on open is the tempting one-liner and it is wrong.
	}

	/** Save the edits, then check again. */
	async function saveAndRetest() {
		if (!created) return;
		saving = true;
		error = null;
		try {
			const cleanedCredentials = cleanServiceMap(credentialsInput);
			await writeCredentialValues(cleanedCredentials);
			const cleanedConfig = cleanServiceMap(configInput);
			created = await updateService(created.id, {
				name: nameInput.trim() || undefined,
				url: urlInput.trim() || undefined,
				config: cleanedConfig,
				// A whole-map replace server-side, so send it only when a name
				// actually changed rather than echoing it back every save.
				credentials: schemeKeyed && !usesOAuth ? cleanedCredentials : undefined
			});
			reopened = false;
			saving = false;
			await runTest();
		} catch (e) {
			error = e instanceof ApiError
				? `Could not save the changes (${e.status}): ${JSON.stringify(e.body)}`
				: 'Could not save the changes';
			saving = false;
		}
	}

	/**
	 * "Activate anyway" — go live on a red verdict.
	 *
	 * `activate?force=true`, not the blunt status PATCH. It runs no probe
	 * either, so there is nothing to save by going around it — and going
	 * around it would skip the `service.activated` event, leaving an agent
	 * blocked on exactly this moment waiting forever.
	 */
	async function activateAnyway() {
		if (!created) return;
		promoting = true;
		error = null;
		try {
			const res = await activateService(created.id, { force: true });
			created = { ...created, status: res.status };
			await goto(`/services/${created.id}`);
		} catch (e) {
			error = e instanceof ApiError
				? `Could not activate (${e.status}): ${JSON.stringify(e.body)}`
				: 'Could not activate';
			promoting = false;
		}
	}

	onMount(async () => {
		await loadTemplates();
		const presetKey = $page.url.searchParams.get('template');
		if (presetKey) {
			const match = templates.find((t) => t.key === presetKey);
			if (match) {
				await selectTemplate(match);
				if (selectedDetail) step = 'configure';
			}
		}
	});
</script>

<svelte:head><title>New service - Overslash</title></svelte:head>

<div class="page">
	<a href="/services" class="back">← Back to services</a>
	<h1>
		{#if created}
			<!-- Not "Check it works" any more: that was an imperative from when
			     the user had to press a button. The check runs itself now, so
			     the heading reports where the service stands. -->
			{#if testing || !testResult}
				Checking it works
			{:else if live}
				{created.name} is live
			{:else}
				Not live yet
			{/if}
		{:else if step === 'pick'}
			Choose a template
		{:else}
			Configure service
		{/if}
	</h1>

	<ConfirmDialog
		open={secretConflict !== null}
		title="Replace an existing secret?"
		message={conflictMessage}
		confirmLabel="Replace it"
		cancelLabel="Cancel"
		danger
		onconfirm={() => {
			secretConflict = null;
			submit(true);
		}}
		oncancel={() => (secretConflict = null)}
	>
		{#if secretConflict}
			<p class="conflict-hint">
				To share the existing credential instead, go back and pick that secret
				name in the credentials field — binding it overwrites nothing.
			</p>
		{/if}
	</ConfirmDialog>

	{#if error}
		<div class="error">{error}</div>
	{/if}

	{#if step === 'pick'}
		<div class="filters">
			<SearchBar
				keys={searchKeys}
				bind:value={searchValue}
				placeholder="Search templates… (try tier=global)"
				onchange={(next) => (searchValue = next)}
			/>
		</div>

		<div class="layout">
			<div class="catalog">
				{#if loadingTemplates}
					<div class="empty">Loading templates…</div>
				{:else if filteredTemplates.length === 0}
					<div class="empty">No templates match.</div>
				{:else}
					<div class="grid">
						{#each filteredTemplates as t (t.key + t.tier)}
							<TemplateCard
								template={t}
								selected={selectedKey === t.key}
								onselect={selectTemplate}
							/>
						{/each}
					</div>
				{/if}
			</div>

			<aside class="preview">
				{#if loadingDetail}
					<p class="muted">Loading…</p>
				{:else if selectedDetail}
					<div class="preview-head">
						<ServiceIcon src={selectedDetail.icon_url} name={selectedDetail.display_name} size={28} />
						<h2>{selectedDetail.display_name}</h2>
						<StatusBadge variant={selectedDetail.tier} />
						<a
							href="/services/templates/{encodeURIComponent(selectedDetail.key)}"
							class="edit-template-link"
						>
							Edit template &rarr;
						</a>
					</div>
					<div class="mono muted">{selectedDetail.key}</div>
					{#if selectedDetail.description}
						<p>{selectedDetail.description}</p>
					{/if}
					{#if selectedDetail.hosts.length}
						<div class="row">
							<span class="label">Hosts</span>
							<span class="mono">{selectedDetail.hosts.join(', ')}</span>
						</div>
					{/if}
					<div class="row">
						<span class="label">Auth</span>
						<span>{(selectedDetail.auth as any[]).map((a) => a.type).join(', ') || 'none'}</span>
					</div>
					<div class="row">
						<span class="label">Actions</span>
						<span>{Object.keys(selectedDetail.actions ?? {}).length}</span>
					</div>
					<button type="button" class="btn primary block" onclick={proceedToConfigure}>
						Use this template
					</button>
				{:else}
					<p class="muted">Select a template to preview its actions and auth requirements.</p>
				{/if}
			</aside>
		</div>
	{:else if created}
		<!-- Post-create verification, and a real decision rather than a report.
		     The instance exists but is not callable: a template that declares a
		     probe is created `pending_setup` and only a green verdict promotes
		     it. So the ways out differ — one fixes the credential, one goes
		     live without a verdict, one throws the whole thing away. -->
		<div class="form-card">
			<div class="row">
				<span class="label">Service</span>
				<span class="mono">{created.name}</span>
				<StatusBadge variant={created.status} />
			</div>

			{#if created.setup && !testResult && !testing}
				<p>
					Once the credential below has been provided, check it here — that is
					what makes {created.name} usable.
				</p>
				<div class="actions start">
					<button type="button" class="btn" onclick={runTest}>Check it works</button>
				</div>
			{:else}
				<TestResult result={testResult} running={testing} onRetry={runTest} />
			{/if}

			{#if created.setup}
				<!-- A credential slot nobody filled in. The link is the same one
				     an agent would be handed, so the person who holds the key
				     provides it themselves and the value never passes through
				     whoever is standing the service up. -->
				<div class="setup-link">
					<p class="label">Still needs a credential</p>
					<p>
						Send this single-use link to whoever holds the key. They will need to
						sign in to Overslash — checking the credential is what switches the
						service on, and that check runs as somebody.
					</p>
					{#each created.setup.warnings ?? [] as w (w.secret_name)}
						<!-- Only ever present when this create was forced past a
						     name collision. Repeated here because the person who
						     confirmed the dialog is often not the person who
						     opens the link. -->
						<p class="overwrite-note">{w.message}</p>
					{/each}
					<input
						type="text"
						readonly
						value={created.setup.short_url ?? created.setup.setup_url}
						onfocus={(e) => e.currentTarget.select()}
					/>
				</div>
			{/if}

			{#if !live && testResult && !testing}
				<!-- The 24h deadline, stated where it is certain to be read.
				     An unfinished setup is swept, and a user who closes this tab
				     on a red verdict should not discover that by absence. -->
				<p class="expiry-note">
					{created.name} is not live, so nothing can call it yet. Unfinished setups
					are deleted automatically after about a day — fix the credential below,
					or activate it anyway if you know it will work.
				</p>
			{/if}

			{#if reopened}
				<!-- The reopen panel. Only the fields `PUT /manage` accepts:
				     rewinding to the configure step would show four more that
				     silently would not save, and its submit creates. -->
				<div class="reopen">
					<label class="field">
						<span class="label">Name</span>
						<input type="text" bind:value={nameInput} disabled={saving} />
					</label>

					{#if created.url !== undefined || urlInput}
						<label class="field">
							<span class="label">URL</span>
							<input type="text" bind:value={urlInput} disabled={saving} />
						</label>
					{/if}

					{#if instanceConfigParams.length > 0}
						<ServiceInstanceConfig
							params={instanceConfigParams}
							bind:config={configInput}
							idPrefix="retry-service-config"
						/>
					{/if}

					{#if schemeKeyed && !usesOAuth}
						<!-- A *value*, not a name. The wizard could only ever bind
						     a vault name, which under the gate is a dead end: the
						     probe answers "no value stored for `resend_key`" and
						     there is nothing on this page that could supply one. -->
						{#each secretSlots as slot (slot.key)}
							<SecretValueField
								bind:value={credentialValues[slot.key]}
								label={credentialLabel(slot)}
								placeholder="Paste a new value"
								disabled={saving}
							/>
						{/each}
					{:else if !usesOAuth}
						<SecretValueField
							bind:value={credentialValues['']}
							label="Credential"
							placeholder="Paste a new value"
							disabled={saving}
						/>
					{/if}

					<div class="actions start">
						<button
							type="button"
							class="btn primary"
							onclick={saveAndRetest}
							disabled={saving}
						>
							{saving ? 'Saving…' : 'Save and check again'}
						</button>
						<button
							type="button"
							class="btn"
							onclick={() => (reopened = false)}
							disabled={saving}>Cancel</button
						>
					</div>
				</div>
			{/if}

			<div class="actions">
				{#if live}
					<button
						type="button"
						class="btn primary"
						onclick={() => goto(`/services/${created?.id}`)}>Done</button
					>
				{:else}
					<button
						type="button"
						class="btn primary"
						onclick={reopen}
						disabled={reopened || testing}>Edit and retry</button
					>
					<button
						type="button"
						class="btn"
						onclick={() => goto(`/services/${created?.id}`)}>Leave as draft</button
					>
					{#if probeRejected(testResult)}
						<!-- "anyway" only where something actually went wrong.
						     With no verdict, or one in which the upstream was
						     never asked (approval, missing credential, deny
						     rule), there is nothing to push past — and offering
						     an override there would imply the credential had
						     been tried when it had not. -->
						{#if confirmingForce}
							<button
								type="button"
								class="btn danger"
								onclick={activateAnyway}
								disabled={promoting}
							>
								{promoting ? 'Activating…' : 'Confirm — go live unchecked'}
							</button>
						{:else}
							<button
								type="button"
								class="btn ghost-danger"
								onclick={() => (confirmingForce = true)}
							>
								{#if kind === 'unreachable'}
									Create anyway
								{:else if kind === 'rejected'}
									Use it anyway
								{:else}
									Activate anyway
								{/if}
							</button>
						{/if}
					{/if}
				{/if}
			</div>

			{#if confirmingForce && kind}
				<p class="force-note">
					{#if kind === 'unreachable'}
						Nothing answered at that address. If it is only reachable from your own
						network the key may well be fine — but nothing will work until
						Overslash can reach it either.
					{:else if kind === 'rejected'}
						{created.name} refused this credential. Activating will not change
						that — the first real call fails the same way.
					{:else}
						<!-- Deliberately not "the credential is probably fine": Resend
						     rejects a bad key with a 400, not a 401. The status alone
						     does not say, so defer to what the upstream actually
						     said, which the verdict above is already showing. -->
						{created.name} answered with an error rather than refusing the
						credential outright — read it above. Activating goes live without
						knowing which it was.
					{/if}
				</p>
			{/if}
		</div>
	{:else if selectedDetail}
		<div class="form-card">
			<div class="row">
				<span class="label">Template</span>
				<span class="mono">{selectedDetail.key}</span>
				<StatusBadge variant={selectedDetail.tier} />
			</div>

			<label class="field">
				<span class="label">Name</span>
				<input type="text" bind:value={nameInput} placeholder={selectedDetail.key} />
				<small>Defaults to the template key if left blank.</small>
			</label>

			<div class="field toggle-field">
				<ToggleSwitch
					checked={userLevel}
					onchange={(v) => (userLevel = v)}
					labelledby="user-level-label"
				/>
				<span id="user-level-label">Create as user-level (only visible to your identity)</span>
			</div>

			{#if !userLevel}
				<div class="field groups-field">
					<span class="label">Groups <span class="req">required</span></span>
					{#if groupGrants.length > 0}
						<ul class="grant-list">
							{#each groupGrants as g (g.group_id)}
								<li>
									<span class="grant-name">{groupName(g.group_id)}</span>
									<span class="grant-meta">{g.access_level}</span>
									{#if g.auto_approve_level !== 'none'}
										<span class="grant-meta">auto-approve {g.auto_approve_level}</span>
									{/if}
									{#if groupById.get(g.group_id)?.is_member === false}
										<span class="grant-warn">you're not a member</span>
									{/if}
									<button
										type="button"
										class="link-btn"
										onclick={() => removeGroupGrant(g.group_id)}>Remove</button
									>
								</li>
							{/each}
						</ul>
					{/if}
					{#if availableGroups.length === 0}
						<p class="muted no-groups">
							No groups exist yet. Create one in <a href="/org/groups" class="link">Org → Groups</a
							>, or keep this service user-level.
						</p>
					{:else}
						<GroupGrantPicker
							groups={availableGroups}
							excludeIds={pickedGroupIds}
							onadd={addGroupGrant}
						/>
					{/if}
					{#if groupHint}
						<small class="hint">{groupHint}</small>
					{/if}
				</div>
			{/if}

			{#if usesOAuth}
				<div class="field">
					<span class="label">OAuth credential ({oauthProvider?.provider})</span>

					{#if matchingConnections.length}
						<label class="radio-row">
							<input
								type="radio"
								name="connection-choice"
								value="existing"
								checked={connectionChoice === 'existing'}
								onchange={() => {
									connectionChoice = 'existing';
									if (!connectionId && preferredConnection) {
										connectionId = preferredConnection.id;
									}
								}}
							/>
							<span>Use an existing connection</span>
						</label>

						{#if connectionChoice === 'existing'}
							<select bind:value={connectionId} class="connection-select">
								{#each matchingConnections as c}
									<option value={c.id}>
										{connectionLabel(c)}
										{connectionUsageHint(c, selectedDetail?.key ?? '')}
									</option>
								{/each}
							</select>
							<small class="hint">
								Connections are labelled with the account's email when the
								provider supplies one. Reusing a connection avoids a fresh
								OAuth flow.
							</small>
						{/if}

						<label class="radio-row">
							<input
								type="radio"
								name="connection-choice"
								value="new"
								checked={connectionChoice === 'new'}
								onchange={() => {
									connectionChoice = 'new';
									connectionId = '';
								}}
							/>
							<span>Connect a new account</span>
						</label>
					{/if}

					{#if connectionChoice === 'new' || matchingConnections.length === 0}
						<div class="new-connection">
							{#if providerInfo?.has_org_credential}
								<p class="cred-source">
									Using <strong>org credentials</strong> configured for {providerInfo.display_name}.
								</p>
							{:else if providerInfo?.has_system_credential}
								<p class="cred-source">
									Using <strong>Overslash system credentials</strong>.
								</p>
							{:else if !providerInfo?.has_user_byoc_credential}
								<p class="cred-source">
									<span class="warn">
										No credentials configured for this provider — paste your own below to continue.
									</span>
								</p>
							{/if}

							<ByocSection
								provider={oauthProvider.provider}
								providerDisplayName={providerInfo?.display_name ?? oauthProvider.provider}
								required={byocRequired}
								defaultExpanded={byocRequired}
								disabled={connectingOAuth}
								alreadyConfigured={providerInfo?.has_user_byoc_credential ?? false}
								scopes={effectiveOAuthScopes}
								redirectUri={providerInfo?.oauth_redirect_uri ?? ''}
								jsOrigin={providerInfo?.oauth_js_origin ?? ''}
								bind:clientId={byocClientId}
								bind:clientSecret={byocClientSecret}
							/>

							<button
								type="button"
								class="btn"
								onclick={startOAuth}
								disabled={connectingOAuth}
							>
								{connectingOAuth ? 'Waiting for authorization…' : '+ Connect new'}
							</button>
						</div>
					{/if}

					<div class="field toggle-field">
						<ToggleSwitch
							checked={useDefaultConnection}
							onchange={(v) => (useDefaultConnection = v)}
							labelledby="use-default-connection-label"
						/>
						<span id="use-default-connection-label">
							Fall back to my default {oauthProvider?.provider} connection when this service
							has none pinned
						</span>
					</div>
					{#if !useDefaultConnection}
						<small class="hint">
							Off: calls fail with <code>needs_authentication</code> until a connection is
							explicitly bound to this service. Use this for white-label setups where each
							service gets its own dedicated connection.
						</small>
					{/if}
				</div>
			{/if}

			{#if isMcp}
				<label class="field">
					<span class="label">MCP server URL</span>
					<input
						type="text"
						bind:value={urlInput}
						placeholder={inheritedUrl ?? selectedDetail?.mcp?.url ?? 'http://host:8081/mcp'}
					/>
					{#if mcpNeedsUrl}
						<small>Required — this template has no default URL.</small>
					{:else if inheritedUrl}
						<small>Leave blank to use your org's deployment ({inheritedUrl}).</small>
					{:else}
						<small>Leave blank to use the template's default.</small>
					{/if}
				</label>
			{:else if httpNeedsUrl}
				<label class="field">
					<span class="label">Endpoint URL</span>
					<input
						type="text"
						bind:value={urlInput}
						placeholder={inheritedUrl ??
							(selectedDetail?.hosts?.[0]
								? `https://${selectedDetail.hosts[0]}`
								: 'https://service.your-org.com')}
					/>
					{#if httpUrlRequired}
						<small>Required — this template has no default endpoint.</small>
					{:else if inheritedUrl}
						<small>Leave blank to use your org's deployment ({inheritedUrl}).</small>
					{:else}
						<small>Point this instance at your own deployment. Leave blank to use the default.</small>
					{/if}
				</label>
			{/if}

			{#if instanceConfigParams.length > 0}
				<ServiceInstanceConfig
					params={instanceConfigParams}
					bind:config={configInput}
					inherited={layerDefaults?.config}
					idPrefix="new-service-config"
				/>
			{/if}

			{#if usesSecret && !usesOAuth && schemeKeyed}
				<ServiceCredentials
					slots={secretSlots}
					bind:credentials={credentialsInput}
					available={availableSecrets}
					loading={secretsLoading}
					idPrefix="new-service-cred"
				/>
			{:else if (usesSecret && !usesOAuth) || mcpNeedsSecret}
				<div class="field">
					<label class="label" for="new-service-secret">
						{#if mcpNeedsSecret}Bearer token secret name{:else}Secret name{/if}
					</label>
					<SecretNamePicker
						id="new-service-secret"
						bind:value={secretName}
						available={availableSecrets}
						loading={secretsLoading}
					/>
					{#if mcpNeedsSecret}
						<small>Vault key holding the MCP server's bearer token. Required — this template has no default.</small>
					{:else if httpNeedsUrl}
						<small>The per-instance credential this gateway presents (e.g. a mailbox <code>user:pass</code>). Any shared gateway key is a separate org secret.</small>
					{:else}
						<small>Pick an existing secret from your vault, or type a new name to use later.</small>
					{/if}
				</div>
			{/if}

			<div class="actions">
				<button
					type="button"
					class="btn"
					onclick={() => {
						oauthAbort?.abort();
						step = 'pick';
						connectionDefaultsApplied = false;
					}}>Back</button
				>
				<button
					type="button"
					class="btn primary"
					onclick={() => submit()}
					disabled={submitting || connectingOAuth || !groupsSatisfied}
				>
					{#if connectingOAuth}
						Waiting for authorization…
					{:else if submitting}
						Creating…
					{:else if usesOAuth && connectionChoice === 'new' && !connectionId}
						Connect & create
					{:else}
						Create service
					{/if}
				</button>
			</div>
		</div>
	{/if}
</div>

<style>
	.page {
		max-width: 1100px;
	}
	.back {
		display: inline-block;
		font-size: 0.85rem;
		color: var(--color-text-muted);
		text-decoration: none;
		margin-bottom: 0.5rem;
	}
	.back:hover {
		color: var(--color-text);
	}
	h1 {
		font: var(--text-h1);
		margin: 0 0 1rem;
	}
	h2 {
		margin: 0;
		font-size: 1.05rem;
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
	.filters {
		margin-bottom: 1rem;
	}
	.layout {
		display: grid;
		grid-template-columns: 2fr 1fr;
		gap: 1.25rem;
	}
	@media (max-width: 900px) {
		.layout {
			grid-template-columns: 1fr;
		}
	}
	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
		gap: 0.75rem;
	}
	.preview {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 1.1rem;
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
		position: sticky;
		top: 1rem;
		align-self: start;
	}
	.preview-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.5rem;
		flex-wrap: wrap;
	}
	.edit-template-link {
		font-size: 0.78rem;
		color: var(--color-primary, #6366f1);
		text-decoration: none;
		white-space: nowrap;
	}
	.edit-template-link:hover {
		text-decoration: underline;
	}
	.row {
		display: flex;
		gap: 0.5rem;
		align-items: center;
		font-size: 0.85rem;
	}
	.label {
		font-size: 0.72rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		min-width: 60px;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.8rem;
	}
	.muted {
		color: var(--color-text-muted);
	}
	.empty {
		background: var(--color-surface);
		border: 1px dashed var(--color-border);
		border-radius: 10px;
		padding: 2rem;
		text-align: center;
		color: var(--color-text-muted);
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
	/* The escape hatch, and the confirm it turns into. Ghost first so it does
	   not compete with "Edit and retry", solid once the user has chosen it. */
	.btn.ghost-danger {
		color: #b91c1c;
		border-color: rgba(220, 38, 38, 0.35);
	}
	.btn.danger {
		background: #b91c1c;
		color: white;
		border-color: #b91c1c;
	}
	.btn.block {
		width: 100%;
		margin-top: 0.5rem;
	}
	.form-card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 10px;
		padding: 1.5rem;
		display: flex;
		flex-direction: column;
		gap: 1rem;
		max-width: 640px;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}
	.groups-field {
		gap: 0.6rem;
	}
	.groups-field .req {
		margin-left: 0.4rem;
		color: var(--color-danger, #b91c1c);
		letter-spacing: normal;
		text-transform: none;
	}
	.groups-field .hint {
		margin: 0;
	}
	.no-groups {
		margin: 0;
		font-size: 0.8rem;
	}
	.no-groups .link {
		color: var(--color-primary, #6366f1);
	}
	.grant-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}
	.grant-list li {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.85rem;
	}
	.grant-name {
		font-weight: 500;
	}
	.grant-meta {
		font-size: 0.72rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--color-text-muted);
	}
	.grant-warn {
		font-size: 0.72rem;
		color: var(--color-danger, #b91c1c);
	}
	.link-btn {
		background: none;
		border: none;
		padding: 0;
		margin-left: auto;
		color: var(--color-text-muted);
		font: inherit;
		font-size: 0.78rem;
		text-decoration: underline;
		cursor: pointer;
	}
	.field.toggle-field {
		flex-direction: row;
		align-items: center;
		gap: 0.6rem;
	}
	.field input[type='text'],
	.field select {
		padding: 0.5rem 0.7rem;
		border-radius: 6px;
		border: 1px solid var(--color-border);
		background: var(--color-bg);
		color: inherit;
		font: inherit;
		font-size: 0.9rem;
	}
	.field small {
		color: var(--color-text-muted);
		font-size: 0.75rem;
	}
	.cred-source {
		margin: 0;
		font-size: 0.78rem;
		color: var(--color-text-muted);
	}
	.cred-source .warn {
		color: #b45309;
	}
	.radio-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.3rem 0;
		font-size: 0.9rem;
		cursor: pointer;
	}
	.connection-select {
		margin: 0.2rem 0 0.25rem 1.55rem;
	}
	.hint {
		display: block;
		margin: 0 0 0.3rem 1.55rem;
		color: var(--color-text-muted);
		font-size: 0.72rem;
	}
	.new-connection {
		margin-left: 1.55rem;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 0.5rem;
	}
	p {
		margin: 0;
		font-size: 0.9rem;
		color: var(--color-text-muted);
	}
	.actions.start {
		justify-content: flex-start;
	}
	.expiry-note,
	.force-note {
		margin: 0;
		font-size: 0.85rem;
		color: var(--color-text-muted, #6b7280);
		line-height: 1.5;
	}
	.force-note {
		color: #b91c1c;
	}
	/* Indented and ruled, so an open panel reads as "inside the failure" rather
	   than as a second form competing with the verdict above it. */
	.reopen {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
		border-left: 2px solid var(--color-border);
		padding-left: 0.85rem;
	}
	.setup-link {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
		border: 1px solid var(--color-border);
		border-radius: 8px;
		padding: 0.75rem 0.85rem;
	}
	.setup-link input {
		width: 100%;
		padding: 0.5rem 0.65rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-bg);
		color: var(--color-text);
		font-family: var(--font-mono);
		font-size: 0.8rem;
	}
	.overwrite-note {
		font-size: 0.8rem;
		color: var(--color-text);
		background: var(--badge-bg-warning);
		border: 1px solid var(--color-warning);
		border-radius: 6px;
		padding: 0.5rem 0.65rem;
		margin: 0;
	}
	.conflict-hint {
		font-size: 0.8rem;
		color: var(--color-text-muted);
		margin: 0 0 1.25rem;
	}
</style>

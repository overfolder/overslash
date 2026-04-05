<script lang="ts">
	import { onMount } from 'svelte';
	import { session, ApiError } from '$lib/session';
	import type { OrgDetail, IdpConfigResponse, IdentitySummary } from '$lib/types';
	import DataTable from '$lib/components/DataTable.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';

	let org: OrgDetail | null = $state(null);
	let idpConfigs: IdpConfigResponse[] = $state([]);
	let identities: IdentitySummary[] = $state([]);
	let loading = $state(true);
	let error: string | null = $state(null);
	let saveSuccess = $state(false);

	// Editable org fields
	let orgName = $state('');
	let allowUserTemplates = $state(true);
	let saving = $state(false);

	// IdP create modal
	let showAddIdp = $state(false);
	let idpForm = $state({
		provider_key: '',
		issuer_url: '',
		display_name: '',
		client_id: '',
		client_secret: '',
		enabled: true,
		allowed_email_domains: ''
	});
	let idpError: string | null = $state(null);
	let idpSaving = $state(false);

	// IdP edit modal
	let showEditIdp = $state(false);
	let editIdpTarget: IdpConfigResponse | null = $state(null);
	let editIdpForm = $state({ client_id: '', client_secret: '', enabled: true, allowed_email_domains: '' });
	let editIdpError: string | null = $state(null);

	// IdP delete
	let showDeleteIdp = $state(false);
	let deleteIdpTarget: IdpConfigResponse | null = $state(null);

	let users = $derived(identities.filter((i) => i.kind === 'user'));

	const idpColumns = [
		{ key: 'provider_key', label: 'Provider' },
		{ key: 'display_name', label: 'Name' },
		{ key: 'source', label: 'Source' },
		{ key: 'enabled', label: 'Enabled' },
		{ key: 'allowed_email_domains', label: 'Domains' },
		{ key: '_actions', label: '' }
	];

	const memberColumns = [
		{ key: 'name', label: 'Name' },
		{ key: 'email', label: 'Email' },
		{ key: 'kind', label: 'Kind' },
		{ key: 'created_at', label: 'Created' }
	];

	async function load() {
		loading = true;
		error = null;
		try {
			const [o, idps, ids] = await Promise.all([
				session.get<OrgDetail>('/v1/orgs/me'),
				session.get<IdpConfigResponse[]>('/v1/org-idp-configs'),
				session.get<IdentitySummary[]>('/v1/identities')
			]);
			org = o;
			orgName = o.name;
			allowUserTemplates = o.allow_user_templates;
			idpConfigs = idps;
			identities = ids;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load settings';
		} finally {
			loading = false;
		}
	}

	async function saveOrg() {
		saving = true;
		saveSuccess = false;
		error = null;
		try {
			org = await session.put<OrgDetail>('/v1/orgs/me', {
				name: orgName,
				allow_user_templates: allowUserTemplates
			});
			saveSuccess = true;
			setTimeout(() => (saveSuccess = false), 3000);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Save failed';
		} finally {
			saving = false;
		}
	}

	async function handleAddIdp() {
		idpError = null;
		idpSaving = true;
		try {
			const body: Record<string, unknown> = {
				client_id: idpForm.client_id,
				client_secret: idpForm.client_secret,
				enabled: idpForm.enabled,
				allowed_email_domains: idpForm.allowed_email_domains.split(',').map((d) => d.trim()).filter(Boolean)
			};
			if (idpForm.provider_key) body.provider_key = idpForm.provider_key;
			if (idpForm.issuer_url) body.issuer_url = idpForm.issuer_url;
			if (idpForm.display_name) body.display_name = idpForm.display_name;

			await session.post('/v1/org-idp-configs', body);
			showAddIdp = false;
			idpForm = { provider_key: '', issuer_url: '', display_name: '', client_id: '', client_secret: '', enabled: true, allowed_email_domains: '' };
			await load();
		} catch (e) {
			idpError = e instanceof ApiError
				? (typeof e.body === 'object' && e.body !== null && 'error' in e.body ? String((e.body as {error:string}).error) : `Error ${e.status}`)
				: (e instanceof Error ? e.message : 'Failed');
		} finally {
			idpSaving = false;
		}
	}

	function openEditIdp(cfg: IdpConfigResponse) {
		editIdpTarget = cfg;
		editIdpForm = {
			client_id: '',
			client_secret: '',
			enabled: cfg.enabled,
			allowed_email_domains: (cfg.allowed_email_domains ?? []).join(', ')
		};
		editIdpError = null;
		showEditIdp = true;
	}

	async function handleEditIdp() {
		if (!editIdpTarget?.id) return;
		editIdpError = null;
		idpSaving = true;
		try {
			const body: Record<string, unknown> = { enabled: editIdpForm.enabled };
			if (editIdpForm.client_id) body.client_id = editIdpForm.client_id;
			if (editIdpForm.client_secret) body.client_secret = editIdpForm.client_secret;
			body.allowed_email_domains = editIdpForm.allowed_email_domains.split(',').map((d) => d.trim()).filter(Boolean);
			await session.put(`/v1/org-idp-configs/${editIdpTarget.id}`, body);
			showEditIdp = false;
			await load();
		} catch (e) {
			editIdpError = e instanceof ApiError
				? (typeof e.body === 'object' && e.body !== null && 'error' in e.body ? String((e.body as {error:string}).error) : `Error ${e.status}`)
				: (e instanceof Error ? e.message : 'Failed');
		} finally {
			idpSaving = false;
		}
	}

	async function handleDeleteIdp() {
		if (!deleteIdpTarget?.id) return;
		try {
			await session.delete(`/v1/org-idp-configs/${deleteIdpTarget.id}`);
			showDeleteIdp = false;
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Delete failed';
			showDeleteIdp = false;
		}
	}

	onMount(load);
</script>

<svelte:head>
	<title>Settings - Overslash Admin</title>
</svelte:head>

<div class="page">
	<h1>Settings</h1>

	{#if loading}
		<div class="loading-card"><div class="spinner"></div> Loading settings...</div>
	{:else}
		{#if error}
			<div class="error-msg">{error}</div>
		{/if}
		{#if saveSuccess}
			<div class="success-msg">Settings saved.</div>
		{/if}

		<!-- Card 1: Organization -->
		<div class="card">
			<h2>Organization</h2>
			<div class="form-grid">
				<div class="form-group">
					<label for="org-name">Name</label>
					<input id="org-name" type="text" bind:value={orgName} />
				</div>
				<div class="form-group">
					<label>Slug</label>
					<input type="text" value={org?.slug ?? ''} disabled />
				</div>
				<div class="form-group">
					<label>Org ID</label>
					<input type="text" class="mono" value={org?.id ?? ''} disabled />
				</div>
				<div class="form-group">
					<label>Created</label>
					<input type="text" value={org?.created_at ? new Date(org.created_at).toLocaleDateString() : ''} disabled />
				</div>
			</div>
		</div>

		<!-- Card 2: Policies -->
		<div class="card">
			<h2>Policies</h2>
			<div class="toggle-row">
				<label class="toggle-label">
					<input type="checkbox" bind:checked={allowUserTemplates} />
					Allow user-level templates
				</label>
				<span class="toggle-desc">When enabled, users can create personal service templates.</span>
			</div>
			<div class="save-row">
				<button class="btn btn-primary" onclick={saveOrg} disabled={saving}>
					{saving ? 'Saving...' : 'Save Settings'}
				</button>
			</div>
		</div>

		<!-- Card 3: Identity Providers -->
		<div class="card">
			<div class="card-header">
				<h2>Identity Providers</h2>
				<button class="btn-sm" onclick={() => (showAddIdp = true)}>Add Provider</button>
			</div>
			<DataTable items={idpConfigs} columns={idpColumns} emptyMessage="No identity providers configured.">
				{#snippet cell({ item, column })}
					{#if column.key === 'source'}
						<StatusBadge status={String(item.source)} />
					{:else if column.key === 'enabled'}
						<StatusBadge status={item.enabled ? 'enabled' : 'disabled'} />
					{:else if column.key === 'allowed_email_domains'}
						{#if item.allowed_email_domains && (item.allowed_email_domains as string[]).length > 0}
							{(item.allowed_email_domains as string[]).join(', ')}
						{:else}
							<span class="muted">any</span>
						{/if}
					{:else if column.key === '_actions'}
						{#if item.source === 'db'}
							<div class="row-actions">
								<button class="btn-sm" onclick={() => openEditIdp(item as unknown as IdpConfigResponse)}>Edit</button>
								<button class="btn-sm btn-danger" onclick={() => { deleteIdpTarget = item as unknown as IdpConfigResponse; showDeleteIdp = true; }}>Delete</button>
							</div>
						{:else}
							<span class="read-only">read-only</span>
						{/if}
					{:else}
						{item[column.key] ?? '—'}
					{/if}
				{/snippet}
			</DataTable>
		</div>

		<!-- Card 4: Members -->
		<div class="card">
			<h2>Members</h2>
			<DataTable items={users} columns={memberColumns} emptyMessage="No users found.">
				{#snippet cell({ item, column })}
					{#if column.key === 'kind'}
						<StatusBadge status={String(item.kind)} />
					{:else if column.key === 'created_at'}
						{item.created_at ? new Date(String(item.created_at)).toLocaleDateString() : '—'}
					{:else}
						{item[column.key] ?? '—'}
					{/if}
				{/snippet}
			</DataTable>
		</div>
	{/if}
</div>

<!-- Add IdP Modal -->
<Modal open={showAddIdp} title="Add Identity Provider" onclose={() => (showAddIdp = false)}>
	{#if idpError}<div class="modal-error">{idpError}</div>{/if}
	<form onsubmit={(e) => { e.preventDefault(); handleAddIdp(); }}>
		<div class="form-group">
			<label for="idp-key">Provider Key (for builtin: google, github)</label>
			<input id="idp-key" type="text" bind:value={idpForm.provider_key} placeholder="google" />
		</div>
		<div class="form-group">
			<label for="idp-issuer">OR Issuer URL (for custom OIDC)</label>
			<input id="idp-issuer" type="text" bind:value={idpForm.issuer_url} placeholder="https://login.example.com" />
		</div>
		<div class="form-group">
			<label for="idp-display">Display Name (custom only)</label>
			<input id="idp-display" type="text" bind:value={idpForm.display_name} placeholder="My OIDC Provider" />
		</div>
		<div class="form-group">
			<label for="idp-client-id">Client ID</label>
			<input id="idp-client-id" type="text" bind:value={idpForm.client_id} required />
		</div>
		<div class="form-group">
			<label for="idp-client-secret">Client Secret</label>
			<input id="idp-client-secret" type="password" bind:value={idpForm.client_secret} required />
		</div>
		<div class="form-group">
			<label for="idp-domains">Allowed Email Domains (comma-separated)</label>
			<input id="idp-domains" type="text" bind:value={idpForm.allowed_email_domains} placeholder="example.com, corp.io" />
		</div>
		<div class="form-group checkbox-group">
			<label>
				<input type="checkbox" bind:checked={idpForm.enabled} />
				Enabled
			</label>
		</div>
		<div class="modal-actions">
			<button type="button" class="btn btn-secondary" onclick={() => (showAddIdp = false)}>Cancel</button>
			<button type="submit" class="btn btn-primary" disabled={idpSaving}>{idpSaving ? 'Adding...' : 'Add Provider'}</button>
		</div>
	</form>
</Modal>

<!-- Edit IdP Modal -->
<Modal open={showEditIdp} title="Edit Identity Provider" onclose={() => (showEditIdp = false)}>
	{#if editIdpError}<div class="modal-error">{editIdpError}</div>{/if}
	<form onsubmit={(e) => { e.preventDefault(); handleEditIdp(); }}>
		<div class="form-group">
			<label for="edit-idp-id">Client ID (leave empty to keep current)</label>
			<input id="edit-idp-id" type="text" bind:value={editIdpForm.client_id} />
		</div>
		<div class="form-group">
			<label for="edit-idp-secret">Client Secret (leave empty to keep current)</label>
			<input id="edit-idp-secret" type="password" bind:value={editIdpForm.client_secret} />
		</div>
		<div class="form-group">
			<label for="edit-idp-domains">Allowed Email Domains</label>
			<input id="edit-idp-domains" type="text" bind:value={editIdpForm.allowed_email_domains} />
		</div>
		<div class="form-group checkbox-group">
			<label>
				<input type="checkbox" bind:checked={editIdpForm.enabled} />
				Enabled
			</label>
		</div>
		<div class="modal-actions">
			<button type="button" class="btn btn-secondary" onclick={() => (showEditIdp = false)}>Cancel</button>
			<button type="submit" class="btn btn-primary" disabled={idpSaving}>{idpSaving ? 'Saving...' : 'Save'}</button>
		</div>
	</form>
</Modal>

<!-- Delete IdP -->
<Modal open={showDeleteIdp} title="Delete Identity Provider" onclose={() => (showDeleteIdp = false)}>
	<p class="confirm-text">Are you sure you want to remove the <strong>{deleteIdpTarget?.display_name}</strong> identity provider?</p>
	<div class="modal-actions">
		<button class="btn btn-secondary" onclick={() => (showDeleteIdp = false)}>Cancel</button>
		<button class="btn btn-danger" onclick={handleDeleteIdp}>Delete</button>
	</div>
</Modal>

<style>
	.page { max-width: 900px; }
	h1 { font-size: 1.75rem; font-weight: 600; margin-bottom: 1.5rem; }
	.card { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
	.card h2 { font-size: 1rem; font-weight: 600; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1rem; }
	.card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
	.card-header h2 { margin-bottom: 0; }

	.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
	.form-group { margin-bottom: 0; }
	.form-group label { display: block; font-size: 0.8rem; font-weight: 500; color: var(--color-text-muted); margin-bottom: 0.3rem; text-transform: uppercase; letter-spacing: 0.04em; }
	.form-group input, .form-group select { width: 100%; padding: 0.5rem 0.75rem; background: var(--color-bg); border: 1px solid var(--color-border); border-radius: 6px; color: var(--color-text); font-size: 0.9rem; }
	.form-group input:disabled { opacity: 0.5; cursor: not-allowed; }
	.form-group input[type="password"] { font-family: var(--font-mono); }
	.mono { font-family: var(--font-mono); font-size: 0.85rem; }

	.toggle-row { display: flex; flex-direction: column; gap: 0.3rem; margin-bottom: 1rem; }
	.toggle-label { display: flex; align-items: center; gap: 0.5rem; font-size: 0.95rem; cursor: pointer; }
	.toggle-label input { accent-color: var(--color-primary); }
	.toggle-desc { font-size: 0.8rem; color: var(--color-text-muted); padding-left: 1.5rem; }
	.save-row { display: flex; justify-content: flex-end; }

	.checkbox-group label { display: flex; align-items: center; gap: 0.5rem; font-size: 0.9rem; text-transform: none; letter-spacing: 0; color: var(--color-text); cursor: pointer; }
	.checkbox-group input[type="checkbox"] { width: auto; accent-color: var(--color-primary); }

	.loading-card { display: flex; align-items: center; gap: 0.75rem; padding: 2rem; color: var(--color-text-muted); }
	.spinner { width: 18px; height: 18px; border: 2px solid var(--color-border); border-top-color: var(--color-primary); border-radius: 50%; animation: spin 0.6s linear infinite; }
	@keyframes spin { to { transform: rotate(360deg); } }

	.error-msg { background: rgba(239,68,68,0.1); border: 1px solid var(--color-danger); color: var(--color-danger); padding: 0.5rem 1rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.9rem; }
	.success-msg { background: rgba(34,197,94,0.1); border: 1px solid var(--color-success); color: var(--color-success); padding: 0.5rem 1rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.9rem; }
	.muted { color: var(--color-text-muted); font-size: 0.85rem; }
	.read-only { font-size: 0.8rem; color: var(--color-text-muted); font-style: italic; }

	.row-actions { display: flex; gap: 0.5rem; }
	.btn-sm { padding: 0.25rem 0.6rem; font-size: 0.8rem; border-radius: 4px; border: none; cursor: pointer; background: var(--color-border); color: var(--color-text); }
	.btn-sm:hover { opacity: 0.8; }
	.btn-danger { background: var(--color-danger); color: white; }
	.btn { padding: 0.6rem 1.25rem; border-radius: 6px; font-size: 0.9rem; font-weight: 500; cursor: pointer; border: none; transition: background 0.15s, opacity 0.15s; }
	.btn-primary { background: var(--color-primary); color: white; }
	.btn-primary:hover { background: var(--color-primary-hover); }
	.btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
	.btn-secondary { background: var(--color-border); color: var(--color-text); }
	.modal-actions { display: flex; justify-content: flex-end; gap: 0.75rem; margin-top: 1.5rem; }
	.modal-error { background: rgba(239,68,68,0.1); border: 1px solid var(--color-danger); color: var(--color-danger); padding: 0.5rem 0.75rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.85rem; }
	.confirm-text { color: var(--color-text-muted); margin-bottom: 0.5rem; }
</style>

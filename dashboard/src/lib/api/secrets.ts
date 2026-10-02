/**
 * Dashboard secret-management API client.
 *
 * Detail (`GET /v1/secrets/{name}`), reveal, restore, put, and delete are
 * gated by `SessionAuth` server-side — bearer API keys are rejected. The
 * list endpoint (`GET /v1/secrets`) also accepts bearer for agents but
 * returns a narrow `{name, version_count, last_rotated_at}` shape with
 * no values; this client only ever calls it with the dashboard session
 * cookie, which gets the full `SecretSummary` shape (SPEC §6).
 */
import { session } from '$lib/session';
import type {
	SecretDetail,
	SecretReveal,
	SecretSummary
} from '$lib/types';

/**
 * Which vault a request addresses. Secret names are unique per vault, not per
 * org: omitted means the caller's own; `owner` names a user's vault and
 * `scope: 'org'` the org-wide one (both admin-only unless it is your own).
 */
export type SecretVault = { owner?: string | null; scope?: 'org' };

/** `?owner=` / `?scope=` for a vault selector, with its leading `?`/`&`. */
function vaultQuery(v: SecretVault | undefined, sep: '?' | '&' = '?'): string {
	if (!v) return '';
	if (v.scope === 'org') return `${sep}scope=org`;
	if (v.owner) return `${sep}owner=${encodeURIComponent(v.owner)}`;
	return '';
}

/** The vault selector for a secret row as the list returned it. */
export function vaultOf(s: SecretSummary): SecretVault {
	return s.scope === 'org' ? { scope: 'org' } : { owner: s.owner_identity_id };
}

export const listSecrets = (vault?: SecretVault, signal?: AbortSignal) =>
	session.get<SecretSummary[]>(`/v1/secrets${vaultQuery(vault)}`, signal);

export const getSecret = (name: string, vault?: SecretVault, signal?: AbortSignal) =>
	session.get<SecretDetail>(
		`/v1/secrets/${encodeURIComponent(name)}${vaultQuery(vault)}`,
		signal
	);

/**
 * Create or update a secret. Each call appends a new version; the previous
 * one stays restorable.
 */
export const putSecret = (
	name: string,
	value: string,
	on_behalf_of?: string,
	vault?: SecretVault
) =>
	session.put<{ name: string; version: number }>(
		`/v1/secrets/${encodeURIComponent(name)}${vaultQuery(vault)}`,
		on_behalf_of ? { value, on_behalf_of } : { value }
	);

/**
 * Reveal a specific version's plaintext. Server records `secret.revealed`
 * in the audit log on success.
 */
export const revealSecretVersion = (name: string, version: number, vault?: SecretVault) =>
	session.post<SecretReveal>(
		`/v1/secrets/${encodeURIComponent(name)}/versions/${version}/reveal${vaultQuery(vault)}`,
		{}
	);

/**
 * Restore an old version: server creates a new version pointing at the
 * old value (the original is never deleted). Audit-logged as
 * `secret.restored`.
 */
export const restoreSecretVersion = (name: string, version: number, vault?: SecretVault) =>
	session.post<{ name: string; version: number }>(
		`/v1/secrets/${encodeURIComponent(name)}/versions/${version}/restore${vaultQuery(vault)}`,
		{}
	);

export const deleteSecret = (name: string, vault?: SecretVault) =>
	session.delete<{ deleted: boolean }>(
		`/v1/secrets/${encodeURIComponent(name)}${vaultQuery(vault)}`
	);

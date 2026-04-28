/**
 * Dashboard secret-management API client.
 *
 * Every endpoint here is gated by `SessionAuth` server-side — bearer API
 * keys are rejected, so secret values never leak to agent runtimes via
 * the API surface (SPEC §6).
 */
import { session } from '$lib/session';
import type {
	SecretDetail,
	SecretReveal,
	SecretSummary
} from '$lib/types';

export const listSecrets = (signal?: AbortSignal) =>
	session.get<SecretSummary[]>('/v1/secrets', signal);

export const getSecret = (name: string, signal?: AbortSignal) =>
	session.get<SecretDetail>(`/v1/secrets/${encodeURIComponent(name)}`, signal);

/**
 * Create or update a secret. Each call appends a new version; the previous
 * one stays restorable.
 */
export const putSecret = (
	name: string,
	value: string,
	on_behalf_of?: string
) =>
	session.put<{ name: string; version: number }>(
		`/v1/secrets/${encodeURIComponent(name)}`,
		on_behalf_of ? { value, on_behalf_of } : { value }
	);

/**
 * Reveal a specific version's plaintext. Server records `secret.revealed`
 * in the audit log on success.
 */
export const revealSecretVersion = (name: string, version: number) =>
	session.post<SecretReveal>(
		`/v1/secrets/${encodeURIComponent(name)}/versions/${version}/reveal`,
		{}
	);

/**
 * Restore an old version: server creates a new version pointing at the
 * old value (the original is never deleted). Audit-logged as
 * `secret.restored`.
 */
export const restoreSecretVersion = (name: string, version: number) =>
	session.post<{ name: string; version: number }>(
		`/v1/secrets/${encodeURIComponent(name)}/versions/${version}/restore`,
		{}
	);

export const deleteSecret = (name: string) =>
	session.delete<{ deleted: boolean }>(`/v1/secrets/${encodeURIComponent(name)}`);

/**
 * Shared credential-status resolver for a service instance.
 *
 * The backend's `credentials_status` is the source of truth: its
 * `compute_credentials_status` resolves the connection the *execution* path
 * would actually use — an explicit binding, or an OAuth template's provider
 * auto-resolved on the owner identity — so it stays correct for instances that
 * work without an explicit `connection_id` bind, and for agent-owned
 * connections that never appear in the caller's personal connection list (see
 * PR #321). We therefore trust it regardless of `connection_id` and only fall
 * back to the structural heuristic when the field is absent (template not
 * resolvable, or a pre-`credentials_status` API). The `connections` argument is
 * no longer consulted (kept for signature stability).
 */
import type { ConnectionSummary, ServiceInstanceSummary } from '$lib/types';

export type CredentialStatus =
	| 'connected'
	| 'needs-setup'
	| 'needs-reconnect'
	| 'partially-degraded';

export function credentialStatus(
	instance: ServiceInstanceSummary,
	_connections: ConnectionSummary[] | Set<string>
): CredentialStatus {
	switch (instance.credentials_status) {
		case 'ok':
			return 'connected';
		case 'needs_reconnect':
			return 'needs-reconnect';
		case 'partially_degraded':
			return 'partially-degraded';
		case 'needs_authentication':
			// No usable connection (unbound and no provider connection, or a
			// dangling/deleted bound one) — the backend asks for auth.
			return 'needs-setup';
	}
	// `credentials_status` absent: classify structurally.
	if (instance.connection_id) return 'connected';
	if (instance.secret_name) return 'connected';
	return 'needs-setup';
}

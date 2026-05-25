/**
 * Shared credential-status resolver for a service instance. A service is
 * "connected" when it has a connection bound to it OR a secret name set.
 * `needs-reconnect` and `partially-degraded` come from the backend's
 * scope-health classifier (see routes/services.rs::classify_scopes) — no
 * action will work when the bound connection doesn't cover any of the
 * template's required scopes. The backend's `credentials_status` field is
 * authoritative whenever a connection is bound; the `connections` argument
 * is no longer consulted (kept for signature stability) so agent-owned
 * connections — which never appear in the calling user's personal list —
 * are classified correctly.
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
	if (instance.connection_id) {
		switch (instance.credentials_status) {
			case 'needs_reconnect':
				return 'needs-reconnect';
			case 'partially_degraded':
				return 'partially-degraded';
			case 'needs_authentication':
				// Connection bound but unresolvable org-scoped (dangling/deleted) —
				// the backend asks for re-auth, so don't paint it connected.
				return 'needs-setup';
			default:
				// 'ok', or an absent field (template has no OAuth scheme to
				// classify, or a benign gap): a bound connection is connected.
				return 'connected';
		}
	}
	if (instance.secret_name) return 'connected';
	return 'needs-setup';
}

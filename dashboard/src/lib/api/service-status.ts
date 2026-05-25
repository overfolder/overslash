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
			case 'ok':
				return 'connected';
			case 'needs_reconnect':
				return 'needs-reconnect';
			case 'partially_degraded':
				return 'partially-degraded';
			case 'needs_authentication':
				// Connection bound but unresolvable org-scoped (dangling/deleted) —
				// the backend asks for re-auth, so don't paint it connected.
				return 'needs-setup';
			default:
				// Field absent: the backend couldn't classify (template resolution
				// failed, or a non-OAuth template carries a connection). Fall through
				// to the secret-name / needs-setup checks rather than masking it.
				break;
		}
	}
	if (instance.secret_name) return 'connected';
	return 'needs-setup';
}

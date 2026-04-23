/**
 * Shared credential-status resolver for a service instance. A service is
 * "connected" when it has a live OAuth connection bound to it OR a secret
 * name set. `needs-reconnect` and `partially-degraded` come from the backend's
 * scope-health classifier (see routes/services.rs::classify_scopes) — no
 * action will work when the bound connection doesn't cover any of the
 * template's required scopes. Kept in a single place so the Services table
 * and the API Explorer picker agree.
 */
import type { ConnectionSummary, ServiceInstanceSummary } from '$lib/types';

export type CredentialStatus =
	| 'connected'
	| 'needs-setup'
	| 'needs-reconnect'
	| 'partially-degraded';

export function credentialStatus(
	instance: ServiceInstanceSummary,
	connections: ConnectionSummary[] | Set<string>
): CredentialStatus {
	const ids =
		connections instanceof Set ? connections : new Set(connections.map((c) => c.id));
	if (instance.connection_id && ids.has(instance.connection_id)) {
		if (instance.credentials_status === 'needs_reconnect') return 'needs-reconnect';
		if (instance.credentials_status === 'partially_degraded') return 'partially-degraded';
		return 'connected';
	}
	if (instance.secret_name) return 'connected';
	return 'needs-setup';
}

/**
 * Shared credential-status resolver for a service instance. A service is
 * "connected" when it has a live OAuth connection bound to it OR a secret
 * name set. Kept in a single place so the Services table and the API
 * Explorer picker agree.
 */
import type { ConnectionSummary, ServiceInstanceSummary } from '$lib/types';

export type CredentialStatus = 'connected' | 'needs-setup';

export function credentialStatus(
	instance: ServiceInstanceSummary,
	connections: ConnectionSummary[] | Set<string>
): CredentialStatus {
	const ids =
		connections instanceof Set ? connections : new Set(connections.map((c) => c.id));
	if (instance.connection_id && ids.has(instance.connection_id)) return 'connected';
	if (instance.secret_name) return 'connected';
	return 'needs-setup';
}

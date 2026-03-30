import type { ConnectionSummary, ConnectionStatus, ServiceSummary, ServiceWithConnection } from './types';

/** Map of service keys to their OAuth provider names. Only OAuth services are included;
 *  API-key-only services (stripe, resend) are intentionally excluded. */
const PROVIDER_MAP: Record<string, string> = {
  github: 'github',
  google_calendar: 'google',
  slack: 'slack',
  x: 'x',
  eventbrite: 'eventbrite'
};

export function getConnectionStatus(connection: ConnectionSummary | null): ConnectionStatus {
  if (!connection) return 'disconnected';
  if (connection.token_expires_at) {
    const expiresAt = new Date(connection.token_expires_at);
    if (expiresAt < new Date()) return 'expired';
  }
  return 'connected';
}

export function mergeServicesWithConnections(
  services: ServiceSummary[],
  connections: ConnectionSummary[]
): ServiceWithConnection[] {
  const connectionsByProvider = new Map<string, ConnectionSummary>();
  for (const conn of connections) {
    if (!connectionsByProvider.has(conn.provider_key)) {
      connectionsByProvider.set(conn.provider_key, conn);
    }
  }

  return services.map((service) => {
    const oauthProvider = PROVIDER_MAP[service.key] ?? null;
    const connection = oauthProvider ? (connectionsByProvider.get(oauthProvider) ?? null) : null;
    return {
      service,
      connection,
      status: getConnectionStatus(connection),
      oauthProvider
    };
  });
}

export function formatRelativeDate(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays === 0) return 'Today';
  if (diffDays === 1) return 'Yesterday';
  if (diffDays < 30) return `${diffDays}d ago`;
  if (diffDays < 365) return `${Math.floor(diffDays / 30)}mo ago`;
  return `${Math.floor(diffDays / 365)}y ago`;
}

export function formatExpiry(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = date.getTime() - now.getTime();

  if (diffMs < 0) return 'Expired';
  const diffMins = Math.floor(diffMs / (1000 * 60));
  if (diffMins < 60) return `${diffMins}m`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d`;
}

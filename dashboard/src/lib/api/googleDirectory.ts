/**
 * Typed client for /v1/google-directory — the org's Google Workspace
 * Directory connection and its group sync. There is no per-org credential:
 * the instance has one service account, which a Workspace admin authorises in
 * admin.google.com before connecting by signing in with Google.
 * See crates/overslash-api/src/routes/google_directory.rs.
 */
import { session } from '$lib/session';

export interface GoogleDirectorySyncStats {
	groups: number;
	identities: number;
	matched: number;
	added: number;
	removed: number;
}

/** What a Workspace admin must add under Domain-wide delegation. */
export interface GoogleDirectoryInstance {
	/** The instance operator configured a service account. */
	available: boolean;
	/** The "Client ID" to paste. Numeric; not a secret. */
	client_id?: string | null;
	/** The service account that client ID belongs to. */
	service_account_email?: string | null;
	/** The exact "OAuth scopes" value to paste. */
	scope: string;
}

export interface GoogleDirectoryConfig {
	/** The Workspace's primary domain, as Google reported it at connect. */
	domain: string;
	/** The Workspace admin the service account acts as — whoever connected. */
	admin_subject: string;
	connected_at: string;
	enabled: boolean;
	sync_interval_hours: number;
	next_sync_at: string;
	/** A manual run is waiting for a worker. At most one can be. */
	queued: boolean;
	/** A worker is sweeping right now. */
	running: boolean;
	last_sync_started_at?: string | null;
	last_sync_finished_at?: string | null;
	last_sync_status?: 'ok' | 'error' | null;
	last_sync_error?: string | null;
	last_sync_stats?: GoogleDirectorySyncStats | null;
}

export interface GoogleDirectoryState {
	instance: GoogleDirectoryInstance;
	/** `null` until the org connects a Workspace. */
	config: GoogleDirectoryConfig | null;
}

/** Why a connect was refused — the `google_directory_error` the callback
 *  redirects back with. */
export const CONNECT_ERRORS: Record<string, string> = {
	expired: 'That sign-in link expired or was already used. Start again.',
	cancelled: 'The Google sign-in was cancelled. Nothing was connected.',
	wrong_session:
		'The Google sign-in finished in a different Overslash session than the one that started it. Start again from this page.',
	not_workspace:
		'That Google account is not part of a Google Workspace or Cloud Identity organization. Sign in with a Workspace admin account.',
	email_unverified: 'Google did not confirm that account’s email address.',
	not_primary_domain:
		'That account is on a secondary domain. Sign in with an admin account on the Workspace’s primary domain.',
	domain_taken: 'Another organization on this Overslash instance has already connected that Workspace.',
	delegation_missing:
		'Google refused Overslash’s service account for that Workspace. Add the client ID and scope below under Domain-wide delegation (it can take a few minutes to apply), then try again.',
	not_admin:
		'That account can’t read the Workspace’s groups. Sign in as a super admin, or an admin with the Groups privilege.',
	google_error: 'Google returned an error. Try again in a moment.'
};

export const googleDirectoryApi = {
	get: (signal?: AbortSignal) =>
		session.get<GoogleDirectoryState>('/v1/google-directory', signal),
	/** Returns the Google URL to send the browser to. */
	connect: () => session.post<{ auth_url: string }>('/v1/google-directory/connect'),
	update: (body: { enabled?: boolean; sync_interval_hours?: number }) =>
		session.put<GoogleDirectoryConfig>('/v1/google-directory', body),
	disconnect: () => session.delete<{ deleted: boolean }>('/v1/google-directory'),
	/** Queue one run. `already_queued` when a run was waiting already. */
	sync: () =>
		session.post<{ queued: boolean; already_queued?: boolean }>('/v1/google-directory/sync')
};

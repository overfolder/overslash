/**
 * Typed client for /v1/google-directory — the org's Google Workspace
 * Directory credential and its group sync.
 * See crates/overslash-api/src/routes/google_directory.rs.
 */
import { ApiError, session } from '$lib/session';

export interface GoogleDirectorySyncStats {
	groups: number;
	identities: number;
	matched: number;
	added: number;
	removed: number;
}

export interface GoogleDirectoryConfig {
	service_account_email: string;
	service_account_key_id: string;
	admin_subject: string;
	customer_id: string;
	domains: string[];
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
	/** The scope to grant in Google's domain-wide delegation screen. */
	scope: string;
	created_at: string;
	updated_at: string;
}

export interface PutGoogleDirectoryRequest {
	service_account_json?: string;
	admin_subject?: string;
	customer_id?: string;
	domains?: string[];
	enabled?: boolean;
	sync_interval_hours?: number;
}

export const googleDirectoryApi = {
	/** `null` when the org has not configured it. */
	get: async (signal?: AbortSignal): Promise<GoogleDirectoryConfig | null> => {
		try {
			return await session.get<GoogleDirectoryConfig>('/v1/google-directory', signal);
		} catch (e) {
			if (e instanceof ApiError && e.status === 404) return null;
			throw e;
		}
	},
	put: (body: PutGoogleDirectoryRequest) =>
		session.put<GoogleDirectoryConfig>('/v1/google-directory', body),
	delete: () => session.delete<{ deleted: boolean }>('/v1/google-directory'),
	/** Queue one run. `already_queued` when a run was waiting already. */
	sync: () =>
		session.post<{ queued: boolean; already_queued?: boolean }>('/v1/google-directory/sync')
};

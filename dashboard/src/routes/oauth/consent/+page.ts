import type { PageLoad } from './$types';
import { session, ApiError } from '$lib/session';

export const ssr = false;
export const prerender = false;

export interface ConsentClientInfo {
	client_name: string | null;
	software_id: string | null;
	software_version: string | null;
}

export interface ConsentConnectionInfo {
	ip: string | null;
}

export interface ConsentParentOption {
	id: string;
	name: string;
	kind: string;
	is_you: boolean;
}

export interface ConsentGroupOption {
	id: string;
	name: string;
	member_count: number;
}

export interface ConsentReauthTarget {
	agent_id: string;
	agent_name: string;
	parent_id: string | null;
	parent_name: string | null;
	last_seen_at: string | null;
}

export interface ConsentContext {
	request_id: string;
	user_email: string;
	client: ConsentClientInfo;
	connection: ConsentConnectionInfo;
	mode: 'new' | 'reauth';
	reauth_target: ConsentReauthTarget | null;
	suggested_agent_name: string;
	parents: ConsentParentOption[];
	groups: ConsentGroupOption[];
}

type LoadResult =
	| { state: 'ready'; context: ConsentContext }
	| { state: 'expired' }
	| { state: 'error'; message: string };

export const load: PageLoad = async ({ url }): Promise<LoadResult> => {
	const request_id = url.searchParams.get('request_id');
	if (!request_id) {
		return {
			state: 'error',
			message: 'Missing request_id. Restart the sign-in from your MCP client.'
		};
	}
	try {
		const context = await session.get<ConsentContext>(
			`/v1/oauth/consent/${encodeURIComponent(request_id)}`
		);
		return { state: 'ready', context };
	} catch (e) {
		if (e instanceof ApiError) {
			if (e.status === 404) return { state: 'expired' };
			if (e.status === 403) {
				return {
					state: 'error',
					message:
						"You're signed in as a different user than started this authorization."
				};
			}
		}
		return {
			state: 'error',
			message: "We couldn't load this authorization request. Try again."
		};
	}
};

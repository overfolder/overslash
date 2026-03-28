import type { Handle } from '@sveltejs/kit';
import type { User } from '$lib/types';

const API_URL = process.env.API_URL ?? 'http://localhost:3000';

export const handle: Handle = async ({ event, resolve }) => {
	const session = event.cookies.get('oss_session');

	if (session) {
		try {
			const res = await fetch(`${API_URL}/auth/me`, {
				headers: { Cookie: `oss_session=${session}` },
			});
			if (res.ok) {
				event.locals.user = (await res.json()) as User;
			} else {
				event.locals.user = null;
			}
		} catch {
			event.locals.user = null;
		}
	} else {
		event.locals.user = null;
	}

	return resolve(event);
};

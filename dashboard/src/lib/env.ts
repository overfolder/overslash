// Which deployment environment the dashboard is talking to.
//
// The client never gets told its environment directly — the API base is
// resolved server-side by `vercel.json` rewrites keyed on the request Host
// header. So we derive it the same way `vercel.json` routes: from the
// hostname. Production is the only allowlisted "silent" environment; anything
// we don't positively recognise as prod is treated as non-prod so the
// environment ribbon / dev favicon fail loud rather than silent.

export type AppEnv = {
	/** Short label for display, e.g. "dev", "preview", "local", "production". */
	name: string;
	isProd: boolean;
};

/**
 * Map a hostname to an environment. Pure — safe to call anywhere.
 *
 * Mirrors the host patterns in `dashboard/vercel.json`:
 *   app.overslash.com / *.app.overslash.com  → prod
 *   *.app.dev.overslash.com / everything else → dev (the fallback backend)
 */
export function environmentFromHost(hostname: string): AppEnv {
	const h = hostname.toLowerCase();

	const isProd =
		(h === 'app.overslash.com' || h.endsWith('.app.overslash.com')) && !h.includes('.dev.');
	if (isProd) return { name: 'production', isProd: true };

	let name = 'dev';
	if (h === 'localhost' || h === '127.0.0.1' || h.endsWith('.local')) name = 'local';
	else if (h.endsWith('.vercel.app')) name = 'preview';
	else if (h.includes('dev.overslash.com')) name = 'dev';

	return { name, isProd: false };
}

/** Browser-only convenience — callers must guard with `browser` from `$app/environment`. */
export function currentEnvironment(): AppEnv {
	return environmentFromHost(window.location.hostname);
}

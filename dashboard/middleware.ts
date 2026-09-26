// Vercel Routing Middleware: vouch for the requests this deployment proxies
// to the API.
//
// vercel.json rewrites /v1, /auth, /oauth, ... to the API. Vercel overwrites
// X-Forwarded-For with the browser's address, but then connects to the API
// from its own egress, which has no published range the API could trust. So
// the API would record Vercel's address as the client. Instead, stamp a
// shared secret the API is configured with (OVERSLASH_TRUSTED_PROXY_SECRET):
// a match lets it trust exactly one more hop and read the browser's address.
// See infra/README.md "Client IP & trusted proxies".
//
// Always *set* the header, never pass one through: a browser-supplied value
// must not reach the API. With the env var unset, the header is stripped.
//
// Only Vercel runs this. The self-hosted build (ADAPTER=static) has the API
// serve the dashboard itself, with no proxy hop to vouch for.

import { next } from '@vercel/functions/middleware';

const SECRET_HEADER = 'x-overslash-proxy-secret';

// Exactly the sources vercel.json rewrites to the API. Page requests don't
// pay for the middleware.
export const config = {
	matcher: [
		'/v1/:path*',
		'/auth/:path*',
		'/oauth/:path*',
		'/mcp',
		'/.well-known/:path*',
		'/connect-authorize',
		'/health',
		'/icons/:path*',
		'/SKILL.md',
		'/public/:path*'
	]
};

export default function middleware(request: Request): Response {
	const headers = new Headers(request.headers);
	const secret = process.env.OVERSLASH_PROXY_SECRET;
	if (secret) {
		headers.set(SECRET_HEADER, secret);
	} else {
		headers.delete(SECRET_HEADER);
	}
	return next({
		request: { headers },
		// Non-secret marker so a deploy can be checked with a plain curl:
		// `1` = the secret was stamped, `0` = the env var is unset.
		headers: { 'x-overslash-proxy-mw': secret ? '1' : '0' }
	});
}

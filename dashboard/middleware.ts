// Vercel Routing Middleware: vouch for the requests this deployment proxies
// to the API.
//
// vercel.json rewrites /v1, /auth, /oauth, ... to the API. Vercel connects to
// the API from its own egress, which has no published range the API could
// trust, so the API would record Vercel's address as the client. Instead,
// stamp a shared secret, OVERSLASH_TRUSTED_PROXY_SECRET (the same variable
// name the API reads, holding the same value), plus the client address this
// middleware saw in x-overslash-client-ip. A secret match makes the API
// record that address. See infra/README.md "Client IP & trusted proxies".
//
// Not X-Forwarded-For. On the upstream request to an external rewrite,
// Vercel forwards the browser's own X-Forwarded-For and does not reliably
// apply a middleware override of it (measured on dev: the same forged
// header was replaced on one request and passed through on the next). The
// request this middleware sees is sanitized, though: x-real-ip is always the
// connecting address, whatever the browser sent. So the address is carried
// in a header of our own, and the API never reads XFF past this hop.
//
// Both headers are always *set*, never passed through, and without an
// address to report neither is sent.
//
// Only Vercel runs this. The self-hosted build (ADAPTER=static) has the API
// serve the dashboard itself, with no proxy hop to vouch for.

import { ipAddress } from '@vercel/functions/headers';
import { next } from '@vercel/functions/middleware';

const SECRET_HEADER = 'x-overslash-proxy-secret';
const CLIENT_IP_HEADER = 'x-overslash-client-ip';

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
	const client = ipAddress(request);
	const secret = client ? process.env.OVERSLASH_TRUSTED_PROXY_SECRET : undefined;
	if (client && secret) {
		headers.set(CLIENT_IP_HEADER, client);
		headers.set(SECRET_HEADER, secret);
	} else {
		headers.delete(CLIENT_IP_HEADER);
		headers.delete(SECRET_HEADER);
	}
	return next({
		request: { headers },
		// Non-secret marker so a deploy can be checked with a plain curl:
		// `1` = the secret was stamped, `0` = it wasn't (env var unset, or no
		// client address to vouch for).
		headers: { 'x-overslash-proxy-mw': secret ? '1' : '0' }
	});
}

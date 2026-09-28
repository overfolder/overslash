/**
 * Whether a service endpoint the user typed is plain `http://`.
 *
 * The API refuses those (CASA 4.1.1): every request to a service endpoint can
 * carry a vault credential, so it goes over TLS. The one exception — a
 * self-hosted deployment that allow-lists its own private network with
 * `OVERSLASH_SSRF_ALLOWED_CIDRS` — is deployment configuration the dashboard
 * cannot see, so this is a heads-up next to the input, not a gate: the save
 * still goes to the server, and the server's answer is the one shown.
 */
export function isPlaintextEndpoint(url: string | null | undefined): boolean {
	return /^\s*http:\/\//i.test(url ?? '');
}

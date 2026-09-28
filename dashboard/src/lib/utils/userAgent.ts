/**
 * A short "Browser on OS" label for a session's User-Agent. Best effort: the
 * raw string is still shown on hover, and anything unrecognised falls back to
 * it (trimmed) rather than guessing.
 */
export function describeUserAgent(ua: string | null | undefined): string {
	if (!ua) return 'Unknown device';
	// Order matters: Edge and Opera also claim Chrome; Chrome also claims Safari.
	const browser = /Edg\//.test(ua)
		? 'Edge'
		: /OPR\//.test(ua)
			? 'Opera'
			: /Firefox\//.test(ua)
				? 'Firefox'
				: /Chrome\//.test(ua)
					? 'Chrome'
					: /Safari\//.test(ua)
						? 'Safari'
						: null;
	const os = /iPhone|iPad/.test(ua)
		? 'iOS'
		: /Android/.test(ua)
			? 'Android'
			: /Mac OS X|Macintosh/.test(ua)
				? 'macOS'
				: /Windows/.test(ua)
					? 'Windows'
					: /CrOS/.test(ua)
						? 'ChromeOS'
						: /Linux/.test(ua)
							? 'Linux'
							: null;
	if (browser && os) return `${browser} on ${os}`;
	if (browser || os) return (browser ?? os) as string;
	return ua.length > 60 ? `${ua.slice(0, 57)}…` : ua;
}

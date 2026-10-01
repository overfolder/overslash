import type { InstanceConfigParam } from '$lib/types';

// Which per-instance fields the service form shows up front, and which it
// keeps behind "Show more options". Every endpoint and config field can be
// overridden; this only decides prominence. A field is up front when the
// instance cannot work without it (required, and nothing — template or org
// layer — supplies a default), or when the template promotes it
// (`x-overslash-promoted`).

export interface EndpointFacts {
	configurable: boolean;
	/** The template's own default endpoint. */
	defaultUrl?: string;
	/** An org layer's default endpoint, which wins over the template's. */
	inheritedUrl?: string;
	promoted: boolean;
}

/** True when the endpoint has no fallback, so leaving it blank breaks the instance. */
export function endpointRequired(e: EndpointFacts): boolean {
	return e.configurable && !e.defaultUrl && !e.inheritedUrl;
}

export function endpointIsMain(e: EndpointFacts): boolean {
	return e.configurable && (e.promoted || endpointRequired(e));
}

export function paramIsMain(
	p: InstanceConfigParam,
	inherited: Record<string, string> | undefined
): boolean {
	return !!p.promoted || (!!p.required && !p.default && !inherited?.[p.name]);
}

export function splitParams(
	params: InstanceConfigParam[],
	inherited: Record<string, string> | undefined
): { main: InstanceConfigParam[]; more: InstanceConfigParam[] } {
	const main: InstanceConfigParam[] = [];
	const more: InstanceConfigParam[] = [];
	for (const p of params) (paramIsMain(p, inherited) ? main : more).push(p);
	return { main, more };
}

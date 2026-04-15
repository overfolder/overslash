import { stringify as yamlStringify, parse as yamlParse } from 'yaml';
import type { TemplateDetail } from '$lib/types';

export function templateToYaml(t: TemplateDetail): string {
	return yamlStringify({
		key: t.key,
		display_name: t.display_name,
		description: t.description ?? '',
		category: t.category ?? '',
		hosts: t.hosts,
		auth: t.auth,
		actions: t.actions
	});
}

/**
 * Parse YAML into a TemplateDetail, rejecting malformed input at the boundary
 * rather than silently coercing it. Returns null only on YAML syntax errors
 * or when the top-level value isn't an object with the required fields.
 */
export function yamlToTemplate(
	yaml: string,
	base: TemplateDetail
): TemplateDetail | null {
	try {
		const parsed = yamlParse(yaml);
		if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;

		// Reject if required string fields are wrong type
		if (parsed.key !== undefined && typeof parsed.key !== 'string') return null;
		if (parsed.display_name !== undefined && typeof parsed.display_name !== 'string') return null;

		// Reject if structural fields are wrong type
		if (parsed.hosts !== undefined && !Array.isArray(parsed.hosts)) return null;
		if (parsed.auth !== undefined && !Array.isArray(parsed.auth)) return null;
		if (
			parsed.actions !== undefined &&
			(typeof parsed.actions !== 'object' || Array.isArray(parsed.actions))
		)
			return null;

		return {
			...base,
			key: parsed.key ?? base.key,
			display_name: parsed.display_name ?? base.display_name,
			description: parsed.description ?? null,
			category: parsed.category ?? null,
			hosts: parsed.hosts ?? base.hosts,
			auth: parsed.auth ?? base.auth,
			actions: parsed.actions ?? base.actions
		};
	} catch {
		return null;
	}
}

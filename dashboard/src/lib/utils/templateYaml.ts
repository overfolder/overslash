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

export function yamlToTemplate(
	yaml: string,
	base: TemplateDetail
): TemplateDetail | null {
	try {
		const parsed = yamlParse(yaml);
		if (!parsed || typeof parsed !== 'object') return null;
		const actions = parsed.actions;
		const validActions =
			actions && typeof actions === 'object' && !Array.isArray(actions)
				? actions
				: {};

		return {
			...base,
			key: parsed.key ?? base.key,
			display_name: parsed.display_name ?? base.display_name,
			description: parsed.description || null,
			category: parsed.category || null,
			hosts: Array.isArray(parsed.hosts) ? parsed.hosts : [],
			auth: Array.isArray(parsed.auth) ? parsed.auth : [],
			actions: validActions
		};
	} catch {
		return null;
	}
}

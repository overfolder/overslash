/**
 * Reading a param's declared `shape` for the API Explorer.
 *
 * The Explorer is the one place a person builds a call by hand, and before
 * shapes existed an `object` param gave them a blank textarea and a sentence of
 * prose. These helpers turn the schema the template already carries into the
 * two things that actually help: a skeleton to start from, and the same
 * complaint the server would have made, made now instead of after the round
 * trip.
 *
 * The checks deliberately mirror `validate_input`: required present, unknown
 * key, string enum — and no type rejection at any depth, because the server
 * does not reject on type either and a form that is stricter than the gateway
 * blocks calls the gateway would have run.
 */

import type { NestedParam, ParamShape } from '$lib/types';

/** One field of a shape, flattened for display with its path. */
export interface ShapeField {
	/** Dotted/indexed path relative to the param, e.g. `objects[].id`. */
	path: string;
	/** Nesting level, for indentation. */
	depth: number;
	type: string;
	required: boolean;
	description: string;
	enumValues?: string[];
}

/** Flatten a shape into the field list rendered under an object/array control. */
export function shapeFields(shape: ParamShape | undefined, depth = 0, prefix = ''): ShapeField[] {
	if (!shape || depth > 4) return [];
	const out: ShapeField[] = [];
	if (shape.properties) {
		// Required first, then alphabetical — the order the server projects and
		// the order someone filling the form wants.
		const entries = Object.entries(shape.properties).sort(([an, a], [bn, b]) => {
			if (!!a.required !== !!b.required) return a.required ? -1 : 1;
			return an.localeCompare(bn);
		});
		for (const [name, p] of entries) {
			const path = prefix ? `${prefix}.${name}` : name;
			out.push(toField(path, depth, p));
			out.push(...shapeFields(p.shape, depth + 1, path));
		}
	} else if (shape.items) {
		// An array's element has no name, so it is addressed by `[]` rather than
		// by an index nobody has chosen yet.
		const path = `${prefix}[]`;
		out.push(toField(path, depth, shape.items));
		out.push(...shapeFields(shape.items.shape, depth + 1, path));
	}
	return out;
}

function toField(path: string, depth: number, p: NestedParam): ShapeField {
	return {
		path,
		depth,
		type: p.type ?? '',
		required: !!p.required,
		description: p.description ?? '',
		enumValues: p.enum
	};
}

/**
 * A JSON skeleton for the declared shape, pretty-printed, for use as the
 * textarea's placeholder.
 *
 * Only *required* properties are filled in. A skeleton carrying every optional
 * field is a wall someone has to delete from, and the field list below the
 * control is where the optional ones are discoverable.
 */
export function skeletonFor(shape: ParamShape | undefined, type: string): string {
	// No declared shape, no skeleton. A bare `{}` is *less* informative than the
	// `JSON object` placeholder it would replace — it looks like a contract
	// ("this object takes no keys") rather than an absence of one.
	if (!shape) return '';
	const value = skeletonValue(shape, type, 0);
	return value === undefined ? '' : JSON.stringify(value, null, 2);
}

function skeletonValue(shape: ParamShape | undefined, type: string, depth: number): unknown {
	if (depth > 4) return null;
	if (shape?.properties) {
		const out: Record<string, unknown> = {};
		for (const [name, p] of Object.entries(shape.properties)) {
			if (!p.required) continue;
			out[name] = skeletonValue(p.shape, p.type ?? '', depth + 1);
		}
		return out;
	}
	if (shape?.items) {
		return [skeletonValue(shape.items.shape, shape.items.type ?? '', depth + 1)];
	}
	switch (type) {
		case 'object':
			return {};
		case 'array':
			return [];
		case 'integer':
		case 'number':
			return 0;
		case 'boolean':
			return false;
		default:
			return '';
	}
}

/**
 * Check a parsed value against a shape, returning the messages the server would
 * return. `relaxed` is the action's `additional_properties`; like the server, it
 * spreads inward and a sub-schema may open itself further but never re-close.
 */
export function shapeErrors(
	value: unknown,
	shape: ParamShape | undefined,
	relaxed: boolean,
	path: string
): string[] {
	if (!shape) return [];
	const out: string[] = [];
	if (shape.properties) {
		if (!isPlainObject(value)) return out;
		const open = relaxed || !!shape.additional_properties;
		for (const [name, p] of Object.entries(shape.properties)) {
			const at = `${path}.${name}`;
			const v = value[name];
			if (v === undefined || v === null) {
				if (p.required) out.push(`missing required argument \`${at}\``);
				continue;
			}
			out.push(...valueErrors(v, p, open, at));
		}
		if (!open) {
			for (const name of Object.keys(value)) {
				if (!(name in shape.properties)) {
					out.push(`unknown argument \`${path}.${name}\``);
				}
			}
		}
	} else if (shape.items) {
		if (!Array.isArray(value)) return out;
		value.forEach((element, i) => {
			if (element === null || element === undefined) return;
			out.push(...valueErrors(element, shape.items as NestedParam, relaxed, `${path}[${i}]`));
		});
	}
	return out;
}

function valueErrors(value: unknown, p: NestedParam, relaxed: boolean, at: string): string[] {
	const out: string[] = [];
	// An empty member list is not a constraint — the server reads it the same
	// way, because a numeric enum lowers to an empty list of strings.
	if (!relaxed && p.enum && p.enum.length > 0 && !(typeof value === 'string' && p.enum.includes(value))) {
		out.push(`argument \`${at}\` value \`${String(value)}\` is not one of: ${p.enum.join(', ')}`);
	}
	out.push(...shapeErrors(value, p.shape, relaxed, at));
	return out;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
	return typeof v === 'object' && v !== null && !Array.isArray(v);
}

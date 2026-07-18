/**
 * Shape a service instance's `credentials` / `config` map for the API.
 *
 * Both are whole-map replaces, and both treat a blank field as "not set"
 * rather than "set to empty": the server rejects an empty value outright, and
 * an empty string in the map would otherwise be a second way to spell unset.
 * So trim everything and drop what's left empty.
 *
 * Used by the create wizard (`/services/new`) and the edit page
 * (`/services/[id]`) for both maps — four call sites that must agree, since a
 * disagreement shows up as a field that silently refuses to clear.
 */
export function cleanServiceMap(input: Record<string, string>): Record<string, string> {
	return Object.fromEntries(
		Object.entries(input)
			.map(([k, v]) => [k, (v ?? '').trim()])
			.filter(([, v]) => v)
	);
}

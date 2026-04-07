export async function copyToClipboard(text: string): Promise<boolean> {
	try {
		if (typeof navigator !== 'undefined' && navigator.clipboard) {
			await navigator.clipboard.writeText(text);
			return true;
		}
	} catch {
		/* fall through */
	}
	return false;
}

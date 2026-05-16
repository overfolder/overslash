import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

const EU_COUNTRIES = new Set([
	'AT', 'BE', 'BG', 'CY', 'CZ', 'DE', 'DK', 'EE', 'ES', 'FI', 'FR', 'GR', 'HR', 'HU',
	'IE', 'IT', 'LT', 'LU', 'LV', 'MT', 'NL', 'PL', 'PT', 'RO', 'SE', 'SI', 'SK',
]);

export const GET: RequestHandler = ({ request }) => {
	// Vercel injects x-vercel-ip-country on all incoming requests.
	// CF-IPCountry is set by Cloudflare on the browser→Vercel leg but is not
	// forwarded when Vercel proxies onward to api.overslash.com, so we must
	// resolve geo here before the rewrite fires.
	const country =
		request.headers.get('x-vercel-ip-country') ??
		request.headers.get('CF-IPCountry') ??
		'';

	if (EU_COUNTRIES.has(country)) {
		return json({ currency: 'eur', base_price: 15 });
	}
	return json({ currency: 'usd', base_price: 20 });
};

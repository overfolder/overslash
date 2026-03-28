import type { Cookies } from '@sveltejs/kit';

const API_URL = process.env.API_URL ?? 'http://localhost:3000';

function headers(cookies: Cookies): HeadersInit {
	const session = cookies.get('oss_session');
	if (!session) return {};
	return { Cookie: `oss_session=${session}` };
}

async function handleResponse(res: Response) {
	if (!res.ok) {
		const body = await res.json().catch(() => ({ error: res.statusText }));
		throw new ApiError(res.status, body.error ?? res.statusText);
	}
	return res.json();
}

export class ApiError extends Error {
	constructor(
		public status: number,
		message: string
	) {
		super(message);
	}
}

export async function get<T>(path: string, cookies: Cookies): Promise<T> {
	const res = await fetch(`${API_URL}${path}`, { headers: headers(cookies) });
	return handleResponse(res) as Promise<T>;
}

export async function post<T>(path: string, cookies: Cookies, body?: unknown): Promise<T> {
	const res = await fetch(`${API_URL}${path}`, {
		method: 'POST',
		headers: { ...headers(cookies), 'Content-Type': 'application/json' },
		body: body ? JSON.stringify(body) : undefined,
	});
	return handleResponse(res) as Promise<T>;
}

export async function put<T>(path: string, cookies: Cookies, body?: unknown): Promise<T> {
	const res = await fetch(`${API_URL}${path}`, {
		method: 'PUT',
		headers: { ...headers(cookies), 'Content-Type': 'application/json' },
		body: body ? JSON.stringify(body) : undefined,
	});
	return handleResponse(res) as Promise<T>;
}

export async function del<T>(path: string, cookies: Cookies): Promise<T> {
	const res = await fetch(`${API_URL}${path}`, {
		method: 'DELETE',
		headers: headers(cookies),
	});
	return handleResponse(res) as Promise<T>;
}

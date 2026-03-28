// See https://svelte.dev/docs/kit/types#app.d.ts
declare global {
	namespace App {
		interface Locals {
			user: {
				identity_id: string;
				org_id: string;
				email: string;
			} | null;
		}
	}
}

export {};

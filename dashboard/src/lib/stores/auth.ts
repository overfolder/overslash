import { writable } from 'svelte/store';
import type { UserInfo, MyPermissions } from '$lib/types';

export const user = writable<UserInfo | null>(null);
export const permissions = writable<MyPermissions | null>(null);

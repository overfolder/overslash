import { writable } from 'svelte/store';
import type {
  ServiceSummary,
  ServiceDetail,
  ConnectionSummary,
  ExecuteResponse
} from './types';

function persistedWritable(key: string, initial: string) {
  let stored = initial;
  if (typeof localStorage !== 'undefined') {
    stored = localStorage.getItem(key) ?? initial;
  }
  const store = writable(stored);
  store.subscribe((val) => {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(key, val);
    }
  });
  return store;
}

/** Shared identity for admin auth guard — avoids duplicate /auth/me/identity fetches. */
export const adminIdentity = writable<import('./session').MeIdentity | null>(null);

export const apiKey = persistedWritable('ovs_api_key', '');
export const services = writable<ServiceSummary[]>([]);
export const selectedServiceKey = writable<string | null>(null);
export const selectedService = writable<ServiceDetail | null>(null);
export const selectedActionKey = writable<string | null>(null);
export const connections = writable<ConnectionSummary[]>([]);
export const executionMode = writable<'A' | 'B' | 'C'>('C');
export const response = writable<ExecuteResponse | null>(null);
export const lastRequest = writable<Record<string, unknown> | null>(null);
export const loading = writable(false);
export const error = writable<string | null>(null);

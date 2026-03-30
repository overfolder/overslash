<script lang="ts">
  import { onMount } from 'svelte';
  import { get } from 'svelte/store';
  import { apiKey } from '$lib/stores';
  import { listServices, getService, listConnections, deleteConnection, ApiError } from '$lib/api';
  import { mergeServicesWithConnections, formatRelativeDate, formatExpiry } from '$lib/services';
  import type { ServiceWithConnection, ServiceDetail } from '$lib/types';

  let items: ServiceWithConnection[] = $state([]);
  let loading = $state(true);
  let error = $state('');
  let actionLoading = $state<string | null>(null);
  let expandedService = $state<string | null>(null);
  let serviceDetails = $state<Record<string, ServiceDetail>>({});
  let toast = $state<{ message: string; type: 'success' | 'error' } | null>(null);
  let connectedCount = $derived(items.filter((i) => i.status === 'connected').length);
  let expiredCount = $derived(items.filter((i) => i.status === 'expired').length);
  let disconnectedCount = $derived(items.filter((i) => i.status === 'disconnected').length);

  onMount(() => load());

  async function load() {
    const key = get(apiKey);
    if (!key) {
      error = 'Enter an API key in the header to view services.';
      loading = false;
      return;
    }
    loading = true;
    error = '';
    try {
      const [services, connections] = await Promise.all([
        listServices(key),
        listConnections(key)
      ]);
      items = mergeServicesWithConnections(services, connections);
    } catch (e) {
      error = e instanceof ApiError ? `API error ${e.status}: ${e.body}` : 'Failed to load';
    } finally {
      loading = false;
    }
  }

  // Reload when API key changes
  apiKey.subscribe(() => { if (!loading) load(); });

  function showToast(message: string, type: 'success' | 'error') {
    toast = { message, type };
    setTimeout(() => (toast = null), 3000);
  }

  async function toggleExpand(key: string) {
    if (expandedService === key) { expandedService = null; return; }
    expandedService = key;
    if (!serviceDetails[key]) {
      try {
        serviceDetails[key] = await getService(get(apiKey), key);
      } catch { /* won't show actions */ }
    }
  }

  async function revokeConnection(serviceKey: string, connectionId: string) {
    actionLoading = serviceKey;
    try {
      await deleteConnection(get(apiKey), connectionId);
      items = items.map((item) =>
        item.service.key === serviceKey
          ? { ...item, connection: null, status: 'disconnected' as const }
          : item
      );
      showToast(`Disconnected from ${serviceKey}`, 'success');
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Revoke failed', 'error');
    } finally {
      actionLoading = null;
    }
  }

  const statusColors: Record<string, string> = {
    connected: 'bg-green-500/15 text-green-400 border-green-500/30',
    expired: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    disconnected: 'bg-gray-500/15 text-gray-400 border-gray-500/30'
  };
  const statusLabels: Record<string, string> = {
    connected: 'Connected',
    expired: 'Token Expired',
    disconnected: 'Not Connected'
  };

  const SERVICE_COLORS: Record<string, string> = {
    github: '#333', google_calendar: '#4285F4', slack: '#4A154B',
    stripe: '#635BFF', x: '#000', eventbrite: '#F05537', resend: '#000'
  };
  const SERVICE_LETTERS: Record<string, string> = {
    github: 'GH', google_calendar: 'GC', slack: 'SL',
    stripe: 'ST', x: 'X', eventbrite: 'EB', resend: 'RS'
  };
</script>

<div class="max-w-5xl mx-auto px-6 py-8">
  <div class="mb-8">
    <h1 class="text-2xl font-bold tracking-tight">Connected Services</h1>
    <p class="mt-1 text-sm text-gray-400">Manage OAuth connections to external services</p>
  </div>

  {#if loading}
    <div class="flex items-center justify-center py-24">
      <div class="h-8 w-8 animate-spin rounded-full border-2 border-gray-700 border-t-white"></div>
    </div>
  {:else if error}
    <div class="rounded-lg border border-red-800 bg-red-950/50 p-6 text-center">
      <p class="text-red-300">{error}</p>
      <button onclick={load} class="mt-3 text-sm text-red-400 underline hover:text-red-300">Retry</button>
    </div>
  {:else}
    <!-- Stats -->
    <div class="mb-6 grid grid-cols-3 gap-4">
      <div class="rounded-lg border border-gray-800 bg-gray-900 px-4 py-3">
        <div class="text-2xl font-bold text-green-400">{connectedCount}</div>
        <div class="text-xs text-gray-500">Connected</div>
      </div>
      <div class="rounded-lg border border-gray-800 bg-gray-900 px-4 py-3">
        <div class="text-2xl font-bold text-yellow-400">{expiredCount}</div>
        <div class="text-xs text-gray-500">Expired</div>
      </div>
      <div class="rounded-lg border border-gray-800 bg-gray-900 px-4 py-3">
        <div class="text-2xl font-bold text-gray-400">{disconnectedCount}</div>
        <div class="text-xs text-gray-500">Not Connected</div>
      </div>
    </div>

    <!-- Services list -->
    <div class="space-y-3">
      {#each items as item (item.service.key)}
        {@const isExpanded = expandedService === item.service.key}
        {@const detail = serviceDetails[item.service.key]}
        <div class="overflow-hidden rounded-lg border border-gray-800 bg-gray-900 transition-colors hover:border-gray-700">
          <button onclick={() => toggleExpand(item.service.key)} class="flex w-full items-center gap-4 px-5 py-4 text-left">
            <div
              class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg text-sm font-bold text-white"
              style="background-color: {SERVICE_COLORS[item.service.key] ?? '#6B7280'}"
            >{SERVICE_LETTERS[item.service.key] ?? item.service.key.slice(0, 2).toUpperCase()}</div>
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-2">
                <span class="font-medium">{item.service.display_name}</span>
                <span class="inline-flex rounded-full border px-2 py-0.5 text-xs {statusColors[item.status]}">{statusLabels[item.status]}</span>
              </div>
              <div class="mt-0.5 flex items-center gap-3 text-xs text-gray-500">
                <span>{item.service.hosts[0]}</span>
                <span>{item.service.action_count} actions</span>
                {#if item.connection?.account_email}<span>{item.connection.account_email}</span>{/if}
              </div>
            </div>
            {#if item.connection}
              <div class="hidden shrink-0 text-right text-xs text-gray-500 sm:block">
                <div>Connected {formatRelativeDate(item.connection.created_at)}</div>
                {#if item.connection.token_expires_at}
                  <div class="mt-0.5">
                    {#if item.status === 'expired'}<span class="text-yellow-400">Token expired</span>
                    {:else}Expires in {formatExpiry(item.connection.token_expires_at)}{/if}
                  </div>
                {:else}<div class="mt-0.5">No expiry</div>{/if}
              </div>
            {/if}
            <svg class="h-5 w-5 shrink-0 text-gray-600 transition-transform {isExpanded ? 'rotate-180' : ''}" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>

          {#if isExpanded}
            <div class="border-t border-gray-800 px-5 py-4">
              <div class="flex flex-wrap gap-2">
                {#if item.connection}
                  <button
                    onclick={() => { if (item.connection) revokeConnection(item.service.key, item.connection.id); }}
                    disabled={actionLoading === item.service.key}
                    class="rounded-lg border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs font-medium text-red-400 transition hover:bg-red-900/50 disabled:opacity-50"
                  >{actionLoading === item.service.key ? 'Revoking...' : 'Revoke Connection'}</button>
                  {#if item.status === 'expired' && item.oauthProvider}
                    <button class="rounded-lg border border-yellow-800 bg-yellow-950/50 px-3 py-1.5 text-xs font-medium text-yellow-400 transition hover:bg-yellow-900/50">Reconnect</button>
                  {/if}
                {:else if item.oauthProvider}
                  <button class="rounded-lg border border-green-800 bg-green-950/50 px-3 py-1.5 text-xs font-medium text-green-400 transition hover:bg-green-900/50">Connect</button>
                {/if}
              </div>

              {#if item.connection}
                <div class="mt-4 grid grid-cols-2 gap-4 text-xs sm:grid-cols-4">
                  <div><div class="text-gray-500">Provider</div><div class="mt-0.5 font-medium">{item.connection.provider_key}</div></div>
                  <div><div class="text-gray-500">Connected</div><div class="mt-0.5 font-medium">{new Date(item.connection.created_at).toLocaleDateString()}</div></div>
                  <div><div class="text-gray-500">Token Expiry</div><div class="mt-0.5 font-medium">{item.connection.token_expires_at ? new Date(item.connection.token_expires_at).toLocaleString() : 'No expiry'}</div></div>
                  <div><div class="text-gray-500">Default</div><div class="mt-0.5 font-medium">{item.connection.is_default ? 'Yes' : 'No'}</div></div>
                </div>
              {/if}

              {#if detail}
                <div class="mt-4">
                  <div class="mb-2 text-xs font-medium text-gray-500">Available Actions</div>
                  <div class="grid gap-1.5 sm:grid-cols-2">
                    {#each Object.entries(detail.actions) as [key, action]}
                      <div class="flex items-center gap-2 rounded-lg bg-gray-800/50 px-3 py-2">
                        <span class="rounded px-1.5 py-0.5 font-mono text-[10px] font-bold {action.method === 'GET' ? 'bg-blue-500/20 text-blue-400' : 'bg-orange-500/20 text-orange-400'}">{action.method}</span>
                        <div class="min-w-0 flex-1">
                          <div class="truncate text-xs font-medium">{key}</div>
                          <div class="truncate text-[10px] text-gray-500">{action.description}</div>
                        </div>
                        <span class="shrink-0 rounded px-1.5 py-0.5 text-[10px] {action.risk === 'read' ? 'bg-gray-700 text-gray-400' : 'bg-yellow-500/15 text-yellow-400'}">{action.risk}</span>
                      </div>
                    {/each}
                  </div>
                </div>
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

{#if toast}
  <div class="fixed bottom-6 right-6 z-50 rounded-lg border px-4 py-3 text-sm shadow-xl {toast.type === 'success' ? 'border-green-800 bg-green-950 text-green-300' : 'border-red-800 bg-red-950 text-red-300'}">
    {toast.message}
  </div>
{/if}

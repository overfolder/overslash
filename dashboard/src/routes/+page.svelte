<script lang="ts">
  import {
    apiKey,
    services,
    selectedServiceKey,
    selectedService,
    selectedActionKey,
    connections,
    executionMode,
    response,
    lastRequest,
    loading,
    error
  } from '$lib/stores';
  import {
    listServices,
    getService,
    listConnections,
    executeAction,
    highlightJson,
    ApiError
  } from '$lib/api';
  import type {
    ServiceSummary,
    ServiceDetail,
    ServiceAction,
    ActionParam,
    ConnectionSummary,
    ExecuteResponse,
    ExecuteRequest
  } from '$lib/types';

  // Local state
  let svcList = $state<ServiceSummary[]>([]);
  let svcDetail = $state<ServiceDetail | null>(null);
  let actionKey = $state<string | null>(null);
  let connList = $state<ConnectionSummary[]>([]);
  let mode = $state<'A' | 'B' | 'C'>('C');
  let paramValues = $state<Record<string, string>>({});
  let resp = $state<ExecuteResponse | null>(null);
  let sentRequest = $state<Record<string, unknown> | null>(null);
  let isLoading = $state(false);
  let errorMsg = $state<string | null>(null);
  let activeTab = $state<'body' | 'headers' | 'request'>('body');
  let key = $state('');

  // Mode A fields
  let rawMethod = $state('GET');
  let rawUrl = $state('');
  let rawHeaders = $state<{ key: string; value: string }[]>([{ key: '', value: '' }]);
  let rawBody = $state('');

  // Mode B fields
  let selectedConnectionId = $state<string | null>(null);
  let connMethod = $state('GET');
  let connUrl = $state('');

  // Subscribe to stores
  apiKey.subscribe((v) => (key = v));
  services.subscribe((v) => (svcList = v));
  selectedService.subscribe((v) => (svcDetail = v));
  selectedActionKey.subscribe((v) => (actionKey = v));
  connections.subscribe((v) => (connList = v));
  executionMode.subscribe((v) => (mode = v));
  response.subscribe((v) => (resp = v));
  lastRequest.subscribe((v) => (sentRequest = v));
  loading.subscribe((v) => (isLoading = v));
  error.subscribe((v) => (errorMsg = v));

  // Derived
  let currentAction = $derived(
    svcDetail && actionKey ? svcDetail.actions[actionKey] ?? null : null
  );
  let paramEntries = $derived(
    currentAction ? Object.entries(currentAction.params).sort(([, a], [, b]) => {
      if (a.required && !b.required) return -1;
      if (!a.required && b.required) return 1;
      return 0;
    }) : []
  );

  async function fetchServices() {
    if (!key) return;
    errorMsg = null;
    try {
      const list = await listServices(key);
      services.set(list);
      const conns = await listConnections(key);
      connections.set(conns);
    } catch (e) {
      errorMsg = e instanceof ApiError ? `${e.status}: ${e.body}` : String(e);
    }
  }

  async function onServiceChange(serviceKey: string) {
    selectedServiceKey.set(serviceKey);
    selectedActionKey.set(null);
    paramValues = {};
    response.set(null);
    lastRequest.set(null);
    if (!serviceKey || !key) {
      selectedService.set(null);
      return;
    }
    try {
      const detail = await getService(key, serviceKey);
      selectedService.set(detail);
    } catch (e) {
      errorMsg = e instanceof ApiError ? `${e.status}: ${e.body}` : String(e);
    }
  }

  function onActionChange(ak: string) {
    selectedActionKey.set(ak);
    response.set(null);
    lastRequest.set(null);
    // Pre-fill defaults
    paramValues = {};
    if (svcDetail && ak && svcDetail.actions[ak]) {
      for (const [k, p] of Object.entries(svcDetail.actions[ak].params)) {
        if (p.default !== undefined && p.default !== null) {
          paramValues[k] = String(p.default);
        }
      }
    }
  }

  function methodColor(method: string): string {
    switch (method.toUpperCase()) {
      case 'GET': return 'bg-green-900 text-green-300';
      case 'POST': return 'bg-blue-900 text-blue-300';
      case 'PUT': return 'bg-yellow-900 text-yellow-300';
      case 'PATCH': return 'bg-orange-900 text-orange-300';
      case 'DELETE': return 'bg-red-900 text-red-300';
      default: return 'bg-gray-700 text-gray-300';
    }
  }

  function riskColor(risk: string): string {
    return risk === 'write' ? 'bg-yellow-900/50 text-yellow-400' : 'bg-green-900/50 text-green-400';
  }

  function statusColor(code: number): string {
    if (code < 300) return 'bg-green-600 text-white';
    if (code < 400) return 'bg-blue-600 text-white';
    if (code < 500) return 'bg-yellow-600 text-white';
    return 'bg-red-600 text-white';
  }

  function addHeaderRow() {
    rawHeaders = [...rawHeaders, { key: '', value: '' }];
  }

  function removeHeaderRow(i: number) {
    rawHeaders = rawHeaders.filter((_, idx) => idx !== i);
  }

  async function execute() {
    if (!key) {
      errorMsg = 'Enter an API key first';
      return;
    }

    isLoading = true;
    loading.set(true);
    errorMsg = null;

    let req: ExecuteRequest;

    if (mode === 'C') {
      if (!svcDetail || !actionKey) {
        errorMsg = 'Select a service and action';
        isLoading = false;
        loading.set(false);
        return;
      }
      const params: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(paramValues)) {
        if (v === '') continue;
        const paramDef = currentAction?.params[k];
        if (paramDef?.type === 'integer') {
          params[k] = parseInt(v, 10);
        } else {
          params[k] = v;
        }
      }
      req = {
        service: svcDetail.key,
        action: actionKey,
        params
      };
    } else if (mode === 'B') {
      if (!selectedConnectionId || !connUrl) {
        errorMsg = 'Select a connection and enter a URL';
        isLoading = false;
        loading.set(false);
        return;
      }
      req = {
        connection: selectedConnectionId,
        method: connMethod,
        url: connUrl
      };
    } else {
      // Mode A
      if (!rawUrl) {
        errorMsg = 'Enter a URL';
        isLoading = false;
        loading.set(false);
        return;
      }
      const headers: Record<string, string> = {};
      for (const h of rawHeaders) {
        if (h.key) headers[h.key] = h.value;
      }
      req = {
        method: rawMethod,
        url: rawUrl,
        headers: Object.keys(headers).length > 0 ? headers : undefined,
        body: rawBody || undefined
      };
    }

    lastRequest.set(req as Record<string, unknown>);
    sentRequest = req as Record<string, unknown>;

    try {
      const result = await executeAction(key, req);
      response.set(result);
      resp = result;
      activeTab = 'body';
    } catch (e) {
      if (e instanceof ApiError) {
        // Try to parse as ExecuteResponse (denied/pending)
        try {
          const parsed = JSON.parse(e.body) as ExecuteResponse;
          if (parsed.status === 'denied' || parsed.status === 'pending_approval') {
            response.set(parsed);
            resp = parsed;
            activeTab = 'body';
            return;
          }
        } catch {
          // Not a structured response
        }
        errorMsg = `API error ${e.status}: ${e.body}`;
      } else {
        errorMsg = String(e);
      }
    } finally {
      isLoading = false;
      loading.set(false);
    }
  }

  // Fetch on mount and refetch when API key changes
  $effect(() => {
    if (key) fetchServices();
  });

  function tryParseJson(text: string): { ok: true; value: unknown } | { ok: false } {
    try {
      return { ok: true, value: JSON.parse(text) };
    } catch {
      return { ok: false };
    }
  }
</script>

<div class="flex h-full">
  <!-- Left Panel: Configuration -->
  <div class="w-[420px] shrink-0 border-r border-gray-800 overflow-y-auto p-5 space-y-5">
    <h2 class="text-sm font-semibold text-gray-400 uppercase tracking-wider">API Explorer</h2>

    {#if errorMsg}
      <div class="bg-red-900/30 border border-red-800 rounded-lg px-3 py-2 text-sm text-red-300">
        {errorMsg}
      </div>
    {/if}

    <!-- Service Selector -->
    <div>
      <label for="service-select" class="block text-xs text-gray-400 mb-1.5">Service</label>
      <select
        id="service-select"
        class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
        onchange={(e) => onServiceChange((e.target as HTMLSelectElement).value)}
      >
        <option value="">Select a service...</option>
        {#each svcList as svc}
          <option value={svc.key}>{svc.display_name} ({svc.action_count} actions)</option>
        {/each}
      </select>
    </div>

    <!-- Action Selector -->
    {#if svcDetail}
      <div>
        <label for="action-select" class="block text-xs text-gray-400 mb-1.5">Action</label>
        <select
          id="action-select"
          class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
          onchange={(e) => onActionChange((e.target as HTMLSelectElement).value)}
        >
          <option value="">Select an action...</option>
          {#each Object.entries(svcDetail.actions).sort(([,a], [,b]) => a.risk === 'read' && b.risk !== 'read' ? -1 : a.risk !== 'read' && b.risk === 'read' ? 1 : 0) as [ak, action]}
            <option value={ak}>{action.method} {action.path} — {action.description}</option>
          {/each}
        </select>
        {#if currentAction}
          <div class="mt-2 flex items-center gap-2">
            <span class="text-xs font-mono px-1.5 py-0.5 rounded {methodColor(currentAction.method)}">{currentAction.method}</span>
            <span class="text-xs font-mono text-gray-400">{currentAction.path}</span>
            <span class="text-xs px-1.5 py-0.5 rounded {riskColor(currentAction.risk)}">{currentAction.risk}</span>
          </div>
        {/if}
      </div>
    {/if}

    <!-- Execution Mode -->
    <div>
      <label class="block text-xs text-gray-400 mb-1.5">Execution Mode</label>
      <div class="flex gap-1 bg-gray-800 rounded-lg p-1">
        {#each [
          { value: 'C', label: 'Service + Action' },
          { value: 'B', label: 'Connection' },
          { value: 'A', label: 'Raw HTTP' }
        ] as opt}
          <button
            class="flex-1 text-xs py-1.5 rounded-md transition-colors {mode === opt.value ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200'}"
            onclick={() => { executionMode.set(opt.value as 'A' | 'B' | 'C'); mode = opt.value as 'A' | 'B' | 'C'; }}
          >
            {opt.label}
          </button>
        {/each}
      </div>
    </div>

    <!-- Mode C: Parameter Form -->
    {#if mode === 'C' && currentAction && paramEntries.length > 0}
      <div class="space-y-3">
        <label class="block text-xs text-gray-400">Parameters</label>
        {#each paramEntries as [pKey, param]}
          <div>
            <label for="param-{pKey}" class="block text-xs text-gray-300 mb-1">
              <span class="font-mono">{pKey}</span>
              {#if param.required}<span class="text-red-400 ml-0.5">*</span>{/if}
              {#if param.description}<span class="text-gray-500 ml-1.5">— {param.description}</span>{/if}
            </label>
            {#if param.enum}
              <select
                id="param-{pKey}"
                class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm font-mono text-gray-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
                value={paramValues[pKey] ?? ''}
                onchange={(e) => paramValues[pKey] = (e.target as HTMLSelectElement).value}
              >
                <option value="">{param.required ? 'Select...' : '(optional)'}</option>
                {#each param.enum as enumVal}
                  <option value={enumVal}>{enumVal}</option>
                {/each}
              </select>
            {:else if param.type === 'integer'}
              <input
                id="param-{pKey}"
                type="number"
                class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm font-mono text-gray-200 focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-gray-600"
                placeholder={param.default !== undefined ? String(param.default) : ''}
                value={paramValues[pKey] ?? ''}
                oninput={(e) => paramValues[pKey] = (e.target as HTMLInputElement).value}
              />
            {:else}
              <input
                id="param-{pKey}"
                type="text"
                class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm font-mono text-gray-200 focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-gray-600"
                placeholder={param.default !== undefined ? String(param.default) : ''}
                value={paramValues[pKey] ?? ''}
                oninput={(e) => paramValues[pKey] = (e.target as HTMLInputElement).value}
              />
            {/if}
          </div>
        {/each}
      </div>
    {/if}

    <!-- Mode B: Connection -->
    {#if mode === 'B'}
      <div class="space-y-3">
        <div>
          <label for="conn-select" class="block text-xs text-gray-400 mb-1.5">Connection</label>
          <select
            id="conn-select"
            class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
            onchange={(e) => selectedConnectionId = (e.target as HTMLSelectElement).value || null}
          >
            <option value="">Select a connection...</option>
            {#each connList as conn}
              <option value={conn.id}>{conn.provider_key}{conn.account_email ? ` (${conn.account_email})` : ''}</option>
            {/each}
          </select>
        </div>
        <div class="flex gap-2">
          <select
            class="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
            bind:value={connMethod}
          >
            {#each ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as m}
              <option value={m}>{m}</option>
            {/each}
          </select>
          <input
            type="text"
            placeholder="https://api.example.com/path"
            class="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm font-mono text-gray-200 focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-gray-600"
            bind:value={connUrl}
          />
        </div>
      </div>
    {/if}

    <!-- Mode A: Raw HTTP -->
    {#if mode === 'A'}
      <div class="space-y-3">
        <div class="flex gap-2">
          <select
            class="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
            bind:value={rawMethod}
          >
            {#each ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'] as m}
              <option value={m}>{m}</option>
            {/each}
          </select>
          <input
            type="text"
            placeholder="https://api.example.com/path"
            class="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm font-mono text-gray-200 focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-gray-600"
            bind:value={rawUrl}
          />
        </div>
        <div>
          <div class="flex items-center justify-between mb-1.5">
            <label class="text-xs text-gray-400">Headers</label>
            <button class="text-xs text-blue-400 hover:text-blue-300" onclick={addHeaderRow}>+ Add</button>
          </div>
          {#each rawHeaders as h, i}
            <div class="flex gap-2 mb-1.5">
              <input
                type="text"
                placeholder="Header name"
                class="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-gray-200 focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-gray-600"
                bind:value={h.key}
              />
              <input
                type="text"
                placeholder="Value"
                class="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-gray-200 focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-gray-600"
                bind:value={h.value}
              />
              <button class="text-gray-500 hover:text-red-400 text-xs px-1" onclick={() => removeHeaderRow(i)}>x</button>
            </div>
          {/each}
        </div>
        <div>
          <label for="raw-body" class="block text-xs text-gray-400 mb-1.5">Body</label>
          <textarea
            id="raw-body"
            rows="4"
            placeholder={'{"key": "value"}'}
            class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm font-mono text-gray-200 focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-gray-600 resize-y"
            bind:value={rawBody}
          ></textarea>
        </div>
      </div>
    {/if}

    <!-- Execute Button -->
    <button
      class="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 text-white font-medium py-2.5 rounded-lg transition-colors flex items-center justify-center gap-2"
      disabled={isLoading || !key}
      onclick={execute}
    >
      {#if isLoading}
        <svg class="animate-spin h-4 w-4" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
        Executing...
      {:else}
        Execute
      {/if}
    </button>
  </div>

  <!-- Right Panel: Response -->
  <div class="flex-1 flex flex-col overflow-hidden">
    <!-- Tabs -->
    <div class="flex border-b border-gray-800 bg-gray-900/50 shrink-0">
      {#each [
        { key: 'body', label: 'Response Body' },
        { key: 'headers', label: 'Headers' },
        { key: 'request', label: 'Request' }
      ] as tab}
        <button
          class="px-4 py-2.5 text-sm transition-colors border-b-2 {activeTab === tab.key ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-500 hover:text-gray-300'}"
          onclick={() => activeTab = tab.key as typeof activeTab}
        >
          {tab.label}
        </button>
      {/each}
    </div>

    <!-- Tab Content -->
    <div class="flex-1 overflow-auto p-5">
      {#if !resp && !sentRequest}
        <div class="flex items-center justify-center h-full text-gray-600">
          <div class="text-center">
            <div class="text-4xl mb-3">&#x2194;</div>
            <p class="text-sm">Select a service and action, then execute to see the response.</p>
          </div>
        </div>
      {:else if activeTab === 'body'}
        {#if resp}
          {#if resp.status === 'executed'}
            <div class="space-y-4">
              <div class="flex items-center gap-3">
                <span class="text-sm font-mono px-2 py-0.5 rounded {statusColor(resp.result.status_code)}">
                  {resp.result.status_code}
                </span>
                <span class="text-xs text-gray-400">{resp.result.duration_ms}ms</span>
                {#if resp.action_description}
                  <span class="text-xs text-gray-500">{resp.action_description}</span>
                {/if}
              </div>
              <div class="bg-gray-900 border border-gray-800 rounded-lg overflow-auto">
                {#if tryParseJson(resp.result.body).ok}
                  <pre class="p-4 text-sm font-mono leading-relaxed overflow-x-auto">{@html highlightJson(tryParseJson(resp.result.body).value)}</pre>
                {:else}
                  <pre class="p-4 text-sm font-mono text-gray-300 whitespace-pre-wrap">{resp.result.body}</pre>
                {/if}
              </div>
            </div>
          {:else if resp.status === 'pending_approval'}
            <div class="bg-amber-900/30 border border-amber-700 rounded-lg p-4 space-y-2">
              <div class="flex items-center gap-2">
                <span class="text-amber-400 font-medium text-sm">Pending Approval</span>
              </div>
              <p class="text-sm text-gray-300">{resp.action_description}</p>
              <div class="text-xs text-gray-400 space-y-1">
                <p>Approval ID: <span class="font-mono text-gray-300">{resp.approval_id}</span></p>
                <p>URL: <span class="font-mono text-gray-300">{resp.approval_url}</span></p>
                <p>Expires: <span class="text-gray-300">{resp.expires_at}</span></p>
              </div>
            </div>
          {:else if resp.status === 'denied'}
            <div class="bg-red-900/30 border border-red-800 rounded-lg p-4 space-y-2">
              <span class="text-red-400 font-medium text-sm">Denied</span>
              <p class="text-sm text-gray-300">{resp.reason}</p>
            </div>
          {/if}
        {/if}
      {:else if activeTab === 'headers'}
        {#if resp && resp.status === 'executed'}
          <div class="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-gray-800">
                  <th class="text-left px-4 py-2 text-xs text-gray-500 font-medium">Header</th>
                  <th class="text-left px-4 py-2 text-xs text-gray-500 font-medium">Value</th>
                </tr>
              </thead>
              <tbody>
                {#each Object.entries(resp.result.headers) as [hk, hv]}
                  <tr class="border-b border-gray-800/50">
                    <td class="px-4 py-1.5 font-mono text-blue-300 text-xs">{hk}</td>
                    <td class="px-4 py-1.5 font-mono text-gray-300 text-xs break-all">{hv}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {:else}
          <p class="text-sm text-gray-500">No response headers to display.</p>
        {/if}
      {:else if activeTab === 'request'}
        {#if sentRequest}
          <div class="bg-gray-900 border border-gray-800 rounded-lg overflow-auto">
            <pre class="p-4 text-sm font-mono leading-relaxed">{@html highlightJson(sentRequest)}</pre>
          </div>
        {:else}
          <p class="text-sm text-gray-500">No request to display.</p>
        {/if}
      {/if}
    </div>
  </div>
</div>

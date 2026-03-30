<script lang="ts">
  import '../app.css';
  import { apiKey } from '$lib/stores';

  let showKey = $state(false);
  let keyValue = $state('');

  apiKey.subscribe((v) => (keyValue = v));

  function onKeyInput(e: Event) {
    const target = e.target as HTMLInputElement;
    apiKey.set(target.value);
  }
</script>

<div class="min-h-screen flex flex-col">
  <header class="border-b border-gray-800 bg-gray-900 px-6 py-3 flex items-center justify-between shrink-0">
    <div class="flex items-center gap-3">
      <span class="text-lg font-bold tracking-tight text-white">Overslash</span>
      <span class="text-xs text-gray-500 border border-gray-700 rounded px-1.5 py-0.5">Developer Tools</span>
    </div>
    <div class="flex items-center gap-3">
      <div class="flex items-center gap-2">
        <span class="text-xs text-gray-400">API Key</span>
        <div class="relative">
          <input
            type={showKey ? 'text' : 'password'}
            value={keyValue}
            oninput={onKeyInput}
            placeholder="osk_..."
            class="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm font-mono text-gray-200 w-72 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 placeholder-gray-600"
          />
          <button
            onclick={() => (showKey = !showKey)}
            class="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 text-xs"
          >
            {showKey ? 'Hide' : 'Show'}
          </button>
        </div>
      </div>
      <div class="w-2 h-2 rounded-full {keyValue ? 'bg-green-500' : 'bg-gray-600'}"></div>
    </div>
  </header>
  <main class="flex-1 overflow-hidden">
    <slot />
  </main>
</div>

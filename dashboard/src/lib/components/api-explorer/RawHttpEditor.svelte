<script lang="ts">
	let {
		method,
		url,
		headers,
		body,
		onmethod,
		onurl,
		onheaders,
		onbody
	}: {
		method: string;
		url: string;
		headers: string;
		body: string;
		onmethod: (v: string) => void;
		onurl: (v: string) => void;
		onheaders: (v: string) => void;
		onbody: (v: string) => void;
	} = $props();

	const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'];

	const bodyHasTemplate = $derived(/\{\{[A-Za-z0-9_]+\}\}/.test(body));
</script>

<div class="row">
	<select
		class="control method"
		value={method}
		onchange={(e) => onmethod((e.currentTarget as HTMLSelectElement).value)}
	>
		{#each METHODS as m (m)}
			<option value={m}>{m}</option>
		{/each}
	</select>
	<input
		class="control url"
		type="text"
		placeholder="https://api.example.com/v1/data"
		value={url}
		oninput={(e) => onurl((e.currentTarget as HTMLInputElement).value)}
	/>
</div>

<div class="field">
	<label class="label" for="raw-headers">Headers</label>
	<textarea
		id="raw-headers"
		class="control mono"
		rows="4"
		placeholder={'Content-Type: application/json\nAuthorization: Bearer {{MY_TOKEN}}'}
		value={headers}
		oninput={(e) => onheaders((e.currentTarget as HTMLTextAreaElement).value)}
	></textarea>
</div>

<div class="field">
	<label class="label" for="raw-body">Body</label>
	<textarea
		id="raw-body"
		class="control mono"
		rows="6"
		placeholder={'{"prompt": "Hello world"}'}
		value={body}
		oninput={(e) => onbody((e.currentTarget as HTMLTextAreaElement).value)}
	></textarea>
	{#if bodyHasTemplate}
		<p class="warn">
			⚠ Body secret injection is not supported yet — <code>{'{{TOKEN}}'}</code> in the body will be sent literally.
		</p>
	{/if}
</div>

<p class="hint">💡 Use <code>{'{{SECRET_NAME}}'}</code> in a header value to inject a secret at call time.</p>

<style>
	.row {
		display: flex;
		gap: 0.5rem;
		margin-bottom: 0.9rem;
	}
	.method { width: 7rem; flex-shrink: 0; }
	.url { flex: 1; }
	.field { margin-bottom: 0.9rem; }
	.label {
		display: block;
		font: var(--text-label);
		color: var(--color-text);
		margin-bottom: 0.3rem;
	}
	.control {
		width: 100%;
		padding: 0.55rem 0.75rem;
		font: inherit;
		font-size: 0.88rem;
		color: var(--color-text);
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
	}
	.control:focus {
		outline: 2px solid var(--color-primary);
		outline-offset: -1px;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 0.82rem;
	}
	.hint {
		font-size: 0.78rem;
		color: var(--color-text-muted);
		margin: 0.4rem 0 0;
	}
	.warn {
		font-size: 0.78rem;
		color: var(--warning-500);
		margin: 0.4rem 0 0;
	}
	code {
		font-family: var(--font-mono);
	}
</style>

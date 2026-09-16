<!--
	The masked input a human pastes a secret into on a public, token-gated
	page. Shared by `/secrets/provide/[req_id]` and `/services/setup/[req_id]`,
	which ask the same question from two framings.

	Deliberately not the dashboard's own secret forms: those run inside a
	session and can lean on the shell for context. This one stands alone on a
	page a stranger may have opened from a chat message.
-->
<script lang="ts">
	let {
		value = $bindable(''),
		label = 'Secret value',
		placeholder = 'Paste secret value',
		disabled = false,
		autofocus = false
	}: {
		value?: string;
		label?: string;
		placeholder?: string;
		disabled?: boolean;
		autofocus?: boolean;
	} = $props();

	let reveal = $state(false);
</script>

<label class="field">
	<span>{label}</span>
	<div class="input-wrap">
		<!-- svelte-ignore a11y_autofocus -->
		<input
			type={reveal ? 'text' : 'password'}
			bind:value
			{disabled}
			{autofocus}
			autocomplete="off"
			spellcheck="false"
			autocapitalize="off"
			autocorrect="off"
			{placeholder}
		/>
		<button
			type="button"
			class="reveal"
			onclick={() => (reveal = !reveal)}
			aria-label={reveal ? 'Hide value' : 'Show value'}
			{disabled}
		>
			{reveal ? 'Hide' : 'Show'}
		</button>
	</div>
</label>

<style>
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
		margin-bottom: 1rem;
	}
	.field span {
		font-size: 0.8rem;
		color: var(--color-text-muted);
	}
	.input-wrap {
		display: flex;
		gap: 0.5rem;
	}
	.input-wrap input {
		flex: 1;
		min-width: 0;
		padding: 0.6rem 0.75rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-bg);
		color: var(--color-text);
		font: inherit;
		font-family: var(--font-mono);
	}
	.reveal {
		padding: 0 0.85rem;
		border: 1px solid var(--color-border);
		border-radius: 6px;
		background: var(--color-bg);
		color: var(--color-text-muted);
		cursor: pointer;
		font-size: 0.8rem;
	}
	.reveal:hover:not(:disabled) {
		color: var(--color-text);
	}
	.reveal:disabled {
		cursor: not-allowed;
		opacity: 0.6;
	}
</style>

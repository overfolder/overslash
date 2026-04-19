<script lang="ts">
	let {
		checked,
		onchange,
		disabled = false,
		label,
		labelledby,
		size = 'md',
		id
	}: {
		checked: boolean;
		onchange: (next: boolean) => void;
		disabled?: boolean;
		/** Accessible name when no visible label is adjacent. Ignored if `labelledby` is set. */
		label?: string;
		/** ID of a visible element that labels this switch. Preferred over `label` when the text is on-screen. */
		labelledby?: string;
		size?: 'sm' | 'md';
		id?: string;
	} = $props();

	function handleClick() {
		if (disabled) return;
		onchange(!checked);
	}
</script>

<button
	type="button"
	role="switch"
	aria-checked={checked}
	aria-label={labelledby ? undefined : label}
	aria-labelledby={labelledby}
	{id}
	{disabled}
	class="switch size-{size}"
	class:on={checked}
	onclick={handleClick}
>
	<span class="thumb" aria-hidden="true"></span>
</button>

<style>
	.switch {
		position: relative;
		display: inline-flex;
		align-items: center;
		flex-shrink: 0;
		padding: 0;
		border-radius: var(--radius-pill);
		border: 1px solid var(--color-border);
		background: var(--neutral-200);
		cursor: pointer;
		transition:
			background-color 150ms ease,
			border-color 150ms ease;
	}
	.switch.size-md {
		width: 36px;
		height: 20px;
	}
	.switch.size-sm {
		width: 28px;
		height: 16px;
	}
	.switch.on {
		background: var(--primary-500);
		border-color: var(--primary-500);
	}
	.switch:hover:not(:disabled) {
		border-color: var(--neutral-300);
	}
	.switch.on:hover:not(:disabled) {
		background: var(--primary-600);
		border-color: var(--primary-600);
	}
	.switch:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.switch:focus-visible {
		outline: 2px solid var(--primary-500);
		outline-offset: 2px;
	}
	.thumb {
		display: block;
		background: var(--color-surface);
		border-radius: 50%;
		box-shadow: var(--shadow-sm);
		transition: transform 150ms ease;
	}
	.size-md .thumb {
		width: 14px;
		height: 14px;
		transform: translateX(2px);
	}
	.size-md.on .thumb {
		transform: translateX(18px);
	}
	.size-sm .thumb {
		width: 10px;
		height: 10px;
		transform: translateX(2px);
	}
	.size-sm.on .thumb {
		transform: translateX(14px);
	}
	@media (prefers-reduced-motion: reduce) {
		.switch,
		.thumb {
			transition: none;
		}
	}
</style>

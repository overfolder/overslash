<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import Avatar from './Avatar.svelte';

	const { Story } = defineMeta({
		title: 'Identity/Avatar',
		component: Avatar,
		tags: ['autodocs'],
		argTypes: { size: { control: { type: 'range', min: 16, max: 96, step: 4 } } },
		args: { name: 'Alice Martin', email: 'alice@acme.com', picture: null, size: 48 }
	});
</script>

<script lang="ts">
	import ProviderTile from './connections/ProviderTile.svelte';
</script>

<Story name="Initials" />
<Story name="Picture" args={{ picture: 'https://i.pravatar.cc/96?img=47' }} />
<Story
	name="Broken picture falls back"
	args={{ picture: 'https://example.invalid/gone.png' }}
/>
<Story
	name="Email only"
	args={{ name: '', email: 'ada@acme.com' }}
/>
<Story name="No name, no email" args={{ name: '', email: null }} />

<Story name="Sizes" asChild>
	<div style="display:flex; align-items:center; gap:12px;">
		{#each [20, 32, 48, 72] as size (size)}
			<Avatar name="Alice Martin" email="alice@acme.com" {size} />
		{/each}
	</div>
</Story>

<!-- What a connection renders: the linked account's face, badged with the
     provider it was linked through. The rounded-square tile needs a matching
     ring, so the caller sets `--avatar-badge-radius` on the wrapper. -->
<Story name="Badged (connection)" asChild>
	<div style="display:flex; align-items:center; gap:16px; --avatar-badge-radius:30%;">
		{#each [32, 48, 72] as size (size)}
			<Avatar email="alice@acme.com" picture="https://i.pravatar.cc/96?img=47" {size}>
				{#snippet badge()}
					<ProviderTile provider="google" size={Math.round(size / 2)} />
				{/snippet}
			</Avatar>
		{/each}
	</div>
</Story>

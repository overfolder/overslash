<script module lang="ts">
	import { defineMeta } from '@storybook/addon-svelte-csf';
	import NavItem from './NavItem.svelte';

	// NavItem reads `$page.url.pathname` (from `$app/stores`) to decide the active
	// state, unless `activeHref` is passed. @storybook/sveltekit mocks `$app/stores`;
	// `parameters.sveltekit_experimental.stores.page.url` sets the mocked path.
	const { Story } = defineMeta({
		title: 'Shell/NavItem',
		component: NavItem,
		tags: ['autodocs'],
		parameters: {
			layout: 'padded',
			sveltekit_experimental: { stores: { page: { url: '/agents' } } }
		},
		argTypes: { collapsed: { control: 'boolean' } },
		args: { href: '/agents', label: 'Agents', icon: '◆', collapsed: false }
	});
</script>

<Story name="Active (from page store)" args={{ href: '/agents', label: 'Agents', icon: '◆' }} />
<Story name="Inactive" args={{ href: '/services', label: 'Services', icon: '⚙' }} />
<Story name="Active (explicit activeHref)" args={{ href: '/secrets', label: 'Secrets', icon: '🔑', activeHref: '/secrets' }} />
<Story name="Collapsed" args={{ href: '/agents', label: 'Agents', icon: '◆', collapsed: true }} />

<Story name="Sidebar group" asChild>
	<nav style="width:220px; display:flex; flex-direction:column; gap:4px; padding:8px; background:var(--color-sidebar); border:1px solid var(--color-border); border-radius:8px;">
		<NavItem href="/agents" label="Agents" icon="◆" activeHref="/agents" />
		<NavItem href="/services" label="Services" icon="⚙" activeHref="/agents" />
		<NavItem href="/secrets" label="Secrets" icon="🔑" activeHref="/agents" />
		<NavItem href="/audit" label="Audit Log" icon="▤" activeHref="/agents" />
	</nav>
</Story>

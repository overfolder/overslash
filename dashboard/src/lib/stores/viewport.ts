import { readable, type Readable } from 'svelte/store';

export type Viewport = 'mobile' | 'tablet' | 'desktop';

// Match the breakpoints used by responsive.css in the design handoff:
//   mobile  : < 768px
//   tablet  : 768–1024px
//   desktop : ≥ 1025px
const MOBILE_MAX = 767;
const TABLET_MAX = 1024;

function classify(width: number): Viewport {
	if (width <= MOBILE_MAX) return 'mobile';
	if (width <= TABLET_MAX) return 'tablet';
	return 'desktop';
}

function initial(): Viewport {
	if (typeof window === 'undefined') return 'desktop';
	return classify(window.innerWidth);
}

export const viewport: Readable<Viewport> = readable<Viewport>(initial(), (set) => {
	if (typeof window === 'undefined') return () => {};
	const onResize = () => set(classify(window.innerWidth));
	window.addEventListener('resize', onResize, { passive: true });
	// Re-emit once on subscribe in case SSR initial differs from client.
	set(classify(window.innerWidth));
	return () => window.removeEventListener('resize', onResize);
});

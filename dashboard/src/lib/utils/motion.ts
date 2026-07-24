import type { TransitionConfig } from 'svelte/transition';
import { cubicOut } from 'svelte/easing';

/** True when the viewer asked the OS to keep animation to a minimum. */
export function prefersReducedMotion(): boolean {
	if (typeof window === 'undefined' || !window.matchMedia) return false;
	return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/** `ms`, or 0 when the viewer prefers reduced motion. */
export function motionDuration(ms: number): number {
	return prefersReducedMotion() ? 0 : ms;
}

/**
 * Collapse a list item out of the flow: height, vertical margins, padding and
 * opacity all go to zero together, so the rows below slide up into the space
 * it vacated instead of jumping. Used by the approval lists, where the point is
 * that the next card lands under a stationary cursor.
 *
 * `svelte/transition`'s `slide` does the box metrics but not opacity, and can't
 * be combined with `fade` on the same element — hence the local implementation.
 */
export function collapse(
	node: Element,
	{ duration = 130, easing = cubicOut }: { duration?: number; easing?: (t: number) => number } = {}
): TransitionConfig {
	const style = getComputedStyle(node);
	const height = parseFloat(style.height);
	const marginTop = parseFloat(style.marginTop);
	const marginBottom = parseFloat(style.marginBottom);
	const paddingTop = parseFloat(style.paddingTop);
	const paddingBottom = parseFloat(style.paddingBottom);
	const borderTop = parseFloat(style.borderTopWidth);
	const borderBottom = parseFloat(style.borderBottomWidth);

	return {
		duration: motionDuration(duration),
		easing,
		css: (t) =>
			'overflow: hidden;' +
			`opacity: ${Math.min(t * 2, 1)};` +
			`height: ${t * height}px;` +
			`margin-top: ${t * marginTop}px;` +
			`margin-bottom: ${t * marginBottom}px;` +
			`padding-top: ${t * paddingTop}px;` +
			`padding-bottom: ${t * paddingBottom}px;` +
			`border-top-width: ${t * borderTop}px;` +
			`border-bottom-width: ${t * borderBottom}px;`
	};
}

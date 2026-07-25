// Anchor resolution + measurement. A URL-driven panel opens on an UNKNOWN future
// render (route mounts → useFetch resolves → <Loader/> swaps out → panel reads its
// param → its children mount), so we never guess timing: we WATCH the DOM with a
// MutationObserver bounded by a timeout until the anchor exists.

export function reducedMotion(): boolean {
  return typeof window !== 'undefined'
    && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches === true
}

export function resolveAnchor(name: string): HTMLElement | null {
  return document.querySelector<HTMLElement>(`[data-tour="${CSS.escape(name)}"]`)
}

/** Resolve now, else wait for the anchor to appear (MutationObserver), else time out.
 *  An optional AbortSignal tears the observer + timer down immediately (step change/exit),
 *  so a slow-mounting anchor never orphans a whole-document observer. */
export function waitForAnchor(name: string, timeoutMs = 4000, signal?: AbortSignal): Promise<HTMLElement | null> {
  const immediate = resolveAnchor(name)
  if (immediate) return Promise.resolve(immediate)
  if (signal?.aborted) return Promise.resolve(null)
  return new Promise((resolve) => {
    let done = false
    const finish = (el: HTMLElement | null) => {
      if (done) return
      done = true
      obs.disconnect()
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
      resolve(el)
    }
    const onAbort = () => finish(null)
    const obs = new MutationObserver(() => {
      const el = resolveAnchor(name)
      if (el) finish(el)
    })
    obs.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['data-tour'] })
    const timer = setTimeout(() => finish(resolveAnchor(name)), timeoutMs)
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

export function scrollAnchorIntoView(el: HTMLElement): void {
  el.scrollIntoView({ block: 'center', inline: 'nearest', behavior: reducedMotion() ? 'auto' : 'smooth' })
}

/**
 * Re-measure the target for a short window after it appears. A slide-over animates in
 * via a CSS transform that fires neither scroll nor ResizeObserver, so a single measure
 * can land on a stale rect. We poll a few animation frames and also settle on
 * transitionend of the nearest panel, then invoke `onRect` with the final rect.
 */
export function trackRect(
  el: HTMLElement,
  onRect: (r: DOMRect) => void,
  opts: { settleMs?: number } = {},
): () => void {
  const settleMs = opts.settleMs ?? 360
  let raf = 0
  const start = performance.now()
  const measure = () => onRect(el.getBoundingClientRect())

  // 1) re-measure window (defeats the slide-in transform race)
  const loop = () => {
    measure()
    if (performance.now() - start < settleMs) raf = requestAnimationFrame(loop)
  }
  raf = requestAnimationFrame(loop)

  // 2) live tracking while the step is active — the only scroller is <main> (AppShell),
  //    and scroll does not bubble, so listen in the capture phase on window.
  const onScroll = () => measure()
  const onResize = () => measure()
  window.addEventListener('scroll', onScroll, { capture: true, passive: true })
  window.addEventListener('resize', onResize, { passive: true })
  const ro = new ResizeObserver(measure)
  ro.observe(el)
  const panel = el.closest('aside, [role="dialog"]') as HTMLElement | null
  const onTransitionEnd = () => measure()
  panel?.addEventListener('transitionend', onTransitionEnd)

  return () => {
    cancelAnimationFrame(raf)
    window.removeEventListener('scroll', onScroll, { capture: true })
    window.removeEventListener('resize', onResize)
    ro.disconnect()
    panel?.removeEventListener('transitionend', onTransitionEnd)
  }
}

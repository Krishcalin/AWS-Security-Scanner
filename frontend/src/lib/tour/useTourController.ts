import { useCallback, useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { PANEL_PARAMS } from '../deeplink'
import { resolveAnchor, waitForAnchor, scrollAnchorIntoView, trackRect, reducedMotion } from './anchor'
import { markTourSeen, saveResume, clearResume } from './storage'
import { getScenario } from './scenarios'
import type { RunnerStatus, TourApi, TourScenario, TourState, TourStep } from './types'

const DEFAULT_DWELL = 6500

/** Build the target URL for a step: scope + panel params → one search string. */
function stepSearch(step: TourStep): string {
  const p = new URLSearchParams()
  if (step.scope && step.scope !== 'org') p.set('scope', step.scope)
  for (const [k, v] of Object.entries(step.params ?? {})) p.set(k, v)
  return p.toString()
}

export function useTourController(): { state: TourState; status: RunnerStatus; api: TourApi } {
  const navigate = useNavigate()
  const location = useLocation()

  const [scenario, setScenario] = useState<TourScenario | null>(null)
  const [index, setIndex] = useState(0)
  const [paused, setPaused] = useState(false)
  const [rect, setRect] = useState<DOMRect | null>(null)
  const [ready, setReady] = useState(false)          // spotlight settled once for this step
  const [awaitingUser, setAwaitingUser] = useState(false)

  const scenarioRef = useRef<TourScenario | null>(null)
  const trackCleanup = useRef<null | (() => void)>(null)
  const restoreFocus = useRef<HTMLElement | null>(null)   // focus to restore on exit
  useEffect(() => { scenarioRef.current = scenario }, [scenario])

  const step: TourStep | null = scenario ? scenario.steps[index] ?? null : null
  const n = scenario?.steps.length ?? 0
  const isLast = index >= n - 1
  const clearTrack = () => { trackCleanup.current?.(); trackCleanup.current = null }

  // ── controls ────────────────────────────────────────────────────────────────
  const next = useCallback(() => {
    const sc = scenarioRef.current
    if (!sc) return
    setIndex((i) => Math.min(sc.steps.length - 1, i + 1))
  }, [])
  const prev = useCallback(() => setIndex((i) => Math.max(0, i - 1)), [])
  const goTo = useCallback((i: number) => {
    const sc = scenarioRef.current
    if (!sc) return
    setIndex(Math.max(0, Math.min(i, sc.steps.length - 1)))
  }, [])
  const pause = useCallback(() => setPaused(true), [])
  const resume = useCallback(() => setPaused(false), [])

  const exit = useCallback(() => {
    clearTrack()
    setScenario(null); setIndex(0); setRect(null); setReady(false); setAwaitingUser(false); setPaused(false)
    markTourSeen(); clearResume()
    // drop tour-owned panel params so the user isn't left in a spotlight-less open panel.
    const p = new URLSearchParams(window.location.search)
    for (const k of PANEL_PARAMS) p.delete(k)
    navigate({ pathname: window.location.pathname, search: p.toString() }, { replace: true })
    // restore focus to wherever the user was before the tour (after inert is lifted)
    const el = restoreFocus.current
    restoreFocus.current = null
    if (el) requestAnimationFrame(() => el.focus?.())
  }, [navigate])

  const start = useCallback((scenarioId: string, atIndex = 0) => {
    const sc = getScenario(scenarioId)
    if (!sc) return
    clearTrack()
    restoreFocus.current = (document.activeElement as HTMLElement) ?? null
    setScenario(sc)
    setIndex(Math.max(0, Math.min(atIndex, sc.steps.length - 1)))
    setPaused(false); setReady(false); setAwaitingUser(false); setRect(null)
  }, [])

  // ── (A) command: navigate to the step's URL (scope + panel). Idempotent. ──────
  useEffect(() => {
    if (!step) return
    const pathname = step.route ?? window.location.pathname
    const search = stepSearch(step)
    const curSearch = window.location.search.replace(/^\?/, '')
    if (window.location.pathname !== pathname || curSearch !== search) {
      navigate({ pathname, search }, { replace: true })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- driven by [scenario,index]; navigate is stable
  }, [scenario, index])

  // ── (B) focus: after the URL settles + the panel mounts, spotlight the anchor. ─
  useEffect(() => {
    if (!step) return
    let cancelled = false
    const ac = new AbortController()   // aborts the anchor observers on step change / exit
    setReady(false)
    setAwaitingUser(false)
    setRect(null)          // drop the previous step's rect so a cross-screen wait shows a
    clearTrack()           // clean centered coachmark, not a spotlight over a stale element

    const run = async () => {
      if (!step.anchor) { if (!cancelled) { setRect(null); setReady(true) } return }
      if (step.waitFor) await waitForAnchor(step.waitFor, 4000, ac.signal)
      const el = await waitForAnchor(step.anchor, 4000, ac.signal)
      if (cancelled) return
      if (!el) {
        if (step.optional) { next(); return }
        setRect(null); setReady(true); return    // graceful centered fallback
      }
      scrollAnchorIntoView(el)
      trackCleanup.current = trackRect(el, (r) => { if (!cancelled) setRect(r) })
      setReady(true)
      if (step.mode?.kind === 'interactive') setAwaitingUser(true)
    }
    run()
    return () => { cancelled = true; ac.abort(); clearTrack() }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- re-run per step + per observed location
  }, [scenario, index, location.key])

  // ── (C) auto-advance: gated on `ready` (settled ONCE) — never restarts on rect. ─
  useEffect(() => {
    if (!step || paused || !ready || isLast) return
    if (step.mode?.kind === 'interactive') return       // wait for the user's click
    if (reducedMotion()) return                          // WCAG: no auto-advance
    const dwell = step.dwellMs ?? DEFAULT_DWELL
    const t = setTimeout(() => next(), dwell)
    return () => clearTimeout(t)
  }, [scenario, index, paused, ready, isLast, step, next])

  // ── (D) take-the-wheel: advance when the user clicks the spotlighted control. ──
  useEffect(() => {
    if (!step || step.mode?.kind !== 'interactive' || !awaitingUser || !ready || !step.anchor) return
    const el = resolveAnchor(step.anchor)
    if (!el) return
    // move focus to the real control so keyboard users can act (it's already in view)
    if (typeof el.focus === 'function') el.focus({ preventScroll: true })
    const advance = () => next()
    // capture phase so we still advance if the element stops propagation
    el.addEventListener('click', advance, { once: true, capture: true })
    return () => el.removeEventListener('click', advance, { capture: true } as EventListenerOptions)
  }, [scenario, index, awaitingUser, ready, step, next])

  // ── resume position (session) ─────────────────────────────────────────────────
  useEffect(() => {
    if (scenario) saveResume({ scenarioId: scenario.id, index })
  }, [scenario, index])

  const status: RunnerStatus = !scenario
    ? 'idle'
    : paused ? 'paused'
    : awaitingUser ? 'awaiting-user'
    : 'playing'

  return {
    state: { scenario, index, status, rect },
    status,
    api: { start, next, prev, goTo, pause, resume, exit },
  }
}

import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { X, ArrowRight, ArrowLeft, Pause, Play, MousePointerClick } from 'lucide-react'
import { placeCard, type Pos } from '../../lib/tour/place'
import type { RunnerStatus, TourApi, TourScenario } from '../../lib/tour/types'

const CARD_W = 344

export function Coachmark({
  scenario, index, rect, status, api,
}: {
  scenario: TourScenario
  index: number
  rect: DOMRect | null
  status: RunnerStatus
  api: TourApi
}) {
  const step = scenario.steps[index]
  const n = scenario.steps.length
  const isLast = index === n - 1
  const interactive = step.mode?.kind === 'interactive'
  const ref = useRef<HTMLDivElement>(null)
  const primaryRef = useRef<HTMLButtonElement>(null)
  const [pos, setPos] = useState<Pos | null>(null)

  // measure the card, then place it beside the spotlight (flip + clamp). Runs before
  // paint so there's no flash; re-runs as the tracked rect moves so the card follows.
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    setPos(placeCard(rect, step.placement ?? 'auto', { w: el.offsetWidth, h: el.offsetHeight }))
  }, [rect, index, step.placement])

  // On an auto (modal) step the app is inert, so move focus into the coachmark — its
  // primary action — giving keyboard users a trapped focus region. Interactive steps
  // instead focus the spotlighted control (handled by the controller), so skip those.
  useEffect(() => {
    if (!interactive) primaryRef.current?.focus()
    // eslint-disable-next-line react-hooks/exhaustive-deps -- focus once per step, not per rect
  }, [index, interactive])

  return (
    <div
      ref={ref}
      role="dialog"
      aria-modal={interactive ? undefined : true}
      aria-labelledby="ow-tour-title"
      aria-describedby="ow-tour-body"
      style={{
        position: 'fixed',
        left: pos?.left ?? -9999,
        top: pos?.top ?? -9999,
        width: CARD_W,
        maxWidth: 'calc(100vw - 24px)',
        zIndex: 70,
      }}
      className="rounded-2xl border border-line bg-panel shadow-2xl p-4"
    >
      {/* eyebrow: scenario + step counter */}
      <div className="flex items-center gap-2.5 mb-2">
        <span className="h-[3px] w-6 rounded ow-grad" />
        <span className="text-[11px] font-mono font-semibold text-ink3 truncate flex-1">{scenario.title}</span>
        <span className="text-[11px] font-mono text-ink3 tabular-nums shrink-0">{index + 1} / {n}</span>
        <button
          onClick={api.exit}
          aria-label="End tour"
          className="h-6 w-6 grid place-items-center rounded-md text-ink3 hover:text-ink hover:bg-panel2 shrink-0"
        >
          <X size={14} />
        </button>
      </div>

      <h3 id="ow-tour-title" className="text-[15px] font-bold text-ink text-balance">{step.title}</h3>
      <div id="ow-tour-body" className="text-sm text-ink2 leading-relaxed mt-1.5">{step.body}</div>

      {interactive && (
        <div className="mt-3 flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold"
          style={{ background: 'var(--accentdim)', color: 'var(--accent)' }}>
          <MousePointerClick size={14} className="shrink-0" />
          {step.mode?.kind === 'interactive' && step.mode.hint ? step.mode.hint : 'Your turn — click the highlighted control to continue.'}
        </div>
      )}

      {/* progress spine */}
      <div className="mt-3 h-1 rounded-full overflow-hidden" style={{ background: 'var(--panel2)' }}>
        <div className="h-full ow-grad transition-all duration-300" style={{ width: `${((index + 1) / n) * 100}%` }} />
      </div>

      {/* controls */}
      <div className="mt-3 flex items-center gap-2">
        <button
          onClick={api.prev}
          disabled={index === 0}
          className="flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-xs font-semibold text-ink2 hover:bg-panel2 disabled:opacity-40"
        >
          <ArrowLeft size={13} /> Back
        </button>

        {!interactive && !isLast && (
          <button
            onClick={() => (status === 'paused' ? api.resume() : api.pause())}
            aria-label={status === 'paused' ? 'Resume' : 'Pause'}
            className="h-8 w-8 grid place-items-center rounded-lg text-ink3 hover:text-ink hover:bg-panel2"
          >
            {status === 'paused' ? <Play size={14} /> : <Pause size={14} />}
          </button>
        )}

        <div className="flex-1" />

        {interactive && !isLast && (
          <button onClick={api.next} className="rounded-lg px-2.5 py-1.5 text-xs font-semibold text-ink3 hover:text-ink hover:bg-panel2">
            Skip
          </button>
        )}
        <button
          ref={primaryRef}
          onClick={isLast ? api.exit : api.next}
          className="flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-bold text-white ow-grad shadow-sm hover:opacity-90"
        >
          {isLast ? 'Finish' : 'Next'} {!isLast && <ArrowRight size={13} />}
        </button>
      </div>
    </div>
  )
}

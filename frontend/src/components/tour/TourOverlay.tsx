import { useEffect } from 'react'
import { createPortal } from 'react-dom'
import { useTour } from '../../lib/tour/TourProvider'
import { Spotlight } from './Spotlight'
import { Coachmark } from './Coachmark'

// Portalled to document.body so `fixed` rects are viewport-true (escaping AppShell's
// overflow-hidden + TopBar's backdrop-blur containing blocks) and the overlay survives
// route changes. Renders nothing when the tour is idle — screens stay untouched.
export function TourOverlay() {
  const { state, status, api } = useTour()
  const { scenario, index, rect } = state
  const step = scenario?.steps[index] ?? null
  const interactive = step?.mode?.kind === 'interactive'

  // Auto (modal) steps: make the rest of the app inert so interaction + focus are
  // confined to the coachmark. Interactive steps leave the app reachable so the user
  // can click the spotlighted control.
  useEffect(() => {
    const root = document.getElementById('root')
    if (!root) return
    if (status !== 'idle' && !interactive) root.setAttribute('inert', '')
    else root.removeAttribute('inert')
    return () => root.removeAttribute('inert')
  }, [status, interactive])

  if (status === 'idle' || !scenario || !step) return null

  return createPortal(
    <>
      <Spotlight rect={rect} interactive={interactive} />
      <Coachmark scenario={scenario} index={index} rect={rect} status={status} api={api} />
      <div aria-live="polite" role="status" className="sr-only">
        {`Step ${index + 1} of ${scenario.steps.length}: ${step.title}`}
      </div>
    </>,
    document.body,
  )
}

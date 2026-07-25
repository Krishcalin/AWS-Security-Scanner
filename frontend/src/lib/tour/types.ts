import { type ReactNode } from 'react'

// The product tour "replays canned scenarios over the real console". Because scope and
// every panel now live in the URL, a step is almost pure data: it declares WHERE to be
// (route + scope + panel params → one URL the controller navigates to) and WHAT to
// spotlight (a data-tour anchor). No step reaches into a screen's internal state.

export type Placement = 'auto' | 'top' | 'bottom' | 'left' | 'right'

/** Auto steps advance on a timer; interactive ("take-the-wheel") steps pause until the
 *  user clicks the spotlighted real control, which advances the tour. */
export type StepMode =
  | { kind: 'auto' }
  | { kind: 'interactive'; hint?: string }

export interface TourStep {
  id: string
  route?: string                    // pathname; omit ⇒ stay on the current route
  scope?: string                    // 'org' | 12-digit account id → becomes ?scope=
  params?: Record<string, string>   // panel params, e.g. { path: 'internet__customers-db' }
  anchor?: string                   // data-tour value to spotlight; omit ⇒ centered card
  waitFor?: string                  // extra anchor to await first (e.g. a panel's inner body)
  title: string
  body: ReactNode
  placement?: Placement
  mode?: StepMode                   // default { kind: 'auto' }
  dwellMs?: number                  // auto-advance dwell override
  optional?: boolean                // if the anchor never resolves, skip instead of centering
}

export interface TourScenario {
  id: string
  title: string
  persona: string
  summary: string
  estMinutes: number
  steps: TourStep[]
}

export type RunnerStatus = 'idle' | 'playing' | 'paused' | 'awaiting-user' | 'done'

export interface TourApi {
  start: (scenarioId: string, atIndex?: number) => void
  next: () => void
  prev: () => void
  goTo: (i: number) => void
  pause: () => void
  resume: () => void
  exit: () => void
}

export interface TourState {
  scenario: TourScenario | null
  index: number
  status: RunnerStatus
  rect: DOMRect | null              // spotlight target rect (null ⇒ centered coachmark)
}

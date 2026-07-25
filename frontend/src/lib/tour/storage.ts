// First-run "seen" flag (localStorage) + a lightweight resume position (sessionStorage).
// All access is wrapped so a disabled/quota-full storage never throws into the UI.

const SEEN_KEY = 'ow.tour.seen'
const POS_KEY = 'ow.tour.pos'

function safeGet(store: Storage, key: string): string | null {
  try { return store.getItem(key) } catch { return null }
}
function safeSet(store: Storage, key: string, val: string): void {
  try { store.setItem(key, val) } catch { /* storage disabled — ignore */ }
}
function safeRemove(store: Storage, key: string): void {
  try { store.removeItem(key) } catch { /* ignore */ }
}

export function hasSeenTour(): boolean {
  return safeGet(localStorage, SEEN_KEY) === '1'
}
export function markTourSeen(): void {
  safeSet(localStorage, SEEN_KEY, '1')
}

export interface ResumePos { scenarioId: string; index: number }

export function saveResume(pos: ResumePos): void {
  safeSet(sessionStorage, POS_KEY, `${pos.scenarioId}:${pos.index}`)
}
export function loadResume(): ResumePos | null {
  const raw = safeGet(sessionStorage, POS_KEY)
  if (!raw) return null
  const i = raw.lastIndexOf(':')
  if (i < 0) return null
  const index = Number(raw.slice(i + 1))
  if (!Number.isInteger(index) || index < 0) return null
  return { scenarioId: raw.slice(0, i), index }
}
export function clearResume(): void {
  safeRemove(sessionStorage, POS_KEY)
}

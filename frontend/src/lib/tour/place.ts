import type { Placement } from './types'

const MARGIN = 12
const GAP = 14

export interface Box { w: number; h: number }
export interface Pos { left: number; top: number }

const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v))

/**
 * Place the coachmark near the spotlight, flipping to whichever side has room and
 * clamping to the viewport. A null rect centers the card (intro/outro/degraded steps).
 */
export function placeCard(rect: DOMRect | null, placement: Placement, card: Box): Pos {
  const vw = window.innerWidth
  const vh = window.innerHeight
  if (!rect) {
    return { left: (vw - card.w) / 2, top: Math.max(MARGIN, (vh - card.h) / 2) }
  }

  const cx = rect.left + rect.width / 2 - card.w / 2
  const cy = rect.top + rect.height / 2 - card.h / 2
  const cand: Record<Exclude<Placement, 'auto'>, Pos & { fits: boolean }> = {
    bottom: { left: cx, top: rect.bottom + GAP, fits: rect.bottom + GAP + card.h <= vh - MARGIN },
    top: { left: cx, top: rect.top - GAP - card.h, fits: rect.top - GAP - card.h >= MARGIN },
    right: { left: rect.right + GAP, top: cy, fits: rect.right + GAP + card.w <= vw - MARGIN },
    left: { left: rect.left - GAP - card.w, top: cy, fits: rect.left - GAP - card.w >= MARGIN },
  }

  const order: Exclude<Placement, 'auto'>[] =
    placement === 'auto'
      ? ['bottom', 'top', 'right', 'left']
      : [placement, 'bottom', 'top', 'right', 'left']

  const chosen = order.map((k) => cand[k]).find((c) => c.fits) ?? cand.bottom
  return {
    left: clamp(chosen.left, MARGIN, vw - card.w - MARGIN),
    top: clamp(chosen.top, MARGIN, vh - card.h - MARGIN),
  }
}

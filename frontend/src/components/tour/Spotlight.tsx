import type { CSSProperties } from 'react'
import { reducedMotion } from '../../lib/tour/anchor'

// A four-pane dim mask that leaves the anchor rect uncovered. In modal (auto) mode a
// fifth transparent pane covers the hole so the app can't be clicked; in interactive
// mode the hole is left open so the user can click the real spotlighted control. A
// null rect dims the whole viewport (intro/outro/centered steps).
const SCRIM = 'rgba(8, 12, 22, 0.55)'   // always-dark scrim (theme-independent)
const PAD = 6

export function Spotlight({ rect, interactive }: { rect: DOMRect | null; interactive: boolean }) {
  if (!rect) {
    return <div style={{ position: 'fixed', inset: 0, background: SCRIM, pointerEvents: 'auto', zIndex: 60 }} />
  }
  const vw = window.innerWidth
  const vh = window.innerHeight
  const x = rect.left - PAD
  const y = rect.top - PAD
  const w = rect.width + PAD * 2
  const h = rect.height + PAD * 2
  const pane: CSSProperties = { position: 'fixed', background: SCRIM, pointerEvents: 'auto', zIndex: 60 }

  return (
    <>
      <div style={{ ...pane, left: 0, top: 0, width: '100%', height: Math.max(0, y) }} />
      <div style={{ ...pane, left: 0, top: y, width: Math.max(0, x), height: h }} />
      <div style={{ ...pane, left: x + w, top: y, width: Math.max(0, vw - (x + w)), height: h }} />
      <div style={{ ...pane, left: 0, top: y + h, width: '100%', height: Math.max(0, vh - (y + h)) }} />
      {/* modal: block clicks through the hole too */}
      {!interactive && <div style={{ position: 'fixed', left: x, top: y, width: w, height: h, pointerEvents: 'auto', zIndex: 60 }} />}
      {/* accent ring around the spotlight */}
      <div
        style={{
          position: 'fixed', left: x, top: y, width: w, height: h, borderRadius: 12, pointerEvents: 'none', zIndex: 61,
          boxShadow: '0 0 0 2px var(--accent), 0 0 0 7px color-mix(in srgb, var(--accent) 22%, transparent)',
          transition: reducedMotion() ? 'none' : 'left .18s ease, top .18s ease, width .18s ease, height .18s ease',
        }}
      />
    </>
  )
}

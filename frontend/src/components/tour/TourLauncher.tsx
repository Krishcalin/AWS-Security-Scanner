import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Compass, X, Play, Sparkles } from 'lucide-react'
import { useTour } from '../../lib/tour/TourProvider'
import { hasSeenTour, markTourSeen } from '../../lib/tour/storage'
import { Gallery } from './Gallery'

const FLAGSHIP = 'attack-path-101'

// Floating launcher + first-run prompt. The prompt only PROMPTS (never auto-starts),
// is dismissible, and shows once — the localStorage check is ref-guarded so React 19
// StrictMode's double-mount can't double-fire it.
export function TourLauncher() {
  const { status, api, galleryOpen, openGallery, closeGallery } = useTour()
  const [prompt, setPrompt] = useState(false)
  const checked = useRef(false)

  useEffect(() => {
    if (checked.current) return
    checked.current = true
    if (!hasSeenTour()) setPrompt(true)
  }, [])

  if (status !== 'idle') return null   // the overlay owns the screen while a tour runs

  const startTour = (id: string, atIndex?: number) => { closeGallery(); setPrompt(false); markTourSeen(); api.start(id, atIndex) }
  const dismiss = () => { setPrompt(false); markTourSeen() }
  const browse = () => { setPrompt(false); markTourSeen(); openGallery() }

  return createPortal(
    <>
      <button
        data-tour="tour-launcher"
        onClick={() => (galleryOpen ? closeGallery() : openGallery())}
        aria-label="Take a tour"
        title="Take a tour"
        className="fixed bottom-5 right-5 z-[74] h-12 w-12 grid place-items-center rounded-full ow-grad text-white shadow-lg hover:scale-105 transition-transform"
      >
        <Compass size={20} />
      </button>

      {galleryOpen && <Gallery onPick={startTour} onClose={closeGallery} />}

      {prompt && !galleryOpen && (
        <div className="fixed bottom-20 right-5 z-[74] w-[min(340px,calc(100vw-24px))] rounded-2xl border border-line bg-panel shadow-2xl p-4">
          <div className="flex items-start gap-2.5">
            <span className="h-8 w-8 rounded-lg ow-grad grid place-items-center text-white shrink-0"><Sparkles size={16} /></span>
            <div className="flex-1">
              <div className="text-sm font-bold text-ink">New to OverWatch?</div>
              <div className="text-xs text-ink2 mt-0.5 leading-relaxed">Take a 2-minute guided tour — trace a real attack path from the internet to the customer database, over this live console.</div>
            </div>
            <button onClick={dismiss} aria-label="Dismiss" className="h-6 w-6 grid place-items-center rounded-md text-ink3 hover:text-ink hover:bg-panel2 shrink-0"><X size={14} /></button>
          </div>
          <div className="flex items-center gap-2 mt-3">
            <button onClick={() => startTour(FLAGSHIP)} className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-bold text-white ow-grad shadow-sm hover:opacity-90">
              <Play size={12} /> Start the tour
            </button>
            <button onClick={browse} className="rounded-lg px-3 py-1.5 text-xs font-semibold text-ink2 hover:bg-panel2">Browse tours</button>
          </div>
        </div>
      )}
    </>,
    document.body,
  )
}

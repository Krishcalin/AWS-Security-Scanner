import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useTourController } from './useTourController'
import { runDevValidation } from './validate'
import type { RunnerStatus, TourApi, TourState } from './types'

interface TourCtx {
  state: TourState
  status: RunnerStatus
  api: TourApi
  galleryOpen: boolean
  openGallery: () => void
  closeGallery: () => void
}

const Ctx = createContext<TourCtx | null>(null)

export function TourProvider({ children }: { children: ReactNode }) {
  const ctrl = useTourController()
  const { status, api } = ctrl
  const [galleryOpen, setGalleryOpen] = useState(false)
  const openGallery = useCallback(() => setGalleryOpen(true), [])
  const closeGallery = useCallback(() => setGalleryOpen(false), [])
  // a running scenario always hides the gallery
  useEffect(() => { if (status !== 'idle') setGalleryOpen(false) }, [status])

  // DEV-only structural check of the scenario registry (ref-guarded for StrictMode).
  const validated = useRef(false)
  useEffect(() => {
    if (validated.current || !import.meta.env.DEV) return
    validated.current = true
    runDevValidation()
  }, [])

  const value = useMemo<TourCtx>(
    () => ({ ...ctrl, galleryOpen, openGallery, closeGallery }),
    [ctrl, galleryOpen, openGallery, closeGallery],
  )

  // Keyboard controls while a scenario is running (Esc / ← / → / Space-to-pause).
  useEffect(() => {
    if (status === 'idle') return
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null
      const typing = !!t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)
      if (typing) return   // never hijack keys while the user is typing (interactive steps leave inputs reachable)
      if (e.key === 'Escape') { e.preventDefault(); api.exit() }
      else if (e.key === 'ArrowRight') { e.preventDefault(); api.next() }
      else if (e.key === 'ArrowLeft') { e.preventDefault(); api.prev() }
      else if (e.key === ' ' && status !== 'awaiting-user') {
        e.preventDefault()
        if (status === 'paused') api.resume(); else api.pause()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [status, api])

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useTour(): TourCtx {
  const c = useContext(Ctx)
  if (!c) throw new Error('useTour must be used within a TourProvider')
  return c
}

import { X, Play, Clock, RotateCcw, Compass } from 'lucide-react'
import { SCENARIOS, getScenario } from '../../lib/tour/scenarios'
import { loadResume } from '../../lib/tour/storage'

// The scenario picker. Reads the pure SCENARIOS registry, so it needs zero knowledge
// of any screen. Shows a Resume affordance when a session position was saved.
export function Gallery({ onPick, onClose }: { onPick: (id: string, atIndex?: number) => void; onClose: () => void }) {
  const resume = loadResume()
  const resumeScenario = resume ? getScenario(resume.scenarioId) : undefined
  const resumeValid = !!resumeScenario && resume!.index < resumeScenario.steps.length && resume!.index > 0

  return (
    <>
      <div className="fixed inset-0 z-[75]" onClick={onClose} />
      <div
        role="dialog"
        aria-label="Product tours"
        className="fixed z-[76] bottom-20 right-5 w-[min(400px,calc(100vw-24px))] rounded-2xl border border-line bg-panel shadow-2xl overflow-hidden"
      >
        <div className="flex items-center gap-2.5 px-4 py-3 border-b border-line">
          <span className="h-7 w-7 rounded-lg ow-grad grid place-items-center text-white shrink-0"><Compass size={15} /></span>
          <div className="leading-tight flex-1">
            <div className="text-sm font-bold text-ink">Take a tour</div>
            <div className="text-[11px] text-ink3">Guided replays over the live console · sample data</div>
          </div>
          <button onClick={onClose} aria-label="Close" className="h-7 w-7 grid place-items-center rounded-md text-ink3 hover:text-ink hover:bg-panel2"><X size={15} /></button>
        </div>

        {resumeValid && (
          <button
            onClick={() => onPick(resume!.scenarioId, resume!.index)}
            className="flex w-full items-center gap-2.5 px-4 py-2.5 text-left border-b border-line2 hover:bg-panel2"
          >
            <RotateCcw size={15} className="text-accent shrink-0" />
            <span className="text-xs text-ink2 flex-1">
              Resume <b className="text-ink">{resumeScenario!.title}</b> · step {resume!.index + 1} of {resumeScenario!.steps.length}
            </span>
          </button>
        )}

        <div className="max-h-[60vh] overflow-y-auto p-2 flex flex-col gap-1.5">
          {SCENARIOS.map((s) => (
            <button
              key={s.id}
              onClick={() => onPick(s.id)}
              className="group w-full text-left rounded-xl border border-line bg-panel hover:border-accent/50 hover:shadow-sm transition-all p-3"
            >
              <div className="flex items-center gap-2 mb-1">
                <span className="h-6 w-6 rounded-lg grid place-items-center shrink-0 ow-grad text-white group-hover:scale-105 transition-transform"><Play size={12} /></span>
                <span className="text-sm font-bold text-ink flex-1">{s.title}</span>
                <span className="text-[11px] text-ink3 flex items-center gap-1 shrink-0"><Clock size={11} /> {s.estMinutes} min</span>
              </div>
              <div className="text-xs text-ink2 leading-relaxed">{s.summary}</div>
              <div className="text-[11px] text-ink3 mt-1.5">{s.persona} · {s.steps.length} steps</div>
            </button>
          ))}
        </div>
      </div>
    </>
  )
}

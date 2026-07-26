import { useEffect, useRef, useState } from 'react'
import { Sparkles, X, ArrowUp, ShieldCheck, Info } from 'lucide-react'
import { useScope } from '../state/scope'
import { useDeepLinkPanel } from '../lib/deeplink'
import { api } from '../api/client'
import { renderAnswer, citationLabel, type Span, type AnswerLine } from '../lib/copilot'
import { Loader, ErrorNote, Chip } from './ui'
import type { CopilotAnswer } from '../api/types'

const SUGGESTIONS = [
  'What are my top risks?',
  'Show me the attack paths',
  'What should I fix first?',
  'How do I fix ATTACK-01?',
]

type Msg =
  | { role: 'user'; text: string }
  | { role: 'assistant'; answer: CopilotAnswer }
  | { role: 'error'; text: string }

function Spans({ spans }: { spans: Span[] }) {
  return (
    <>
      {spans.map((s, i) =>
        s.bold ? <b key={i} className="font-semibold text-ink">{s.text}</b>
        : s.code ? <code key={i} className="font-mono text-[0.85em] rounded px-1 py-0.5" style={{ background: 'var(--panel2)', color: 'var(--accent)' }}>{s.text}</code>
        : <span key={i}>{s.text}</span>,
      )}
    </>
  )
}

function AnswerBody({ lines }: { lines: AnswerLine[] }) {
  return (
    <div className="flex flex-col gap-1.5 text-sm leading-relaxed text-ink2">
      {lines.map((l, i) => {
        if (l.kind === 'bullet')
          return <div key={i} className="flex gap-2"><span className="text-ink3 select-none">•</span><span><Spans spans={l.spans} /></span></div>
        if (l.kind === 'step')
          return (
            <div key={i} className="flex gap-2.5 pl-1">
              <span className="shrink-0 h-5 w-5 rounded-full grid place-items-center text-[11px] font-mono font-bold mt-0.5" style={{ background: 'var(--accentdim)', color: 'var(--accent)' }}>{l.num}</span>
              <span><Spans spans={l.spans} /></span>
            </div>
          )
        if (l.kind === 'sub')
          return <div key={i} className="pl-5 text-ink3"><Spans spans={l.spans} /></div>
        return <div key={i}><Spans spans={l.spans} /></div>
      })}
    </div>
  )
}

function AssistantMsg({ answer }: { answer: CopilotAnswer }) {
  const lines = renderAnswer(answer.answer)
  return (
    <div className="flex flex-col gap-2.5 rounded-2xl rounded-tl-sm border border-line px-4 py-3" style={{ background: 'var(--panel)' }}>
      {answer.abstained ? (
        <div className="flex items-start gap-2 text-sm text-ink2">
          <Info size={15} className="mt-0.5 shrink-0 text-ink3" />
          <span>{answer.answer}</span>
        </div>
      ) : (
        <AnswerBody lines={lines} />
      )}

      {answer.citations.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-line2">
          <span className="text-[11px] font-semibold uppercase tracking-wide text-ink3 mr-0.5">Sources</span>
          {answer.citations.map((c) => (
            <Chip key={c} mono>{citationLabel(c)}</Chip>
          ))}
        </div>
      )}

      {!answer.abstained && answer.mode === 'extractive' && (
        <div className="flex items-center gap-1.5 text-[11px] text-ink3">
          <ShieldCheck size={12} style={{ color: 'var(--low)' }} />
          <span>Grounded · retrieval-only · answered from this scan, nothing left your boundary</span>
        </div>
      )}
    </div>
  )
}

export function CopilotPanel() {
  const [open, setOpen] = useDeepLinkPanel('copilot')
  const { scope } = useScope()
  const [messages, setMessages] = useState<Msg[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const endRef = useRef<HTMLDivElement>(null)

  // a fresh conversation per scope — old citations belong to the previous account
  useEffect(() => { setMessages([]) }, [scope])
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages, loading])

  if (open == null) return null

  const scopeLabel = scope === 'org' ? 'the organization' : `account ${scope}`

  const ask = async (question: string) => {
    const q = question.trim()
    if (!q || loading) return
    setInput('')
    setMessages((m) => [...m, { role: 'user', text: q }])
    setLoading(true)
    try {
      const answer = await api.copilot(scope, q)
      setMessages((m) => [...m, { role: 'assistant', answer }])
    } catch (e) {
      setMessages((m) => [...m, { role: 'error', text: e instanceof Error ? e.message : String(e) }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-40">
      <div className="absolute inset-0 bg-black/30 backdrop-blur-sm" onClick={() => setOpen(null)} />
      <aside className="absolute right-0 top-0 bottom-0 w-full max-w-[560px] bg-canvas border-l border-line shadow-2xl flex flex-col">
        <div className="sticky top-0 z-10 bg-canvas/90 backdrop-blur border-b border-line px-5 py-3.5 flex items-center gap-2.5">
          <span className="h-7 w-7 grid place-items-center rounded-lg text-white ow-grad"><Sparkles size={15} /></span>
          <div className="flex flex-col leading-tight">
            <span className="text-sm font-extrabold text-ink">Ask OverWatch</span>
            <span className="text-[11px] text-ink3">Grounded in {scopeLabel}'s own scan</span>
          </div>
          <button onClick={() => setOpen(null)} className="ml-auto h-8 w-8 grid place-items-center rounded-lg border border-line text-ink3 hover:text-ink"><X size={16} /></button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-4 flex flex-col gap-4">
          {messages.length === 0 && (
            <div className="flex flex-col gap-3 pt-4">
              <p className="text-sm text-ink2 leading-relaxed">
                Ask about your findings, attack paths, choke points, or how to remediate a specific check.
                Answers are composed <b className="text-ink">only</b> from this scan — no data leaves your boundary,
                and I abstain rather than invent.
              </p>
              <div className="flex flex-col gap-1.5">
                {SUGGESTIONS.map((s) => (
                  <button
                    key={s}
                    onClick={() => ask(s)}
                    className="text-left rounded-xl border border-line px-3.5 py-2.5 text-sm text-ink2 hover:border-accent/40 hover:text-ink transition-colors"
                    style={{ background: 'var(--panel)' }}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>
          )}

          {messages.map((m, i) =>
            m.role === 'user' ? (
              <div key={i} className="self-end max-w-[85%] rounded-2xl rounded-tr-sm px-3.5 py-2 text-sm text-white ow-grad">{m.text}</div>
            ) : m.role === 'assistant' ? (
              <div key={i} className="max-w-[92%]"><AssistantMsg answer={m.answer} /></div>
            ) : (
              <div key={i} className="max-w-[92%]"><ErrorNote msg={m.text} /></div>
            ),
          )}

          {loading && <div className="max-w-[92%]"><Loader label="Reading your scan…" /></div>}
          <div ref={endRef} />
        </div>

        <div className="border-t border-line px-4 py-3">
          <div className="flex items-end gap-2 rounded-2xl border border-line px-3 py-2" style={{ background: 'var(--panel)' }}>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ask(input) } }}
              rows={1}
              placeholder="Ask about this scan…"
              className="flex-1 resize-none bg-transparent text-sm text-ink placeholder:text-ink3 outline-none max-h-32 leading-relaxed"
            />
            <button
              onClick={() => ask(input)}
              disabled={!input.trim() || loading}
              title="Send"
              className="shrink-0 h-8 w-8 grid place-items-center rounded-lg text-white ow-grad disabled:opacity-40 transition-opacity"
            >
              <ArrowUp size={16} />
            </button>
          </div>
          <p className="text-[11px] text-ink3 mt-1.5 text-center">Enter to send · Shift+Enter for a new line</p>
        </div>
      </aside>
    </div>
  )
}

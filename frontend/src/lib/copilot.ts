// Pure, testable helpers for the grounded copilot panel — NO React, NO DOM, so the
// shipped vitest (node env, `src/**/*.test.ts`) can exercise them against the fixture.
// The backend answer text is markdown-lite (`- **ID** (SEV): …`, numbered `1.` steps,
// `**bold**`, `` `code` ``); the panel renders the line model this produces.
import { lastSeg } from './deeplink'

export type Span = { text: string; bold?: boolean; code?: boolean }
export type AnswerLine =
  | { kind: 'bullet'; spans: Span[] }
  | { kind: 'step'; num: number; spans: Span[] }
  | { kind: 'sub'; spans: Span[] } // an indented continuation ("  Fix: …", "Affected: …")
  | { kind: 'text'; spans: Span[] } // a header / plain line

/** Split a line into ordered bold (`**..**`) / code (`` `..` ``) / plain spans. */
export function parseSpans(text: string): Span[] {
  const spans: Span[] = []
  const re = /\*\*(.+?)\*\*|`([^`]+)`/g
  let last = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) spans.push({ text: text.slice(last, m.index) })
    if (m[1] !== undefined) spans.push({ text: m[1], bold: true })
    else spans.push({ text: m[2], code: true })
    last = re.lastIndex
  }
  if (last < text.length) spans.push({ text: text.slice(last) })
  return spans.length ? spans : [{ text }]
}

/** Parse the backend's markdown-lite answer into a renderable line model. */
export function renderAnswer(text: string): AnswerLine[] {
  const lines: AnswerLine[] = []
  for (const raw of (text || '').split('\n')) {
    if (!raw.trim()) continue
    const step = raw.match(/^\s*(\d+)\.\s+(.*)$/)
    if (step) {
      lines.push({ kind: 'step', num: Number(step[1]), spans: parseSpans(step[2]) })
      continue
    }
    const bullet = raw.match(/^\s*-\s+(.*)$/)
    if (bullet) {
      lines.push({ kind: 'bullet', spans: parseSpans(bullet[1]) })
      continue
    }
    if (/^\s{2,}\S/.test(raw)) {
      lines.push({ kind: 'sub', spans: parseSpans(raw.trim()) })
      continue
    }
    lines.push({ kind: 'text', spans: parseSpans(raw.trim()) })
  }
  return lines
}

/** Pick the sample-mode canned answer whose LONGEST matched keyword is longest — i.e. the
 *  MOST SPECIFIC match — so a broad keyword ("summary") never shadows a specific one
 *  ("attack path") regardless of fixture array order. Returns null when nothing matches. */
export function pickCopilotAnswer<T extends { match: string[] }>(answers: T[], question: string): T | null {
  const q = (question || '').toLowerCase()
  let best: T | null = null
  let bestLen = 0
  for (const a of answers) {
    let longest = 0
    for (const m of a.match) if (q.includes(m) && m.length > longest) longest = m.length
    if (longest > bestLen) { bestLen = longest; best = a }
  }
  return best
}

/** Human-readable label for a citation id: a path index, a check id, or a node/ARN tail. */
export function citationLabel(id: string): string {
  const p = id.match(/^path:(\d+)$/)
  if (p) return `Attack path #${Number(p[1]) + 1}`
  if (/^[A-Z][A-Z0-9]*-\d+$/.test(id)) return id // a check id (ATTACK-01, IAM-02, S3-01)
  return lastSeg(id) // a node id / ARN (choke point) → its last meaningful segment
}

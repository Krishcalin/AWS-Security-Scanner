import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import { renderAnswer, parseSpans, citationLabel, pickCopilotAnswer } from './copilot'

// Fixtures are the source of truth: the copilot.json canned answers must keep the exact
// backend answer() dict shape, and any check_id they cite must still exist in the findings
// fixture — a drift fails the build (mirrors deeplink.test.ts / scenarios.test.ts).
const SAMPLE = join(process.cwd(), 'public', 'sample')
const read = (f: string) => JSON.parse(readFileSync(join(SAMPLE, f), 'utf-8'))
const CHECK_ID = /^[A-Z][A-Z0-9]*-\d+$/

describe('parseSpans', () => {
  it('splits bold and code runs in order', () => {
    expect(parseSpans('Fix **ATTACK-01** via `aws iam` now')).toEqual([
      { text: 'Fix ' }, { text: 'ATTACK-01', bold: true },
      { text: ' via ' }, { text: 'aws iam', code: true }, { text: ' now' },
    ])
  })
  it('returns a single plain span when there is no markup', () => {
    expect(parseSpans('plain text')).toEqual([{ text: 'plain text' }])
  })
})

describe('renderAnswer', () => {
  it('classifies headers, bullets, sub-lines and numbered steps', () => {
    const lines = renderAnswer('Top risks:\n- **ATTACK-01** (CRITICAL): exposed\n  Fix: patch it\n  1. do a thing')
    expect(lines.map((l) => l.kind)).toEqual(['text', 'bullet', 'sub', 'step'])
    const step = lines[3]
    expect(step.kind === 'step' && step.num).toBe(1)
  })
  it('skips blank lines', () => {
    expect(renderAnswer('a\n\n\nb')).toHaveLength(2)
  })
})

describe('citationLabel', () => {
  it('humanises a path id (0-indexed → #1)', () => expect(citationLabel('path:0')).toBe('Attack path #1'))
  it('keeps a check id as-is', () => expect(citationLabel('IAM-02')).toBe('IAM-02'))
  it('takes the last segment of a node id / ARN', () =>
    expect(citationLabel('arn:aws:ec2:us-east-1:123456789012:instance/i-0app01server')).toBe('i-0app01server'))
})

describe('pickCopilotAnswer — most-specific (longest keyword) wins, not array order', () => {
  const fx = read('copilot.json')
  const intentOf = (q: string) => pickCopilotAnswer(fx.answers, q)?.answer.intent

  it('a broad keyword does not shadow a specific one', () => {
    // "summary" (top_risks) must NOT beat "attack path" (paths); "most critical" must NOT
    // beat "how do i remediate" (fix) — the exact shadowing the first-hit matcher exhibited.
    expect(intentOf('summarize the attack paths')).toBe('paths')
    expect(intentOf('how do i remediate the most critical finding?')).toBe('fix')
  })
  it('still routes a plain broad question to top_risks', () => {
    expect(intentOf('what are my top risks?')).toBe('top_risks')
  })
  it('returns null when nothing matches', () => {
    expect(pickCopilotAnswer(fx.answers, 'weather in paris')).toBeNull()
  })
})

describe('copilot.json fixture is well-formed and grounded', () => {
  const fx = read('copilot.json')
  const findingIds = new Set(
    (read('account_123456789012_findings.json') as { check_id: string }[]).map((f) => f.check_id))

  it('every canned answer carries the backend answer() shape', () => {
    expect(fx.answers.length).toBeGreaterThan(0)
    for (const entry of fx.answers) {
      const a = entry.answer
      expect(Array.isArray(entry.match) && entry.match.length).toBeTruthy()
      expect(typeof a.answer).toBe('string')
      expect(Array.isArray(a.citations)).toBe(true)
      expect(Array.isArray(a.retrieved)).toBe(true)
      expect(typeof a.abstained).toBe('boolean')
      expect(['extractive', 'llm']).toContain(a.mode)
      expect(typeof a.intent).toBe('string')
    }
    expect(fx.abstain.abstained).toBe(true)
    expect(fx.abstain.citations).toEqual([])
  })

  it('finding-type citations resolve against the findings fixture', () => {
    for (const entry of fx.answers)
      for (const c of entry.answer.citations as string[])
        if (CHECK_ID.test(c)) expect(findingIds.has(c), `stale citation ${c}`).toBe(true)
  })

  it('every canned answer renders without throwing', () => {
    for (const entry of fx.answers) expect(renderAnswer(entry.answer.answer).length).toBeGreaterThan(0)
  })
})

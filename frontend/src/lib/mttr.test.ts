import { describe, it, expect } from 'vitest'
import { formatDuration, normalizeSeries, burndownTrend } from './mttr'

describe('formatDuration', () => {
  it('formats days / hours / minutes', () => {
    expect(formatDuration(3 * 86400)).toBe('3.0d')
    expect(formatDuration(12 * 86400)).toBe('12d')       // ≥10d rounds to integer
    expect(formatDuration(5 * 3600)).toBe('5h')
    expect(formatDuration(30 * 60)).toBe('30m')
  })
  it('handles null / non-finite as an em-dash', () => {
    expect(formatDuration(null)).toBe('—')
    expect(formatDuration(undefined)).toBe('—')
    expect(formatDuration(Infinity)).toBe('—')
  })
})

describe('normalizeSeries', () => {
  it('scales to [0,1] over its own min..max', () => {
    expect(normalizeSeries([10, 20, 30])).toEqual([0, 0.5, 1])
  })
  it('a flat series maps to 0.5 (no divide-by-zero)', () => {
    expect(normalizeSeries([7, 7, 7])).toEqual([0.5, 0.5, 0.5])
  })
})

describe('burndownTrend', () => {
  it('down = fewer open findings than the start (improving)', () => {
    expect(burndownTrend([40, 30, 22])).toBe('down')
    expect(burndownTrend([10, 20, 35])).toBe('up')
    expect(burndownTrend([15, 12, 15])).toBe('flat')
    expect(burndownTrend([5])).toBe('flat')
  })
})

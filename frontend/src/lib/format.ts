// Presentation helpers — the ONE severity color law, grade/score coloring, time.

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const

const SEV_FG: Record<string, string> = {
  CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)',
  LOW: 'var(--low)', INFO: 'var(--info)',
}
const SEV_BG: Record<string, string> = {
  CRITICAL: 'var(--critbg)', HIGH: 'var(--highbg)', MEDIUM: 'var(--medbg)',
  LOW: 'var(--lowbg)', INFO: 'var(--infobg)',
}

export const sevColor = (s: string): string => SEV_FG[(s || '').toUpperCase()] ?? 'var(--ink3)'
export const sevBg = (s: string): string => SEV_BG[(s || '').toUpperCase()] ?? 'var(--panel2)'

export function gradeColor(grade: string): string {
  switch ((grade || '').toUpperCase()) {
    case 'A': return 'var(--low)'
    case 'B': return 'var(--info)'
    case 'C': return 'var(--med)'
    case 'D': return 'var(--high)'
    default: return 'var(--crit)'
  }
}

export function scoreColor(score: number): string {
  if (score >= 80) return 'var(--low)'
  if (score >= 60) return 'var(--med)'
  if (score >= 40) return 'var(--high)'
  return 'var(--crit)'
}

/** short account label: alias if any, else the 12-digit id */
export const acctLabel = (alias: string | undefined, id: string): string => alias || id

export function relTime(epoch: number | null | undefined): string {
  if (!epoch) return 'never'
  const d = Date.now() / 1000 - epoch
  if (d < 90) return 'just now'
  if (d < 3600) return `${Math.round(d / 60)}m ago`
  if (d < 86400) return `${Math.round(d / 3600)}h ago`
  return `${Math.round(d / 86400)}d ago`
}

export function healthTone(health: string): { fg: string; bg: string; label: string } {
  switch ((health || '').toLowerCase()) {
    case 'healthy': return { fg: 'var(--low)', bg: 'var(--lowbg)', label: 'Healthy' }
    case 'degraded': return { fg: 'var(--med)', bg: 'var(--medbg)', label: 'Degraded' }
    case 'unauthorized': return { fg: 'var(--crit)', bg: 'var(--critbg)', label: 'Unauthorized' }
    case 'validating': return { fg: 'var(--info)', bg: 'var(--infobg)', label: 'Validating' }
    default: return { fg: 'var(--ink3)', bg: 'var(--panel2)', label: health || 'Unknown' }
  }
}

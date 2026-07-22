// Class-based light/dark theme (the `.dark` variant drives the token overrides).
const KEY = 'ow-theme'

export function initTheme(): boolean {
  const saved = localStorage.getItem(KEY)
  const dark = saved
    ? saved === 'dark'
    : window.matchMedia('(prefers-color-scheme: dark)').matches
  document.documentElement.classList.toggle('dark', dark)
  return dark
}

export function applyTheme(dark: boolean): void {
  localStorage.setItem(KEY, dark ? 'dark' : 'light')
  document.documentElement.classList.toggle('dark', dark)
}

export const isDark = (): boolean => document.documentElement.classList.contains('dark')

import { useEffect, useState } from 'react'

export interface Async<T> {
  data: T | null
  loading: boolean
  error: string | null
}

/** Minimal async-data hook: re-runs `fn` when `deps` change, cancels stale results. */
export function useFetch<T>(fn: () => Promise<T>, deps: unknown[]): Async<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    let alive = true
    setLoading(true)
    setError(null)
    fn()
      .then((d) => alive && (setData(d), setLoading(false)))
      .catch((e) => alive && (setError(String(e?.message ?? e)), setLoading(false)))
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  return { data, loading, error }
}

import { useEffect, useRef, useState } from 'react'

export type SseEvent = { event: string; data: any; ts?: number }

export function useSse(url: string | null, enabled = true) {
  const [events, setEvents] = useState<SseEvent[]>([])
  const [connected, setConnected] = useState(false)
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    if (!url || !enabled) return
    // EventSource can't send headers: attach JWT as ?token= (backend accepts it)
    let finalUrl = url
    try {
      const t = localStorage.getItem('cipherpost_token')
      if (t && !url.includes('token=')) {
        finalUrl = url + (url.includes('?') ? '&' : '?') + `token=${encodeURIComponent(t)}`
      }
    } catch { /* private mode */ }
    const es = new EventSource(finalUrl)
    esRef.current = es
    es.onopen = () => setConnected(true)
    es.onerror = () => setConnected(false)
    const handler = (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data)
        setEvents((prev) => [{ event: e.type || data.event || 'message', data: data.data ?? data, ts: Date.now() }, ...prev].slice(0, 200))
      } catch {
        setEvents((prev) => [{ event: e.type, data: e.data, ts: Date.now() }, ...prev].slice(0, 200))
      }
    }
    // listen to all event types used by backend
    ;["sessions","findings","alerts","status","heartbeat","message"].forEach((ev) => es.addEventListener(ev, handler as any))
    es.onmessage = handler as any
    return () => {
      es.close()
      setConnected(false)
    }
  }, [url, enabled])

  return { events, connected }
}

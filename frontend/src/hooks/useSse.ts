import { useEffect, useRef, useState } from 'react'

export type SseEvent = { event: string; data: any; ts?: number }

const BASE = (import.meta as any).env?.VITE_API_BASE_URL ?? '/api/v1'

async function fetchSseTicket(): Promise<string | null> {
  try {
    const t = localStorage.getItem('cipherpost_token')
    if (!t) return null
    const res = await fetch(`${BASE}/live/ticket`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${t}` },
    })
    if (!res.ok) return null
    const body = (await res.json()) as { ticket?: string }
    return body.ticket ?? null
  } catch {
    return null
  }
}

export function useSse(url: string | null, enabled = true) {
  const [events, setEvents] = useState<SseEvent[]>([])
  const [connected, setConnected] = useState(false)
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    if (!url || !enabled) return
    let cancelled = false
    let es: EventSource | null = null
    // EventSource can't send headers: fetch a short-lived single-use ticket
    // with the Bearer token, then open the stream with ?ticket= (never ?token=).
    fetchSseTicket().then((ticket) => {
      if (cancelled) return
      let finalUrl = url
      if (ticket && !url.includes('ticket=') && !url.includes('token=')) {
        finalUrl = url + (url.includes('?') ? '&' : '?') + `ticket=${encodeURIComponent(ticket)}`
      }
      es = new EventSource(finalUrl)
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

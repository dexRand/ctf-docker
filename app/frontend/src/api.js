const BASE = '/api/v1'

export async function api(path, opts = {}) {
  const r = await fetch(BASE + path, opts)
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`)
  const ct = r.headers.get('content-type') || ''
  return ct.includes('application/json') ? r.json() : r.text()
}

export function wsUrl(path) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${location.host}${path}`
}

export function fmtSize(n) {
  if (n == null) return ''
  const u = ['B', 'KB', 'MB', 'GB']
  let f = n, i = 0
  while (f >= 1024 && i < u.length - 1) { f /= 1024; i++ }
  return `${i === 0 ? f : f.toFixed(1)}${u[i]}`
}

export function fmtDate(s) {
  if (!s) return ''
  try { return new Date(s).toLocaleString() } catch { return s }
}

export const STATUS_COLOR = {
  created: 'text-slate-400', queued: 'text-amber-400', running: 'text-amber-400',
  paused: 'text-sky-400', done: 'text-emerald-400', error: 'text-red-400', cancelled: 'text-slate-400',
}

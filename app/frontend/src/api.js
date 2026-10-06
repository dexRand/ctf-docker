const BASE = '/api/v1'

function apiKey() {
  try { return localStorage.getItem('stegsuite_api_key') || '' } catch { return '' }
}

export async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) }
  const key = apiKey()
  if (key) headers['x-api-key'] = key
  const r = await fetch(BASE + path, { ...opts, headers })
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`)
  const ct = r.headers.get('content-type') || ''
  return ct.includes('application/json') ? r.json() : r.text()
}

export function wsUrl(path) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const key = apiKey()
  const q = key ? (path.includes('?') ? '&' : '?') + 'key=' + encodeURIComponent(key) : ''
  return `${proto}://${location.host}${path}${q}`
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
  created: 'text-dim', queued: 'text-warn', running: 'text-warn',
  paused: 'text-info', done: 'text-acc', error: 'text-danger', cancelled: 'text-dim',
}

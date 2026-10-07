<script setup>
import { ref, computed, onMounted, onBeforeUnmount, watch, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { api, wsUrl, fmtSize, fmtDate, fmtTime, STATUS_COLOR } from '../api'
import { toolLabel } from '../labels'
import { t, tt, lang } from '../i18n'
import { mdToHtml } from '../md'
import { notify } from '../toast'
import Terminal from '../components/Terminal.vue'
import GraphView from '../components/GraphView.vue'
import Icon from '../components/Icon.vue'

const props = defineProps({ id: { type: String, required: true } })
const router = useRouter()

const project = ref(null)
const runs = ref([])
const findings = ref([])
const locked = ref([])
const wordlists = ref([])
const log = ref([])
const selected = ref(null)
const tab = ref('overview')
const rightTab = ref('findings')
const outputs = ref({})
const expanded = ref({})
const lightbox = ref(null)
const previewErr = ref(false)
const report = ref({ open: false, text: '', busy: false })
const reportLang = ref('en')
const err = ref('')
const progress = ref({ processed: 0, total: 0 })
const currentFile = ref('')
const progressPct = computed(() => {
  const total = progress.value.total || tree.value.length
  return total ? Math.min(100, Math.round((progress.value.processed / total) * 100)) : 0
})
// responsive: below 900px we show one pane at a time (files/detail/panel)
const narrow = ref(false)
const mobilePane = ref('detail')
const MOBILE_PANES = ['files', 'detail', 'panel']
let mq = null
function onMq() { if (mq) narrow.value = mq.matches }
function mobileTabBtn(p) {
  return mobilePane.value === p ? 'bg-acc text-[#06120b] font-bold' : 'text-dim hover:text-fglite'
}
function loadW(key, def) {
  try { const v = parseInt(localStorage.getItem('steg.pane.' + key) || '', 10); return isNaN(v) ? def : v } catch { return def }
}
const leftW = ref(loadW('left', 250))
const rightW = ref(loadW('right', 380))
const gridRef = ref(null)
const logsRef = ref(null)
const graphRef = ref(null)
const logSplit = ref(loadW('logsplit', 300))
function clamp(v, mn, mx) { return Math.min(mx, Math.max(mn, v)) }
// Delta-based drag: we capture the sizes at pointerdown and apply the pointer
// offset. No rect math during the move, so the panes never jump or fight.
let drag = null
function startDrag(kind, e) {
  e.preventDefault()
  e.stopPropagation()
  const grid = gridRef.value?.getBoundingClientRect()
  const logsBox = logsRef.value?.parentElement?.getBoundingClientRect()
  drag = {
    kind, x: e.clientX, y: e.clientY,
    left: leftW.value, right: rightW.value, split: logSplit.value,
    gw: grid ? grid.width : 1400, lh: logsBox ? logsBox.height : 800,
  }
  window.addEventListener('pointermove', onDrag)
  window.addEventListener('pointerup', endDrag)
  document.body.style.cursor = kind === 'logsplit' ? 'row-resize' : 'col-resize'
  document.body.style.userSelect = 'none'
}
function onDrag(e) {
  if (!drag) return
  const dx = e.clientX - drag.x, dy = e.clientY - drag.y
  if (drag.kind === 'left') {
    leftW.value = clamp(drag.left + dx, 180, Math.max(220, Math.min(560, drag.gw - drag.right - 380)))
  } else if (drag.kind === 'right') {
    rightW.value = clamp(drag.right - dx, 300, Math.max(340, Math.min(820, drag.gw - drag.left - 380)))
  } else if (drag.kind === 'logsplit') {
    logSplit.value = clamp(drag.split + dy, 80, Math.max(120, drag.lh - 150))
  }
}
function endDrag() {
  if (!drag) return
  drag = null
  window.removeEventListener('pointermove', onDrag)
  window.removeEventListener('pointerup', endDrag)
  document.body.style.cursor = ''
  document.body.style.userSelect = ''
  savePanes()
  window.dispatchEvent(new Event('resize'))
}
function savePanes() {
  try {
    localStorage.setItem('steg.pane.left', String(leftW.value))
    localStorage.setItem('steg.pane.right', String(rightW.value))
    localStorage.setItem('steg.pane.logsplit', String(logSplit.value))
  } catch { /* private mode */ }
}
// Keyboard support for the separators (role=separator): arrow keys resize.
function nudge(kind, delta) {
  if (kind === 'left') leftW.value = clamp(leftW.value + delta, 180, 560)
  else if (kind === 'right') rightW.value = clamp(rightW.value - delta, 300, 820)
  else if (kind === 'logsplit') logSplit.value = clamp(logSplit.value + delta, 80, 640)
  savePanes()
  window.dispatchEvent(new Event('resize'))
}
let ws = null
let refreshTimer = null
let logSeeded = false

const IMG = /\.(png|jpe?g|gif|bmp|webp|tiff?)$/i
const AUD = /\.(wav|mp3|flac|ogg|m4a|aac|au)$/i
const VID = /\.(mp4|mkv|webm|avi|mov)$/i
const TXT = /\.(txt|md|json|xml|csv|log|strings|out|py)$/i

const tree = computed(() => (project.value?.tree || []).slice().sort((a, b) => a.order_index - b.order_index))
const treeById = computed(() => Object.fromEntries(tree.value.map((n) => [n.id, n])))
const childrenByParent = computed(() => {
  const m = {}
  for (const n of tree.value) { (m[n.parent_id ?? 0] ||= []).push(n) }
  for (const k in m) m[k].sort((a, b) => a.order_index - b.order_index)
  return m
})
const collapsed = ref(new Set())
function originTool(n) {
  const o = String(n?.origin || '')
  if (!o || o === 'upload') return 'upload'
  const m = o.match(/^extracted:([^:]+):\d+$/)
  return m ? m[1] : 'extracted'
}
function toggleKey(key) {
  const s = new Set(collapsed.value)
  s.has(key) ? s.delete(key) : s.add(key)
  collapsed.value = s
}
function toggleNode(n) { toggleKey(n._gid || n.id) }
const search = ref('')
const visibleTree = computed(() => {
  const q = search.value.trim().toLowerCase()
  const m = childrenByParent.value
  const out = []
  // while searching, keep matches and their ancestors and expand everything
  let keep = null
  if (q) {
    keep = new Set()
    for (const n of tree.value) {
      if (!String(n.name).toLowerCase().includes(q)) continue
      let cur = n
      while (cur) { keep.add(cur.id); cur = treeById.value[cur.parent_id] }
    }
  }
  const walk = (pid, depth) => {
    const groups = new Map()
    for (const n of (m[pid] || [])) {
      if (keep && !keep.has(n.id)) continue
      const t = originTool(n)
      if (!groups.has(t)) groups.set(t, [])
      groups.get(t).push(n)
    }
    const multi = groups.size > 1
    for (const [tool, list] of groups) {
      if (multi) {
        const gid = `g:${pid}:${tool}`
        out.push({ _group: true, _gid: gid, _pid: pid, _tool: tool, _depth: depth, _kids: list.length, name: tool, label: toolLabel(tool) })
        if (!q && collapsed.value.has(gid)) continue
        for (const n of list) {
          out.push({ ...n, _depth: depth + 1, _kids: (m[n.id] || []).length })
          if (q || !collapsed.value.has(n.id)) walk(n.id, depth + 1)
        }
      } else {
        for (const n of list) {
          out.push({ ...n, _depth: depth, _kids: (m[n.id] || []).length })
          if (q || !collapsed.value.has(n.id)) walk(n.id, depth)
        }
      }
    }
  }
  walk(0, 0)
  return out
})
const runsByFile = computed(() => {
  const m = {}
  for (const r of runs.value) (m[r.file_id] ||= []).push(r)
  return m
})
const logRuns = computed(() => runs.value.slice().sort((a, b) => b.id - a.id))
const lockedIds = computed(() => new Set(locked.value.map((l) => l.file_id)))
const selectedNode = computed(() => tree.value.find((n) => n.id === selected.value) || null)
const childrenOf = (id) => tree.value.filter((n) => n.parent_id === id)
const selectedRuns = computed(() => runsByFile.value[selected.value] || [])
const flags = computed(() => findings.value.filter((f) => f.kind === 'flag'))
const passwords = computed(() => findings.value.filter((f) => f.kind === 'password'))
const passwordFileIds = computed(() => new Set(passwords.value.map((p) => p.file_id)))
function pwdOf(fileId) { return passwords.value.find((p) => p.file_id === fileId) || null }

// --- graph tab: force-directed tool graph + flag timeline -----------------
const graphFlagIds = computed(() => new Set(flags.value.map((f) => f.file_id)))
const graphNodes = computed(() => tree.value.map((n) => ({
  id: n.id,
  name: shortName(n.name),
  tool: toolLabel(originTool(n)),
  route: routeIdSet.value.has(n.id),
  flag: graphFlagIds.value.has(n.id),
  cracked: !!pwdOf(n.id),
  locked: lockedIds.value.has(n.id),
})))
const graphLinks = computed(() => tree.value.filter((n) => n.parent_id != null)
  .map((n) => ({
    source: n.parent_id,
    target: n.id,
    route: routeIdSet.value.has(n.id) && routeIdSet.value.has(n.parent_id),
  })))
// ordered route from the upload down to each flag (deduped), for the timeline
const routeSteps = computed(() => {
  const seen = new Set()
  const steps = []
  for (const f of flags.value) {
    for (const n of chainOf(f.file_id)) {
      if (seen.has(n.id)) continue
      seen.add(n.id)
      const isUpload = n.parent_id == null
      steps.push({
        id: n.id, name: n.name, tool: isUpload ? 'upload' : originTool(n),
        flag: f.file_id === n.id, pwd: isUpload ? null : pwdOf(n.id),
      })
    }
  }
  return steps
})
// clicking a graph node (or a timeline step) selects that file on the left,
// so the details stay in one place (tree + overview/extracted)
function selectFile(id) { selected.value = id }
function shortName(s) { s = String(s); return s.length > 18 ? s.slice(0, 17) + '…' : s }
const notes = computed(() => findings.value.filter((f) => f.kind === 'note'))
const routeTreeText = computed(() => (routeNodes().length ? asciiRouteTree() : ''))
const routeIdSet = computed(() => new Set(routeNodes().map((n) => n.id)))
// only the runs that actually took part: the finder tool + the tools that
// produced each file on the path to the flag (not every tool that ran)
const relevantRuns = computed(() => {
  const wanted = new Set()
  const found = new Set()
  for (const f of flags.value) {
    wanted.add(`${f.file_id}:${sourceTool(f.source)}`)
    // the source can be a pseudo-tool ("raw scan") matching no run; the run that
    // really showed the flag is found from its output
    const ev = evidenceFor(f)
    if (ev && ev.run) found.add(ev.run)
    let cur = f.file_id
    while (cur && treeById.value[cur]) {
      const n = treeById.value[cur]
      if (n.parent_id != null) {
        const t = originTool(n)
        if (t && t !== 'upload' && t !== 'extracted') wanted.add(`${n.parent_id}:${t}`)
      }
      cur = n.parent_id
    }
  }
  return runs.value.filter((r) => found.has(r.id) || wanted.has(`${r.file_id}:${r.tool}`))
})
// run ids that actually produced a flag. The finding source names a tool, but
// it can be a pseudo-source ("raw scan") that matches no run at all: the flag
// may have surfaced in some other tool's output (exiftool Artist, png-chunks
// tEXt, ...). So prefer the run whose output really contains the flag value,
// and fall back to the tool named in the source.
const solverRuns = computed(() => {
  const s = new Set()
  for (const f of flags.value) {
    const ev = evidenceFor(f)
    if (ev && ev.run) { s.add(ev.run); continue }
    const src = sourceTool(f.source)
    for (const r of runsByFile.value[f.file_id] || []) if (r.tool === src) s.add(r.id)
  }
  return s
})
// tools that solved a flag, for the "tool usati per la flag" chip row
const solverTools = computed(() => {
  const s = new Set()
  for (const f of flags.value) {
    const ev = evidenceFor(f)
    if (ev && ev.run) s.add(ev.tool)
    else s.add(sourceTool(f.source))
  }
  return s
})
// each flag paired with the real tool output that shows it
const flagCards = computed(() => flags.value.map((f) => ({ f, ev: evidenceFor(f) })))
// files "near" the flag path: siblings and children of route nodes
const nearIdSet = computed(() => {
  const s = new Set()
  if (!flags.value.length) return s
  for (const r of routeNodes()) {
    const pid = r.parent_id ?? 0
    for (const n of tree.value) if ((n.parent_id ?? 0) === pid) s.add(n.id)
    for (const n of tree.value) if ((n.parent_id ?? 0) === r.id) s.add(n.id)
  }
  for (const id of routeIdSet.value) s.delete(id)
  return s
})
function nodeColor(n) {
  if (!flags.value.length) return ''
  if (routeIdSet.value.has(n.id)) return 'text-acc'
  if (nearIdSet.value.has(n.id)) return 'text-fglite'
  return 'text-dim'
}
function groupColor(n) {
  if (!flags.value.length) return 'text-dim'
  const kids = childrenByParent.value[n._pid] || []
  const mine = kids.filter((c) => originTool(c) === n._tool)
  if (mine.some((c) => routeIdSet.value.has(c.id))) return 'text-acc'
  if (mine.some((c) => nearIdSet.value.has(c.id))) return 'text-fglite'
  return 'text-dim'
}

function statusChip(status) {
  const map = {
    done: 'border-acc/50 bg-acc/5 text-acc',
    running: 'border-warn/50 bg-warn/5 text-warn',
    queued: 'border-warn/50 bg-warn/5 text-warn',
    paused: 'border-info/50 bg-info/5 text-info',
    error: 'border-danger/50 bg-danger/5 text-danger',
  }
  return map[status] || 'border-edge text-dim'
}
function runStatusChip(status) {
  const map = {
    done: 'border-acc/40 bg-acc/5 text-acc',
    needs_password: 'border-warn/40 bg-warn/5 text-warn',
    cracked: 'border-acc/50 bg-acc/10 text-acc',
    skipped: 'border-edge text-dim',
  }
  return map[status] || 'border-danger/40 bg-danger/5 text-danger'
}
// a run that asked for a password but whose file was later cracked is shown as
// "cracked" (with the recovered password), not as still "needs_password"
function effStatus(r) {
  return (r && r.needs_password && pwdOf(r.file_id)) ? 'cracked' : (r ? r.status : '')
}
function tabBtn(tb) {
  return tab.value === tb ? 'bg-acc text-[#06120b] font-bold' : 'text-dim hover:text-fglite'
}
function rightTabBtn(t) {
  return rightTab.value === t ? 'bg-acc text-[#06120b] font-bold' : 'text-dim hover:text-fglite'
}

async function load() {
  try {
    project.value = await api(`/projects/${props.id}`)
    ;[findings.value, locked.value, wordlists.value] = await Promise.all([
      api(`/projects/${props.id}/findings`),
      api(`/projects/${props.id}/locked`),
      api('/wordlists'),
    ])
    for (const l of locked.value) {
      try { l._wl = localStorage.getItem(`steg.wl.${props.id}.${l.file_id}`) || '' } catch { l._wl = '' }
    }
    runs.value = await api(`/projects/${props.id}/runs`)
    // seed the live log from persisted events so the Logs tab is not empty on
    // projects that were analysed in a previous session (only once, and only if
    // no live event has arrived yet)
    if (!logSeeded) {
      logSeeded = true
      try {
        const evs = await api(`/projects/${props.id}/events`)
        if (!log.value.length) {
          log.value = (evs || []).map((e) => ({ type: 'event', level: e.level, message: e.message, ts: e.ts }))
        }
      } catch { /* no history */ }
    }
    // preload outputs of tools that ran on files containing a flag, so the
    // evidence excerpt (tool output with the flag) is available immediately
    for (const f of findings.value.filter((x) => x.kind === 'flag')) {
      for (const r of runs.value.filter((x) => x.file_id === f.file_id)) out(r.id)
    }
    if (selected.value == null && tree.value.length) selected.value = tree.value[0].id
    // refresh the full-logs view if the user is looking at it
    fullLogs.value = ''
    if (logView.value === 'full') showFullLogs()
  } catch (e) { err.value = String(e) }
}

function connect() {
  ws = new WebSocket(wsUrl(`/ws/projects/${props.id}`))
  ws.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data) } catch { return }
    if (m.type === 'ping') return
    log.value.push(m)
    if (log.value.length > 800) log.value.splice(0, 400)
    if (m.total != null) progress.value.total = m.total
    if (m.type === 'file') currentFile.value = m.name
    if (m.type === 'progress') progress.value.processed = m.processed
    if (m.type === 'crack' && m.status === 'found') {
      notify(`🔑 ${m.password}${m.wordlist ? ` (via ${m.wordlist})` : ''}`, 'ok')
    }
    if (['status', 'file', 'tool', 'crack'].includes(m.type)) scheduleRefresh()
  }
}
function scheduleRefresh() {
  if (refreshTimer) return
  refreshTimer = setTimeout(() => { refreshTimer = null; load() }, 600)
}
async function action(kind) {
  try { await api(`/projects/${props.id}/${kind}`, { method: 'POST' }) }
  catch (e) { err.value = String(e); notify(String(e), 'error') }
}
async function del() {
  if (!confirm(t('proj.del_confirm'))) return
  try {
    await api(`/projects/${props.id}`, { method: 'DELETE' })
    notify(t('toast.deleted'), 'ok')
    router.push('/')
  } catch (e) { notify(String(e), 'error') }
}
async function crack(item, wl) {
  try {
    await api(`/projects/${props.id}/crack`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ file_id: item.file_id, wordlists: wl ? [wl] : null }),
    })
  } catch (e) { notify(String(e), 'error') }
}
// remember the wordlist chosen for a locked file (per project + file)
function persistWl(l) {
  try { l._wl ? localStorage.setItem(`steg.wl.${props.id}.${l.file_id}`, l._wl) : localStorage.removeItem(`steg.wl.${props.id}.${l.file_id}`) } catch { /* private mode */ }
}
const wlUploading = ref(false)
async function uploadWordlist(e) {
  const file = e.target.files?.[0]
  if (!file) return
  wlUploading.value = true
  try {
    const fd = new FormData()
    fd.append('file', file)
    const info = await api('/wordlists', { method: 'POST', body: fd })
    wordlists.value = await api('/wordlists')
    notify(t('toast.wordlist_added', { name: info.name }), 'ok')
  } catch (err2) { notify(String(err2), 'error') } finally {
    wlUploading.value = false
    e.target.value = ''
  }
}
async function out(rid) {
  if (outputs.value[rid] != null) return outputs.value[rid]
  const fid = (runs.value.find((r) => r.id === rid) || {}).file_id
  try { outputs.value[rid] = await api(`/projects/${props.id}/files/${fid}/runs/${rid}`) }
  catch (e) { outputs.value[rid] = String(e) }
}
async function toggle(rid) {
  if (expanded.value[rid]) { delete expanded.value[rid]; return }
  expanded.value[rid] = true
  await out(rid)
}
async function toggleRun(rid) {
  const k = 'run:' + rid
  if (expanded.value[k]) { delete expanded.value[k]; return }
  expanded.value[k] = true
  await out(rid)
}
function artUrl(a) { return `/api/v1/projects/${props.id}/artifacts/${a.id}/content` }
function fileUrl(n) { return `/api/v1/projects/${props.id}/files/${n.id}/content` }

async function loadPreview(id) {
  const n = tree.value.find((x) => x.id === id)
  if (!n || !TXT.test(n.name)) return
  const key = 'file' + id
  if (outputs.value[key] != null) return
  try { outputs.value[key] = await api(`/projects/${props.id}/files/${id}/content`) }
  catch (e) { outputs.value[key] = String(e) }
}

function commandsOf(text) {
  return String(text || '').split('\n').filter((l) => l.startsWith('# '))
    .map((l) => l.slice(2)).filter((c) => c && c !== 'commands:')
}
// excerpt of a tool output around the flag (the evidence of where it was)
function evidenceLines(text, flag, width = 3) {
  const lines = String(text).split('\n')
  const idx = lines.findIndex((l) => l.includes(flag))
  if (idx < 0) return ''
  const from = Math.max(0, idx - width)
  const to = Math.min(lines.length, idx + width + 1)
  return lines.slice(from, to).join('\n').slice(0, 900)
}
function evidenceFor(f) {
  const src = sourceTool(f.source)
  const cands = (runsByFile.value[f.file_id] || []).slice()
    .sort((a, b) => ((a.tool === src) ? -1 : 0) - ((b.tool === src) ? -1 : 0))
  for (const r of cands) {
    const o = outputs.value[r.id]
    if (o && String(o).includes(f.value)) {
      return { run: r.id, tool: r.tool, command: commandsOf(o)[0] || '', lines: evidenceLines(String(o), f.value) }
    }
  }
  return null
}

// --- ASCII tree (box drawing) ---
function childrenMap(nodes) {
  const m = {}
  for (const n of nodes) { (m[n.parent_id ?? 0] ||= []).push(n) }
  for (const k in m) m[k].sort((a, b) => a.order_index - b.order_index)
  return m
}
const SRC_PREFIX = ['b64', 'hex', 'fuzzy']
const SRC_DECODER = { b64: 'base64', hex: 'hex', fuzzy: 'fuzzy/OCR' }
function sourceParts(src) {
  const parts = String(src || '').split(':').filter(Boolean)
  const dec = []
  while (parts.length > 1 && SRC_PREFIX.includes(parts[0])) dec.push(parts.shift())
  const tool = parts[0] === 'raw' ? 'raw scan' : (parts[0] || '?')
  return { tool, dec }
}
function sourceTool(src) { return sourceParts(src).tool }
function sourceHow(src, lng) {
  const { tool, dec } = sourceParts(src)
  const name = toolLabel(tool, lng)
  return dec.length ? name + ' + ' + dec.map((d) => SRC_DECODER[d] || d).join(' + ') : name
}
function chainOf(fileId) {
  const chain = []
  let cur = fileId
  while (cur && treeById.value[cur]) { chain.unshift(treeById.value[cur]); cur = treeById.value[cur].parent_id }
  return chain
}
function pwdVia(p) { return p && p.context ? ` (via ${p.context})` : '' }
function chainText(f, lng) {
  const parts = []
  const ev = evidenceFor(f)
  const via = lng ? tt(lng, 'proj.via') : t('proj.via')
  chainOf(f.file_id).forEach((n, i) => {
    const ot = originTool(n)
    if (i === 0) parts.push(n.name)
    else {
      const pw = passwords.value.find((p) => p.file_id === n.id)
      parts.push(`${n.name} (${via} ${toolLabel(ot, lng)}${pw ? ', pwd ' + pw.value + pwdVia(pw) : ''})`)
    }
  })
  parts.push(`[${ev && ev.run ? toolLabel(ev.tool, lng) : sourceHow(f.source, lng)}]`)
  return parts.join('  ->  ')
}
function flagTools() {
  const s = new Set()
  for (const f of flags.value) {
    const ev = evidenceFor(f)
    s.add(ev && ev.run ? ev.tool : sourceTool(f.source))
    for (const n of chainOf(f.file_id)) {
      const t = originTool(n)
      if (t && t !== 'upload' && t !== 'extracted') s.add(t)
    }
  }
  for (const r of relevantRuns.value) s.add(r.tool)
  return [...s].sort()
}
function routeLabel(n) {
  const fl = flags.value.filter((f) => f.file_id === n.id).map((f) => f.value)
  const pw = passwords.value.filter((p) => p.file_id === n.id).map((p) => p.value)
  const ot = originTool(n)
  let s = n.name
  if (ot && ot !== 'upload' && ot !== 'extracted') s += `   (${ot})`
  if (fl.length) s += `   <-- FLAG: ${fl.join(', ')}`
  else if (pw.length) s += `   <-- password: ${pw.join(', ')}`
  return s
}
function asciiRouteTree() {
  const m = childrenMap(routeNodes())
  const lines = []
  const walk = (pid, prefix) => {
    const kids = m[pid] || []
    kids.forEach((k, i) => {
      const last = i === kids.length - 1
      lines.push(prefix + (last ? '└── ' : '├── ') + routeLabel(k))
      walk(k.id, prefix + (last ? '    ' : '│   '))
    })
  }
  walk(0, '')
  return lines.join('\n')
}
function routeNodes() {
  const ids = new Set()
  for (const f of flags.value) {
    let cur = f.file_id
    while (cur && treeById.value[cur]) { ids.add(cur); cur = treeById.value[cur].parent_id }
  }
  // keep the ancestry order (tree is already sorted by discovery)
  return tree.value.filter((n) => ids.has(n.id))
}

async function openReport() {
  reportLang.value = lang.value
  report.value = { open: true, text: '…', busy: true }
  try {
    await buildReport(reportLang.value)
  } catch (e) {
    report.value = { open: true, text: '⚠️ ' + String(e), busy: false }
  }
}
async function buildReport(lng) {
  const g = (k, p) => tt(lng, k, p)
  const P = project.value
  const L = []
  L.push(`# ${g('report.title_line', { name: P.name })}`)
  L.push('')
  L.push(g('report.status_line', { status: P.status, mode: P.mode, files: P.files, date: fmtDate(P.created_at) }))
  L.push('')
  if (passwords.value.length) {
    L.push('## ' + g('report.passwords'))
    L.push(g('report.passwords_head'))
    L.push('|---|---|---|')
    for (const p of passwords.value) L.push(`| \`${p.value}\` | ${p.source} | ${p.context ? `\`${p.context}\`` : '—'} |`)
  }
  if (notes.value.length) {
    L.push(''); L.push('## ' + g('report.notes')); L.push(g('report.notes_head')); L.push('|---|---|')
    for (const n of notes.value) L.push(`| ${n.value} | ${n.source} |`)
  }
  L.push(''); L.push('## ' + g('report.how_header'))
  if (flagCards.value.length) {
    for (const { f, ev } of flagCards.value) {
      const fn = treeById.value[f.file_id]
      L.push(`### \`${f.value}\``)
      L.push(`- ${g('report.where')} ${fn ? fn.name : '?'}${fn ? `  ·  [${g('report.open_link')}](${fileUrl(fn)})` : ''}`)
      L.push(`- ${g('report.how')} ${ev && ev.run ? toolLabel(ev.tool, lng) : sourceHow(f.source, lng)}`)
      L.push(`- ${g('report.chain')} \`${chainText(f, lng)}\``)
      if (ev && ev.lines) {
        L.push('```')
        L.push(`# ${ev.tool}${ev.command ? '  —  ' + ev.command : ''}`)
        L.push(ev.lines.replace(/```/g, "'''"))
        L.push('```')
      } else if (f.context) {
        L.push('```')
        L.push(String(f.context).replace(/```/g, "'''"))
        L.push('```')
      }
      L.push('')
    }
  } else L.push(g('report.no_flag_how'))
  L.push(`## ${g('report.tools_header_prefix')} (${flagTools().length})`)
  L.push(flagTools().map((t) => `\`${t}\`${solverTools.value.has(t) ? ' ' + g('report.solved_tag') : ''}`).join(', ') || '_—_')
  L.push(''); L.push('## ' + g('report.path_header'))
  L.push('```')
  L.push(routeNodes().length ? asciiRouteTree() : g('report.no_path'))
  L.push('```')
  const rel = relevantRuns.value
  if (rel.length) {
    L.push(''); L.push(`## ${g('report.route_runs', { n: rel.length })}`)
    L.push(g('report.run_head'))
    L.push('|---|---|---|---|')
    for (const r of rel) {
      const f = treeById.value[r.file_id]
      L.push(`| ${f ? f.name : '?'} | ${r.tool} | ${r.status} | ${(r.summary || '').replace(/\|/g, '\\|')} |`)
    }
    const blocks = []
    for (const r of rel) {
      const o = outputs.value[r.id] != null ? outputs.value[r.id] : await out(r.id)
      const cmds = commandsOf(o)
      if (cmds.length) {
        blocks.push('```\n# ' + (treeById.value[r.file_id] || {}).name + ' — ' + r.tool + '\n' + cmds.join('\n') + '\n```')
      }
    }
    if (blocks.length) { L.push(''); L.push('## ' + g('report.commands')); L.push(...blocks) }
  }
  const routeFiles = routeNodes().filter((n) => n.parent_id != null)
  if (routeFiles.length) {
    L.push(''); L.push(`## ${g('report.route_files', { n: routeFiles.length })}`)
    L.push(g('report.route_files_head'))
    L.push('|---|---|---|---|')
    for (const n of routeFiles) L.push(`| ${n.name} | ${fmtSize(n.size)} | ${originTool(n)} | [${g('report.open_link')}](${fileUrl(n)}) |`)
  }
  const noise = tree.value.length - routeNodes().length
  L.push('')
  L.push(g('report.footer', { files: tree.value.length, runs: runs.value.length, noise }))
  report.value = { open: true, text: L.join('\n'), busy: false }
}
function copyReport() { navigator.clipboard?.writeText(report.value.text) }
const copied = ref('')
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
    copied.value = text
    setTimeout(() => { if (copied.value === text) copied.value = '' }, 1500)
  } catch { /* clipboard unavailable */ }
}
async function copyAllFlags() {
  if (!flags.value.length) return
  await copyText(flags.value.map((f) => f.value).join('\n'))
  notify(t('toast.copied_flags', { n: flags.value.length }), 'ok')
}
function downloadReport() {
  const blob = new Blob([report.value.text], { type: 'text/markdown' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `stegsuite-report-${props.id}.md`
  a.click()
}

// --- transcript (for an AI agent: what the tool did, commands + outputs) ---
const transcript = ref({ open: false, text: '', busy: false })
function plainLog() {
  return log.value.map((m) => {
    const ts = m.ts ? fmtTime(m.ts) + '  ' : ''
    if (m.type === 'event') return `${ts}${m.level === 'warn' ? '!' : '·'} ${m.message}`
    let s = `${ts}${m.type}`
    if (m.message) s += ` ${m.message}`
    if (m.name) s += ` ${m.name}`
    if (m.tool) s += ` → ${m.tool}`
    if (m.status) s += ` (${m.status})`
    if (m.password) s += ` 🔑 ${m.password}` + (m.wordlist ? ` (via ${m.wordlist})` : '')
    return s
  }).join('\n')
}
function copyLogs() { navigator.clipboard?.writeText(plainLog() || '') }

// full logs = event log + every run with its full commands/output, copyable in one click
const logView = ref('runs')
const fullLogs = ref('')
const fullLogsBusy = ref(false)
async function buildFullLogs() {
  const P = project.value || {}
  const L = [`# StegSuite full logs — ${P.name} (${P.id})`, '', '## Event log', plainLog() || '(none)', '', '## Runs']
  const byFile = {}
  for (const r of runs.value) (byFile[r.file_id] ||= []).push(r)
  for (const n of tree.value) {
    for (const r of (byFile[n.id] || [])) {
      L.push('')
      L.push(`### ${n.name} — ${r.tool} — ${effStatus(r)} (exit ${r.exit_code ?? '-'}) — ${fmtDate(r.finished_at || r.started_at)}`)
      const raw = outputs.value[r.id] != null ? outputs.value[r.id] : await out(r.id)
      L.push(String(raw ?? '(no output)'))
    }
  }
  return L.join('\n')
}
async function showFullLogs() {
  logView.value = 'full'
  if (fullLogs.value) return
  fullLogsBusy.value = true
  try { fullLogs.value = await buildFullLogs() } finally { fullLogsBusy.value = false }
}
async function copyFullLogs() {
  if (!fullLogs.value) {
    fullLogsBusy.value = true
    try { fullLogs.value = await buildFullLogs() } finally { fullLogsBusy.value = false }
  }
  navigator.clipboard?.writeText(fullLogs.value)
}
function fileTreeText() {
  const lines = []
  const walk = (pid, depth) => {
    for (const n of (childrenByParent.value[pid] || [])) {
      const tool = n.parent_id == null ? 'upload' : originTool(n)
      lines.push('  '.repeat(depth) + `- ${n.name}  [${tool}]  ${fmtSize(n.size)}`
        + (n.sha256 ? `  sha256:${n.sha256.slice(0, 16)}…` : ''))
      walk(n.id, depth + 1)
    }
  }
  walk(0, 0)
  return lines.join('\n') || '(empty)'
}
function xmlAttr(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/\n/g, ' ')
}
function cdata(s) {
  return '<![CDATA[' + String(s ?? '').replace(/\]\]>/g, ']]]]><![CDATA[>') + ']]>'
}
function flagFormat() {
  const f = flags.value[0]
  if (!f) return ''
  const m = String(f.value).match(/^([A-Za-z0-9_]+)\{/)
  return m ? m[1] + '{...}' : ''
}
async function buildTranscript() {
  const P = project.value || {}
  const L = []
  // Long, high-signal context first; the actual task goes at the very end
  // (per Anthropic long-context guidance: data on top, query at the bottom).
  L.push('You are a CTF assistant. The transcript below is the machine log of an')
  L.push('automated steganography/forensics tool run on a challenge. If the flag is')
  L.push('not present or the tool stopped early, continue from this transcript.')
  L.push('')
  L.push('<transcript>')
  L.push(`<challenge name="${xmlAttr(P.name)}" id="${xmlAttr(P.id)}" status="${xmlAttr(P.status)}" mode="${xmlAttr(P.mode)}">`)
  L.push(`  <files_count>${P.files}</files_count>`)
  L.push(`  <created>${xmlAttr(fmtDate(P.created_at))}</created>`)
  const fmt = flagFormat()
  if (fmt) L.push(`  <flag_format>${xmlAttr(fmt)}</flag_format>`)
  L.push('</challenge>')
  L.push('')

  L.push('<findings>')
  L.push('  <flags>')
  for (const f of flags.value) {
    L.push(`    <flag value="${xmlAttr(f.value)}" file="${xmlAttr((treeById.value[f.file_id] || {}).name || '?')}" how="${xmlAttr(sourceHow(f.source))}"/>`)
  }
  L.push('  </flags>')
  L.push('  <passwords>')
  for (const p of passwords.value) {
    L.push(`    <password value="${xmlAttr(p.value)}" source="${xmlAttr(p.source)}"`
      + `${p.context ? ` wordlist="${xmlAttr(p.context)}"` : ''} file="${xmlAttr((treeById.value[p.file_id] || {}).name || '?')}"/>`)
  }
  L.push('  </passwords>')
  L.push('  <notes>')
  for (const n of notes.value) L.push(`    <note>${xmlAttr(n.value)} (${xmlAttr(n.source)})</note>`)
  L.push('  </notes>')
  if (locked.value.length) {
    L.push('  <still_locked>')
    for (const l of locked.value) L.push(`    <locked file="${xmlAttr(l.name)}" tool="${xmlAttr(l.kind)}"/>`)
    L.push('  </still_locked>')
  }
  L.push('</findings>')
  L.push('')

  L.push('<flag_path>')
  L.push(routeNodes().length ? asciiRouteTree() : '(no path to a flag yet)')
  L.push('</flag_path>')
  if (routeSteps.value.length) {
    L.push('')
    L.push('<timeline>')
    routeSteps.value.forEach((s, i) => L.push(
      `${i + 1}. ${s.name} [${s.tool}]${s.pwd ? ' pwd=' + s.pwd.value : ''}${s.flag ? ' <-- FLAG' : ''}`))
    L.push('</timeline>')
  }
  L.push('')

  L.push('<files>')
  const walk = (pid, depth) => {
    for (const n of (childrenByParent.value[pid] || [])) {
      const tool = n.parent_id == null ? 'upload' : originTool(n)
      const mark = graphFlagIds.value.has(n.id) ? ' flag="true"'
        : pwdOf(n.id) ? ' cracked="true"' : lockedIds.value.has(n.id) ? ' locked="true"' : ''
      L.push(`${'  '.repeat(depth + 1)}<file name="${xmlAttr(n.name)}" tool="${xmlAttr(tool)}" size="${fmtSize(n.size)}"`
        + `${n.sha256 ? ` sha256="${n.sha256.slice(0, 16)}"` : ''}${mark}/>`)
      walk(n.id, depth + 1)
    }
  }
  walk(0, 0)
  L.push('</files>')
  L.push('')

  // commands for every run (cheap, high-signal); outputs truncated, with more
  // room for the runs that are on the flag path
  L.push('<runs>')
  const byFile = {}
  for (const r of runs.value) (byFile[r.file_id] ||= []).push(r)
  for (const n of tree.value) {
    for (const r of (byFile[n.id] || [])) {
      const raw = outputs.value[r.id] != null ? outputs.value[r.id] : await out(r.id)
      const text = String(raw ?? '')
      const cap = relevantRuns.value.some((x) => x.id === r.id) ? 3000 : 1200
      const cmds = commandsOf(text)
      L.push(`  <run file="${xmlAttr(n.name)}" tool="${xmlAttr(r.tool)}" status="${xmlAttr(effStatus(r))}" exit="${r.exit_code ?? '-'}" at="${xmlAttr(fmtDate(r.finished_at || r.started_at))}">`)
      if (r.summary) L.push(`    <summary>${xmlAttr(r.summary)}</summary>`)
      L.push('    <commands>')
      if (cmds.length) for (const c of cmds) L.push(`      <cmd>${xmlAttr(c)}</cmd>`)
      else L.push('      <cmd>(none recorded)</cmd>')
      L.push('    </commands>')
      if (text) {
        const body = text.replace(/^# commands:\n(?:# .*\n)*\n?/, '').slice(0, cap)
        L.push(`    <output>${cdata(body)}${text.length > cap ? `\n… [truncated ${text.length - cap} chars]` : ''}</output>`)
      }
      L.push('  </run>')
    }
  }
  L.push('</runs>')
  L.push('')
  L.push('<event_log>')
  L.push(cdata(plainLog() || '(none)'))
  L.push('</event_log>')
  L.push('</transcript>')
  L.push('')
  L.push('<task>')
  L.push('The automated tool may have stopped early or missed the flag. Using the transcript above:')
  L.push('1. Summarize what has already been done and what is still unsolved (see <still_locked>).')
  L.push('2. Give the exact next commands (tool + file paths) to finish the challenge and obtain the flag.')
  if (flags.value.length) L.push('A flag is already present in <findings><flags>: verify it and, if valid, confirm it.')
  else L.push('No flag has been found yet, so propose the next steps to find it.')
  L.push('Explain briefly why each command is the right next step.')
  L.push('</task>')
  return L.join('\n')
}
async function openTranscript() {
  transcript.value = { open: true, text: '', busy: true }
  try {
    transcript.value = { open: true, text: await buildTranscript(), busy: false }
  } catch (e) {
    transcript.value = { open: true, text: '⚠️ ' + String(e), busy: false }
  }
}
function copyTranscript() { navigator.clipboard?.writeText(transcript.value.text) }
function downloadTranscript() {
  const blob = new Blob([transcript.value.text], { type: 'text/markdown' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `stegsuite-transcript-${props.id}.md`
  a.click()
}

const X16 = ['#000000', '#cd3131', '#0dbc79', '#e5e510', '#2472c8', '#bc3fbc', '#11a8cd', '#e5e5e5',
  '#666666', '#f14c4c', '#23d18b', '#f5f543', '#3b8eea', '#d670d6', '#29b8db', '#ffffff']
function xterm(n) {
  n = Number(n)
  if (n < 16) return X16[n]
  if (n < 232) { const k = n - 16, r = Math.floor(k / 36), g = Math.floor((k % 36) / 6), b = k % 6; const v = (x) => (x ? x * 40 + 55 : 0); return `rgb(${v(r)},${v(g)},${v(b)})` }
  const v = 8 + (n - 232) * 10; return `rgb(${v},${v},${v})`
}
function ansiToHtml(s) {
  const esc = String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  let open = 0
  return esc.replace(/\x1b\[([0-9;]*)m/g, (_m, codes) => {
    const parts = codes.split(';').filter((x) => x !== '').map(Number)
    const css = []
    for (let i = 0; i < parts.length; i++) {
      const c = parts[i]
      if (c === 0) css.push('RESET')
      else if (c === 1) css.push('font-weight:600')
      else if (c >= 30 && c <= 37) css.push(`color:${X16[c - 30]}`)
      else if (c >= 90 && c <= 97) css.push(`color:${X16[c - 90 + 8]}`)
      else if (c >= 40 && c <= 47) css.push(`background:${X16[c - 40]}`)
      else if (c >= 100 && c <= 107) css.push(`background:${X16[c - 100 + 8]}`)
      else if (c === 38 && parts[i + 1] === 5) { css.push(`color:${xterm(parts[i + 2])}`); i += 2 }
      else if (c === 48 && parts[i + 1] === 5) { css.push(`background:${xterm(parts[i + 2])}`); i += 2 }
    }
    if (css.includes('RESET')) { const n = open; open = 0; return '</span>'.repeat(n) }
    open++
    return `<span style="${css.join(';')}">`
  }) + '</span>'.repeat(open)
}

watch(selected, (id) => { previewErr.value = false; if (id != null) loadPreview(id) })
watch(reportLang, (l) => {
  if (!report.value.open) return
  report.value.busy = true
  buildReport(l)
    .then(() => { report.value.busy = false })
    .catch((e) => { report.value = { open: true, text: '⚠️ ' + String(e), busy: false } })
})
watch(rightTab, async () => { await nextTick(); window.dispatchEvent(new Event('resize')) })
watch(() => props.id, () => {
  selected.value = null; outputs.value = {}; expanded.value = {}; log.value = []; logSeeded = false
  progress.value = { processed: 0, total: 0 }; currentFile.value = ''
  load()
})
onMounted(() => {
  mq = window.matchMedia('(max-width: 900px)')
  narrow.value = mq.matches
  mq.addEventListener('change', onMq)
  load(); connect()
})
onBeforeUnmount(() => {
  if (mq) mq.removeEventListener('change', onMq)
  endDrag()
  try { ws && ws.close() } catch {}
})
</script>

<template>
  <div class="flex h-full flex-col font-mono">
    <!-- action bar -->
    <div class="flex flex-wrap items-center gap-2 border-b border-edge bg-panel px-3 py-1.5 text-xs">
      <button @click="router.push('/')" class="kb px-2" :aria-label="t('proj.back_home')"><Icon name="chevronR" class="rotate-180" :size="12" /></button>
      <span class="font-bold text-fgx">{{ project?.name }}</span>
      <span class="rounded border px-2 py-0.5 text-[10px]" :class="statusChip(project?.status)">
        {{ project?.status }}
      </span>
      <span class="hidden text-[10px] text-dim lg:inline">
        --{{ project?.mode }} · {{ project?.files }} {{ t('proj.files') }} · {{ fmtDate(project?.created_at) }}
      </span>
      <div class="ml-auto flex flex-wrap items-center gap-1.5">
        <button @click="action('start')" class="kb kb-acc text-[10px]"><Icon name="play" :size="11" />start</button>
        <button @click="action('pause')" class="kb text-[10px]" :aria-label="t('proj.pause')"><Icon name="pause" :size="11" /></button>
        <button @click="action('resume')" class="kb text-[10px]" :aria-label="t('proj.resume')"><Icon name="play" :size="11" /></button>
        <button @click="action('cancel')" class="kb kb-danger text-[10px]" :aria-label="t('proj.cancel')"><Icon name="close" :size="11" /></button>
        <button @click="load" class="kb text-[10px]" :aria-label="t('proj.reload')"><Icon name="refresh" :size="11" /></button>
        <button @click="openReport" class="kb text-[10px]"><Icon name="report" :size="11" />{{ t('report.title') }}</button>
        <button @click="openTranscript" class="kb text-[10px]"><Icon name="copy" :size="11" />{{ t('proj.transcript') }}</button>
        <button @click="del" class="kb kb-danger text-[10px]" :aria-label="t('proj.delete')"><Icon name="trash" :size="11" /></button>
      </div>
    </div>

    <!-- per-file progress (live, from the WS progress events) -->
    <div v-if="project && ['running','queued'].includes(project.status)"
         class="flex items-center gap-2 border-b border-edge bg-panel2 px-3 py-1 text-[10px] text-dim">
      <Icon name="cpu" :size="11" class="shrink-0 text-warn" />
      <span class="shrink-0">{{ t('proj.progress', { done: progress.processed, total: progress.total || tree.length }) }}</span>
      <div class="h-1.5 min-w-0 flex-1 overflow-hidden rounded bg-ink"
           role="progressbar" :aria-valuenow="progressPct" aria-valuemin="0" aria-valuemax="100"
           :aria-label="t('proj.progress', { done: progress.processed, total: progress.total || tree.length })">
        <div class="h-1.5 rounded bg-warn transition-all" :style="{ width: Math.max(2, progressPct) + '%' }"></div>
      </div>
      <span class="shrink-0 text-warn">{{ progressPct }}%</span>
      <span class="hidden min-w-0 max-w-[28ch] truncate sm:inline" :title="currentFile">{{ currentFile }}</span>
    </div>

    <p v-if="err" class="border-b border-edge bg-danger/10 px-3 py-1 text-[11px] text-danger">[!] {{ err }}</p>

    <!-- mobile: one pane at a time -->
    <div v-if="narrow" class="flex items-center gap-1 border-b border-edge bg-panel px-2 py-1 text-[11px]">
      <button v-for="p in MOBILE_PANES" :key="p" type="button" @click="mobilePane = p"
              class="rounded px-2.5 py-0.5" :class="mobileTabBtn(p)" :aria-pressed="mobilePane === p">{{ t('proj.view_' + p) }}</button>
    </div>

    <div ref="gridRef" class="flex min-h-0 flex-1 overflow-hidden">
      <!-- files (left) -->
      <aside class="flex min-h-0 flex-col bg-panel"
             :class="narrow ? (mobilePane === 'files' ? 'flex-1' : 'hidden') : 'shrink-0'"
             :style="narrow ? {} : { width: leftW + 'px' }">
        <div class="flex items-center gap-2 border-b border-edge bg-panel2 px-2 py-1.5 text-[10px] uppercase tracking-widest text-dim">
          <Icon name="folder" :size="12" /> files <span class="normal-case text-acc">({{ tree.length }})</span>
          <input v-model="search" type="search" :placeholder="t('proj.filter_placeholder')" :aria-label="t('proj.filter_placeholder')"
                 class="ml-auto w-24 rounded border border-edge bg-ink px-1.5 py-0.5 text-[10px] placeholder:text-dim focus:border-acc" />
        </div>
        <div v-if="flags.length" class="flex flex-wrap items-center gap-x-3 gap-y-0.5 border-b border-edge px-2 py-1 text-[10px]">
          <span class="text-acc">● {{ t('proj.legend_route') }}</span>
          <span class="text-fglite">● {{ t('proj.legend_adjacent') }}</span>
          <span class="text-dim">● {{ t('proj.legend_dead') }}</span>
        </div>
        <div class="min-h-0 flex-1 overflow-auto p-1.5">
          <div v-for="n in visibleTree" :key="n._gid || n.id"
               @click="n._group ? toggleNode(n) : (selected = n.id)"
               class="row flex cursor-pointer items-center gap-1 rounded"
               :class="!n._group && selected === n.id ? 'bg-acc/15 text-fgx' : ''">
            <span :style="{ paddingLeft: (n._depth * 12) + 'px' }" class="flex min-w-0 items-center gap-1">
              <button v-if="n._kids" class="shrink-0 text-dim hover:text-acc" @click.stop="toggleNode(n)">
                <Icon :name="collapsed.has(n._gid || n.id) ? 'chevronR' : 'chevronD'" :size="12" />
              </button>
              <span v-else class="w-3 shrink-0"></span>
              <Icon :name="n._group ? 'folder' : (lockedIds.has(n.id) ? 'lock' : 'file')" :size="12" class="shrink-0 text-dim" />
              <span class="truncate" :class="n._group ? groupColor(n) : nodeColor(n)" :title="n._group ? n.name : n.origin">
                {{ n._group ? n.label + ' (' + n._kids + ')' : n.name }}
              </span>
              <span v-if="!n._group" class="shrink-0 text-[10px] text-dim">{{ fmtSize(n.size) }}</span>
              <span v-if="!n._group && flags.some((f) => f.file_id === n.id)" class="shrink-0 text-acc" :title="t('proj.flag_here')">●</span>
              <span v-else-if="!n._group && pwdOf(n.id)" class="shrink-0 text-warn" :title="t('proj.cracked')">🔑</span>
              <span v-else-if="!n._group && lockedIds.has(n.id)" class="shrink-0 text-warn" :title="t('proj.pw_needed')">[pw]</span>
            </span>
          </div>
        </div>
      </aside>
      <div v-if="!narrow" class="sep sep-v" role="separator" aria-orientation="vertical" tabindex="0" :aria-label="t('proj.resize_files')"
           @pointerdown="startDrag('left', $event)"
           @keydown.left.prevent="nudge('left', -16)" @keydown.right.prevent="nudge('left', 16)"></div>

      <!-- detail (center) -->
      <main class="flex min-h-0 min-w-0 flex-1 flex-col" :class="narrow && mobilePane !== 'detail' ? 'hidden' : ''">
        <div class="flex items-center gap-1 border-b border-edge bg-panel2 px-2 py-1.5 text-[11px]">
          <button v-for="tb in ['overview','extracted','preview']" :key="tb" @click="tab = tb"
                  class="rounded px-2.5 py-0.5" :class="tabBtn(tb)">
            {{ t('proj.tab_' + tb) }}
          </button>
          <span class="ml-2 min-w-0 truncate text-[11px] text-dim">{{ selectedNode?.name }}</span>
        </div>
        <div class="min-h-0 flex-1 overflow-auto p-2.5">
          <template v-if="tab === 'overview'">
            <div v-if="!selectedRuns.length" class="text-xs text-dim">
              <span class="text-acc">$</span> {{ t('proj.no_runs') }}
            </div>
            <div v-for="r in selectedRuns" :key="r.id" class="mb-2 rounded border bg-panel/50"
                 :class="solverRuns.has(r.id) ? 'border-acc/70' : 'border-edge'">
              <div class="row flex cursor-pointer items-center gap-2 hover:bg-acc/5" @click="toggle(r.id)">
                <Icon :name="expanded[r.id] ? 'chevronD' : 'chevronR'" :size="13" class="shrink-0 text-dim" />
                <b class="text-xs" :class="solverRuns.has(r.id) ? 'text-acc' : 'text-fglite'" :title="r.tool">{{ toolLabel(r.tool) }}</b>
                <span v-if="solverRuns.has(r.id)" class="inline-flex shrink-0 items-center gap-1 rounded bg-acc/15 px-1.5 py-0.5 text-[9px] font-bold text-acc">
                  <Icon name="flag" :size="10" />{{ t('proj.solved') }}
                </span>
                <span class="rounded bg-ink px-1.5 py-0.5 text-[9px]" :class="runStatusChip(effStatus(r))">{{ effStatus(r) }}</span>
                <span v-if="r.needs_password && pwdOf(r.file_id)" class="inline-flex shrink-0 items-center gap-1 rounded bg-acc/10 px-1.5 py-0.5 text-[9px] font-bold text-acc">
                  <Icon name="key" :size="10" />{{ pwdOf(r.file_id).value }}<span v-if="pwdOf(r.file_id).context" class="font-normal text-dim">(via {{ pwdOf(r.file_id).context }})</span>
                </span>
                <span v-else-if="r.needs_password" class="text-[9px] text-warn" :title="t('proj.pw_needed')">[pw]</span>
                <span class="truncate text-[11px] text-dim">{{ r.summary }}</span>
                <span class="ml-auto shrink-0 text-[9px] text-dim">{{ (r.artifacts||[]).length }} {{ t('proj.artifacts') }}</span>
              </div>
              <div v-if="(r.artifacts||[]).length" class="flex flex-wrap gap-2 border-t border-edge p-2">
                <template v-for="a in r.artifacts" :key="a.id">
                  <img v-if="IMG.test(a.name)" :src="artUrl(a)" class="h-20 cursor-zoom-in rounded border border-edge bg-ink" :title="a.name" @click="lightbox = artUrl(a)" @error="(e) => (e.target.style.display = 'none')" />
                  <a v-else :href="artUrl(a)" class="flex items-center gap-1 rounded border border-edge px-2 py-1 text-[10px] text-fglite hover:border-acc hover:text-acc" download>
                    <Icon name="download" :size="11" />{{ a.name }}
                  </a>
                </template>
              </div>
              <pre v-if="expanded[r.id] && outputs[r.id] != null" class="ansi max-h-72 overflow-auto border-t border-edge bg-ink p-2 leading-relaxed" v-html="ansiToHtml(outputs[r.id])"></pre>
            </div>
          </template>

          <template v-else-if="tab === 'extracted'">
            <div v-if="!childrenOf(selected).length" class="text-xs text-dim">{{ t('proj.no_extracted') }}</div>
            <div v-for="c in childrenOf(selected)" :key="c.id" @click="selected = c.id"
                 class="row cursor-pointer rounded hover:bg-acc/5">
              <span class="text-acc">[+]</span> {{ c.name }}
              <span class="text-dim">{{ fmtSize(c.size) }} · {{ toolLabel(originTool(c)) }}</span>
              <span v-if="pwdOf(c.id)" class="ml-2 text-[10px] text-acc">🔑 crack → {{ pwdOf(c.id).value }}<span v-if="pwdOf(c.id).context" class="text-dim"> (via {{ pwdOf(c.id).context }})</span></span>
              <span v-else-if="lockedIds.has(c.id)" class="ml-2 text-[10px] text-warn">[pw]</span>
            </div>
          </template>

          <template v-else>
            <div v-if="!selectedNode" class="text-xs text-dim">{{ t('proj.select_file') }}</div>
            <div v-else>
              <div v-if="IMG.test(selectedNode.name) && !previewErr">
                <img :src="fileUrl(selectedNode)" class="max-h-[55vh] cursor-zoom-in rounded border border-edge bg-ink" @click="lightbox = fileUrl(selectedNode)" @error="previewErr = true" />
              </div>
              <audio v-else-if="AUD.test(selectedNode.name)" :src="fileUrl(selectedNode)" controls class="w-full" />
              <video v-else-if="VID.test(selectedNode.name)" :src="fileUrl(selectedNode)" controls class="max-h-[55vh] w-full rounded" />
              <pre v-else-if="TXT.test(selectedNode.name)" class="out max-h-[55vh] overflow-auto rounded border border-edge bg-ink p-2 text-fglite">{{ outputs['file'+selectedNode.id] }}</pre>
              <div v-else class="text-xs text-dim">
                <a :href="fileUrl(selectedNode)" class="flex items-center gap-1 text-info hover:underline" download>
                  <Icon name="download" :size="13" />{{ selectedNode.name }}
                </a>
                <div class="mt-2 text-[11px] text-dim">{{ selectedNode.mime }} · {{ fmtSize(selectedNode.size) }}</div>
              </div>
            </div>
          </template>
        </div>
      </main>
      <div v-if="!narrow" class="sep sep-v" role="separator" aria-orientation="vertical" tabindex="0" :aria-label="t('proj.resize_panel')"
           @pointerdown="startDrag('right', $event)"
           @keydown.left.prevent="nudge('right', -16)" @keydown.right.prevent="nudge('right', 16)"></div>

      <!-- findings / terminal / logs (right) -->
      <aside class="flex min-h-0 flex-col border-l border-edge bg-panel"
             :class="narrow ? (mobilePane === 'panel' ? 'flex-1' : 'hidden') : 'shrink-0'"
             :style="narrow ? {} : { width: rightW + 'px' }">
        <div class="flex items-center gap-1 border-b border-edge bg-panel2 px-2 py-1.5 text-[11px]">
          <button type="button" @click="rightTab = 'findings'" class="rounded px-2.5 py-0.5" :class="rightTabBtn('findings')">
            {{ t('proj.tab_findings') }}
            <span v-if="flags.length" class="text-acc">{{ flags.length }}</span>
            <span v-if="locked.length" class="text-warn"> ▣{{ locked.length }}</span>
          </button>
          <button type="button" @click="rightTab = 'terminal'" class="rounded px-2.5 py-0.5" :class="rightTabBtn('terminal')">
            {{ t('proj.right_terminal') }}
          </button>
          <button type="button" @click="rightTab = 'logs'" class="rounded px-2.5 py-0.5" :class="rightTabBtn('logs')">
            {{ t('proj.right_logs') }}
            <span v-if="log.length" class="text-acc">{{ log.length }}</span>
          </button>
          <button type="button" @click="rightTab = 'graph'" class="rounded px-2.5 py-0.5" :class="rightTabBtn('graph')">
            {{ t('proj.right_graph') }}
          </button>
        </div>

        <!-- findings -->
        <div v-show="rightTab === 'findings'" class="min-h-0 flex-1 overflow-auto p-2">
          <template v-if="flags.length">
            <div class="mb-2 flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-acc">
              <Icon name="flag" :size="12" /> {{ t('proj.flags_found', { n: flags.length }) }}
              <button type="button" @click="copyAllFlags"
                      class="ml-auto rounded border border-edge px-1.5 py-0.5 font-normal normal-case tracking-normal text-dim hover:border-acc hover:text-acc"
                      :aria-label="t('proj.copy_all_flags')"><Icon name="copy" :size="10" /> {{ t('proj.copy_all_flags') }}</button>
            </div>
            <div v-for="c in flagCards" :key="c.f.id" class="mb-2 rounded border border-acc/40 bg-acc/5 p-2">
              <div class="flex items-start gap-1">
                <span class="text-acc">>_</span>
                <div class="min-w-0 flex-1 break-all text-xs font-bold text-acc">{{ c.f.value }}</div>
                <button type="button" @click="copyText(c.f.value)" :aria-label="t('proj.copy_flag', { v: c.f.value })"
                        class="shrink-0 rounded border border-edge p-0.5 text-dim hover:border-acc hover:text-acc">
                  <Icon :name="copied === c.f.value ? 'check' : 'copy'" :size="11" />
                </button>
              </div>
              <div class="mt-1 text-[11px] text-dim">
                {{ t('proj.in') }}
                <button class="text-fg hover:text-acc hover:underline" @click="c.f.file_id && (selected = c.f.file_id)">{{ (treeById[c.f.file_id] || {}).name || '?' }}</button>
                · <b class="text-fglite">{{ c.ev && c.ev.run ? toolLabel(c.ev.tool) : sourceHow(c.f.source) }}</b>
              </div>
              <div class="mt-1 break-all text-[10px] text-dim">{{ chainText(c.f) }}</div>
              <pre v-if="c.ev" class="mt-1 max-h-28 overflow-auto whitespace-pre rounded border border-edge bg-ink p-1.5 text-[10px] text-fglite"># {{ c.ev.tool }}{{ c.ev.command ? '  —  ' + c.ev.command : '' }}
{{ c.ev.lines }}</pre>
              <pre v-else-if="c.f.context" class="mt-1 max-h-24 overflow-auto whitespace-pre-wrap break-all rounded border border-edge bg-ink p-1.5 text-[10px] text-dim">{{ c.f.context }}</pre>
            </div>
            <div class="mb-1 mt-3 flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-acc">
              <Icon name="term" :size="12" /> {{ t('proj.solver_chain', { n: flagTools().length }) }}
            </div>
            <div class="flex flex-wrap gap-1">
              <span v-for="t in flagTools()" :key="t" :title="t" class="rounded px-1.5 py-0.5 text-[10px]"
                    :class="solverTools.has(t) ? 'border border-acc bg-acc/10 text-acc' : 'bg-panel2 text-fglite'">{{ toolLabel(t) }}</span>
            </div>
          </template>
          <div v-else class="mb-1 flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-dim">
            <Icon name="flag" :size="12" /> {{ t('proj.flag') }} (0)
          </div>

          <div class="mb-1 mt-3 flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-warn">
            <Icon name="key" :size="12" /> {{ t('proj.password', { n: passwords.length }) }}
          </div>
          <div v-for="p in passwords" :key="p.id" class="row rounded text-xs text-warn">
            {{ p.value }}<span class="text-dim"> — {{ t('proj.via') }} </span><b class="text-warn">{{ p.context || '?' }}</b>
            <span class="text-dim"> ({{ p.source }})</span>
          </div>

          <div class="mb-1 mt-3 flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-info">
            <Icon name="lock" :size="12" /> {{ t('proj.locked', { n: locked.length }) }}
            <label class="ml-auto cursor-pointer rounded border border-edge px-1.5 py-0.5 font-normal normal-case tracking-normal text-dim hover:border-acc hover:text-acc">
              <Icon name="upload" :size="10" /> {{ wlUploading ? '…' : t('proj.wl_add') }}
              <input type="file" class="hidden" accept=".txt,.lst,.gz" :disabled="wlUploading" @change="uploadWordlist" />
            </label>
          </div>
          <div v-for="l in locked" :key="l.file_id" class="mb-2 rounded border border-edge p-2">
            <div class="truncate text-xs text-fglite">{{ l.name }} <span class="text-dim">({{ l.kind }})</span></div>
            <div class="mt-1 flex gap-1">
              <select v-model="l._wl" @change="persistWl(l)" class="w-full rounded border border-edge bg-ink px-1 py-0.5 text-[10px] text-fglite focus:border-acc">
                <option value="">{{ t('proj.all') }}</option>
                <option v-for="w in wordlists" :key="w.name" :value="w.name">{{ w.name }}</option>
              </select>
              <button @click="crack(l, l._wl)" class="kb kb-acc shrink-0 text-[10px]"><Icon name="key" :size="11" />{{ t('proj.crack') }}</button>
            </div>
          </div>

          <div class="mb-1 mt-4 flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-acc">
            <Icon name="link" :size="12" /> {{ t('proj.flag_route') }}
          </div>
          <pre class="max-h-44 overflow-auto whitespace-pre text-[10px] leading-5 text-fglite">{{ routeTreeText || t('proj.no_flag') }}</pre>
        </div>

        <!-- terminal -->
        <div v-show="rightTab === 'terminal'" class="flex min-h-0 flex-1 flex-col">
          <div class="flex items-center bg-panel2 px-3 py-1 text-left text-[10px] text-dim">{{ t('proj.terminal_label') }}</div>
          <div class="min-h-0 flex-1"><Terminal :pid="props.id" /></div>
        </div>

        <!-- logs: live events on top, all runs below -->
        <div v-show="rightTab === 'logs'" class="flex min-h-0 flex-1 flex-col">
          <div class="flex items-center bg-panel2 px-3 py-1 text-[10px] font-bold uppercase tracking-widest text-dim">
            <Icon name="term" :size="12" /> <span class="ml-1">{{ t('proj.log_live', { n: log.length }) }}</span>
            <button type="button" @click="copyLogs"
                    class="ml-auto rounded border border-edge px-1 py-0.5 font-normal normal-case tracking-normal text-dim hover:border-acc hover:text-acc"
                    :aria-label="t('proj.copy_logs')"><Icon name="copy" :size="10" /> {{ t('proj.copy_logs') }}</button>
          </div>
          <div ref="logsRef" class="shrink-0 overflow-auto border-b border-edge/50 bg-ink/50 px-2 py-1" :style="{ height: logSplit + 'px' }"
               role="log" aria-live="polite" aria-relevant="additions">
            <p v-if="!log.length" class="text-[11px] text-dim">{{ t('proj.no_events') }}</p>
            <div v-for="(m, i) in log" :key="i" class="text-[11px] leading-5"
                 :class="m.level === 'warn' ? 'text-warn' : 'text-dim'">
              <span class="mr-1 text-[10px] text-dim" v-if="m.ts">{{ fmtTime(m.ts) }}</span>
              <span class="text-[10px]">{{ m.type }}</span>
              <span v-if="m.message">{{ m.message }}</span>
              <span v-else-if="m.type === 'file'"> · {{ m.name }}</span>
              <span v-else-if="m.type === 'tool'"> · {{ m.name }} → {{ toolLabel(m.tool) }} ({{ m.status }})</span>
              <span v-else-if="m.type === 'crack'">
                · {{ m.status }}
                <span v-if="m.password">→ {{ m.password }} <span v-if="m.wordlist" class="text-warn">(via {{ m.wordlist }})</span></span>
              </span>
            </div>
          </div>
          <div class="sep sep-h" role="separator" aria-orientation="horizontal" tabindex="0" :aria-label="t('proj.resize_logs')"
               @pointerdown="startDrag('logsplit', $event)"
               @keydown.up.prevent="nudge('logsplit', -16)" @keydown.down.prevent="nudge('logsplit', 16)"></div>
          <div class="flex items-center gap-3 px-3 pb-1 pt-1 text-[10px] font-bold uppercase tracking-widest">
            <button type="button" @click="logView = 'runs'"
                    :class="logView === 'runs' ? 'text-acc' : 'text-dim hover:text-fglite'">
              {{ t('proj.log_runs', { n: runs.length }) }}
            </button>
            <button type="button" @click="showFullLogs"
                    :class="logView === 'full' ? 'text-acc' : 'text-dim hover:text-fglite'">
              {{ t('proj.full_logs') }}
            </button>
            <button type="button" @click="logView === 'full' ? copyFullLogs() : copyLogs()"
                    class="ml-auto rounded border border-edge px-1 py-0.5 font-normal normal-case tracking-normal text-dim hover:border-acc hover:text-acc">
              <Icon name="copy" :size="10" /> {{ logView === 'full' ? t('proj.copy_full_logs') : t('proj.copy_logs') }}
            </button>
          </div>
          <div v-show="logView === 'runs'" class="min-h-0 flex-1 overflow-auto bg-ink p-1.5">
            <p v-if="!logRuns.length" class="text-[11px] text-dim">{{ t('proj.log_empty') }}</p>
            <div v-for="r in logRuns" :key="r.id" class="border-b border-edge/50 last:border-b-0">
              <button type="button" @click="toggleRun(r.id)"
                      class="flex w-full items-center gap-1.5 py-1 pr-1 text-left text-[11px] hover:bg-acc/5">
                <Icon :name="expanded['run:' + r.id] ? 'chevronD' : 'chevronR'" :size="11" class="shrink-0 text-dim" />
                <Icon name="term" :size="11" class="shrink-0 text-dim" />
                <span class="shrink-0 text-[9px] text-dim" :title="fmtDate(r.finished_at || r.started_at)">{{ fmtTime(r.finished_at || r.started_at) }}</span>
                <b class="shrink-0 text-fglite">{{ toolLabel(r.tool) }}</b>
                <span class="min-w-0 truncate text-dim">{{ (treeById[r.file_id] || {}).name || r.file_id }}</span>
                <span class="rounded bg-panel2 px-1 py-0.5 text-[9px]" :class="runStatusChip(effStatus(r))">{{ effStatus(r) }}</span>
                <span v-if="r.needs_password && !passwordFileIds.has(r.file_id)" class="shrink-0 text-[9px] text-warn">[pw]</span>
                <span v-if="r.needs_password && pwdOf(r.file_id)" class="shrink-0 text-[9px] text-acc" :title="pwdOf(r.file_id).context ? 'via ' + pwdOf(r.file_id).context : ''">🔑{{ pwdOf(r.file_id).value }}</span>
                <span v-if="r.exit_code != null" class="ml-auto shrink-0 text-[9px] text-dim">exit {{ r.exit_code }}</span>
              </button>
              <pre v-if="expanded['run:' + r.id] && outputs[r.id] != null"
                   class="ansi max-h-52 overflow-auto whitespace-pre-wrap break-words border-t border-edge/60 bg-ink p-2 text-[10px] leading-relaxed"
                   v-html="ansiToHtml(outputs[r.id])"></pre>
            </div>
          </div>
          <div v-show="logView === 'full'" class="min-h-0 flex-1 overflow-auto bg-ink p-2">
            <p v-if="fullLogsBusy" class="animate-blink text-[11px] text-acc">▋ {{ t('proj.full_logs') }}…</p>
            <pre v-else class="ansi whitespace-pre-wrap break-words text-[10px] leading-relaxed text-fglite">{{ fullLogs }}</pre>
          </div>
        </div>

        <!-- graph: force-directed tool graph + flag timeline -->
        <div v-show="rightTab === 'graph'" class="flex min-h-0 flex-1 flex-col">
          <div v-if="!tree.length" class="p-2 text-[11px] text-dim">{{ t('proj.no_graph') }}</div>
          <template v-else>
            <!-- timeline: how the flag was found (click → selects the file) -->
            <div v-if="routeSteps.length" class="max-h-40 shrink-0 overflow-auto border-b border-edge p-2">
              <div class="mb-1 flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-acc">
                <Icon name="flag" :size="12" /> {{ t('proj.timeline') }}
              </div>
              <ol>
                <li v-for="(s, i) in routeSteps" :key="s.id" class="flex items-center gap-1.5 py-0.5 text-[11px]">
                  <span class="w-4 shrink-0 text-right text-[9px] text-dim">{{ i + 1 }}</span>
                  <span class="shrink-0 text-dim">{{ i === 0 ? '▲' : '↳' }}</span>
                  <button type="button" @click="selectFile(s.id)" class="truncate text-left hover:underline"
                          :class="selected === s.id ? 'text-acc' : (s.flag ? 'font-bold text-acc' : 'text-fglite')">{{ s.name }}</button>
                  <span class="shrink-0 rounded bg-panel2 px-1 py-0.5 text-[9px] text-dim">{{ toolLabel(s.tool) }}</span>
                  <span v-if="s.pwd" class="shrink-0 text-[9px] text-warn" :title="s.pwd.context">🔑{{ s.pwd.value }}</span>
                  <span v-if="s.flag" class="shrink-0 text-[9px] text-acc">★</span>
                </li>
              </ol>
            </div>

            <!-- the graph: drag to move, wheel/pinch to zoom, click a dot to select the file -->
            <div class="relative min-h-0 flex-1">
              <GraphView ref="graphRef" :nodes="graphNodes" :links="graphLinks" :selected="selected" @select="selectFile" />
              <button type="button" @click="graphRef && graphRef.fit()"
                      class="absolute right-2 top-2 rounded border border-edge bg-panel/90 px-1.5 py-0.5 text-[9px] text-dim hover:border-acc hover:text-acc"
                      :aria-label="t('proj.graph_fit')">fit</button>
            </div>
            <p class="shrink-0 border-t border-edge px-2 py-1 text-[9px] text-dim">{{ t('proj.graph_hint') }}</p>
          </template>
        </div>
      </aside>
    </div>

    <!-- lightbox -->
    <div v-if="lightbox" class="fixed inset-0 z-40 flex items-center justify-center bg-black/80" @click="lightbox = null">
      <img :src="lightbox" class="max-h-[92vh] max-w-[94vw] rounded border border-edge" />
    </div>

    <!-- report modal -->
    <div v-if="report.open" class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-3 sm:p-6" @click.self="report.open = false">
      <div class="flex max-h-[88vh] w-[min(980px,calc(100vw-1.5rem))] flex-col rounded border border-edge bg-panel">
        <div class="flex items-center gap-2 border-b border-edge bg-panel2 px-4 py-2 text-xs">
          <Icon name="report" :size="14" class="text-acc" /><b>{{ t('report.title') }}</b><span v-if="report.busy" class="animate-blink text-acc">▋</span>
          <label class="flex items-center gap-1.5 text-[10px] text-dim">
            {{ t('report.lang') }}
            <select v-model="reportLang" class="rounded border border-edge bg-ink px-1 py-0.5 text-[10px] uppercase focus:border-acc">
              <option value="en">English</option>
              <option value="it">Italiano</option>
            </select>
          </label>
          <button @click="copyReport" class="kb ml-auto text-[10px]"><Icon name="copy" :size="11" />{{ t('report.copy') }}</button>
          <button @click="downloadReport" class="kb text-[10px]"><Icon name="download" :size="11" />.md</button>
          <button @click="report.open = false" class="kb text-[10px]" :aria-label="t('report.close')"><Icon name="close" :size="11" /></button>
        </div>
        <div class="md min-h-0 flex-1 overflow-auto p-5" v-html="mdToHtml(report.text)"></div>
      </div>
    </div>

    <!-- transcript modal (copy/paste into an AI agent) -->
    <div v-if="transcript.open" class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-3 sm:p-6" @click.self="transcript.open = false">
      <div class="flex max-h-[88vh] w-[min(900px,calc(100vw-1.5rem))] flex-col rounded border border-edge bg-panel">
        <div class="flex items-center gap-2 border-b border-edge bg-panel2 px-4 py-2 text-xs">
          <Icon name="copy" :size="14" class="text-acc" /><b>{{ t('proj.transcript') }}</b><span v-if="transcript.busy" class="animate-blink text-acc">▋</span>
          <button @click="copyTranscript" class="kb ml-auto text-[10px]"><Icon name="copy" :size="11" />{{ t('report.copy') }}</button>
          <button @click="downloadTranscript" class="kb text-[10px]"><Icon name="download" :size="11" />.md</button>
          <button @click="transcript.open = false" class="kb text-[10px]" :aria-label="t('report.close')"><Icon name="close" :size="11" /></button>
        </div>
        <pre class="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-words p-4 text-[11px] leading-relaxed text-fglite">{{ transcript.text }}</pre>
      </div>
    </div>
  </div>
</template>
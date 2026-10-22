<script setup>
import { ref, computed, onMounted, onBeforeUnmount, watch, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { api, wsUrl, fmtSize, fmtDate, fmtTime } from '../api'
import { toolLabel } from '../labels'
import { ansiToHtml } from '../lib/ansi'
import { usePaneResize } from '../composables/usePaneResize'
import { t, lang } from '../i18n'
import { notify } from '../toast'
import TextModal from '../components/TextModal.vue'
import Terminal from '../components/Terminal.vue'
import GraphView from '../components/GraphView.vue'
import Icon from '../components/Icon.vue'

const props = defineProps({ id: { type: String, required: true } })
const router = useRouter()

const project = ref(null)
const runs = ref([])
const findings = ref([])
const locked = ref([])
const cracks = ref({ running: false, jobs: [] })
const now = ref(Date.now() / 1000)
let crackTick = null
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
  return mobilePane.value === p ? 'bg-acc text-ink font-bold' : 'text-dim hover:text-fglite'
}
const gridRef = ref(null)
const treeScrollRef = ref(null)
const logsRef = ref(null)
const graphRef = ref(null)
const { leftW, rightW, logSplit, startDrag, endDrag, nudge } = usePaneResize(gridRef, logsRef)
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

// --- crack queue: live jobs of this project (queued/running/finished) -------
const crackActive = computed(() => (cracks.value.jobs || []).filter((j) => j.status === 'queued' || j.status === 'running'))
const crackShown = computed(() => {
  const jobs = cracks.value.jobs || []
  const active = jobs.filter((j) => j.status === 'queued' || j.status === 'running')
  const done = jobs.filter((j) => !['queued', 'running'].includes(j.status))
  return [...active, ...done].slice(0, 12)
})
function crackChip(status) {
  const map = {
    running: 'border-warn/60 bg-warn/10 text-warn',
    queued: 'border-info/50 bg-info/10 text-info',
    found: 'border-acc/50 bg-acc/10 text-acc',
    not_found: 'border-edge text-dim',
    cancelled: 'border-edge text-dim',
    error: 'border-danger/50 bg-danger/10 text-danger',
  }
  return map[status] || 'border-edge text-dim'
}
function crackLabel(status) { return t('proj.crackq_' + status) }
function queuePos(j) {
  const q = (cracks.value.jobs || []).filter((x) => x.status === 'queued').sort((a, b) => a.id - b.id)
  return q.findIndex((x) => x.id === j.id) + 1
}
function elapsed(j) {
  const end = j.finished_at || now.value
  const start = j.started_at || j.queued_at
  return Math.max(0, end - start)
}
function fmtDur(sec) {
  sec = Math.max(0, Math.round(sec))
  if (sec < 60) return sec + 's'
  const m = Math.floor(sec / 60), s = sec % 60
  return `${m}m ${String(s).padStart(2, '0')}s`
}
async function cancelCrack(j) {
  try {
    await api(`/cracks/${j.id}`, { method: 'DELETE' })
    scheduleRefresh()
  } catch (e) { notify(String(e), 'error') }
}

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
// the solution as computed by the backend (/summary): flags with chain and
// evidence, the route through the tree, solver/route runs, tools involved
const summary = ref({ flags: [], route_ids: [], route_steps: [], route_tree: '',
  relevant_run_ids: [], solver_run_ids: [], flag_tools: [], solver_tools: [] })
const routeSteps = computed(() => summary.value.route_steps)
// clicking a graph node (or a timeline step) selects that file on the left,
// so the details stay in one place (tree + overview/extracted)
function selectFile(id) {
  if (id == null) return
  selected.value = id
  if (narrow.value) mobilePane.value = 'files'   // show the left menu on mobile
  if (search.value) search.value = ''            // a filter could hide it
  // expand the ancestors and their tool groups so the file is actually visible
  const s = new Set(collapsed.value)
  let node = treeById.value[id]
  while (node) {
    s.delete(node.id)
    s.delete(`g:${node.parent_id ?? 0}:${originTool(node)}`)
    node = treeById.value[node.parent_id]
  }
  collapsed.value = s
  nextTick(() => {
    const row = treeScrollRef.value && treeScrollRef.value.querySelector(`[data-fid="${id}"]`)
    if (row && row.scrollIntoView) row.scrollIntoView({ block: 'nearest' })
  })
}
function shortName(s) { s = String(s); return s.length > 18 ? s.slice(0, 17) + '…' : s }
const notes = computed(() => findings.value.filter((f) => f.kind === 'note'))
const routeTreeText = computed(() => summary.value.route_tree)
const routeIdSet = computed(() => new Set(summary.value.route_ids))
const routeNodes = () => tree.value.filter((n) => routeIdSet.value.has(n.id))
const solverRuns = computed(() => new Set(summary.value.solver_run_ids))
const solverTools = computed(() => new Set(summary.value.solver_tools))
const flagTools = () => summary.value.flag_tools
// each flag paired with the tool output that shows it
const flagCards = computed(() => summary.value.flags.map((f) => ({
  f: { ...f, file_id: f.file ? f.file.id : null }, ev: f.evidence,
})))
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
  return tab.value === tb ? 'bg-acc text-ink font-bold' : 'text-dim hover:text-fglite'
}
function rightTabBtn(t) {
  return rightTab.value === t ? 'bg-acc text-ink font-bold' : 'text-dim hover:text-fglite'
}

// every load() gets a sequence number: a slow response for a previous project
// (or an older refresh) must never overwrite newer data
let loadSeq = 0
async function load() {
  const seq = ++loadSeq
  const id = props.id
  try {
    const [proj, fnd, lck, wls, rns, sum, cq] = await Promise.all([
      api(`/projects/${id}`),
      api(`/projects/${id}/findings`),
      api(`/projects/${id}/locked`),
      api('/wordlists'),
      api(`/projects/${id}/runs`),
      api(`/projects/${id}/summary`),
      api(`/projects/${id}/crack/status`),
    ])
    if (seq !== loadSeq) return
    for (const l of lck) {
      try { l._wl = localStorage.getItem(`steg.wl.${id}.${l.file_id}`) || '' } catch { l._wl = '' }
    }
    project.value = proj
    findings.value = fnd
    locked.value = lck
    wordlists.value = wls
    runs.value = rns
    summary.value = sum
    cracks.value = cq || { running: false, jobs: [] }
    now.value = Date.now() / 1000
    // seed the live log from persisted events so the Logs tab is not empty on
    // projects that were analysed in a previous session (only once, and only if
    // no live event has arrived yet)
    if (!logSeeded) {
      logSeeded = true
      try {
        const evs = await api(`/projects/${id}/events`)
        if (seq === loadSeq && !log.value.length) {
          log.value = (evs || []).map((e) => ({ type: 'event', level: e.level, message: e.message, ts: e.ts }))
        }
      } catch { /* no history */ }
    }
    if (selected.value == null && tree.value.length) selected.value = tree.value[0].id
    // refresh the full-logs view if the user is looking at it
    fullLogs.value = ''
    if (logView.value === 'full') showFullLogs()
  } catch (e) { if (seq === loadSeq) err.value = String(e) }
}

// live events; reconnects (backend restart, network blip) until unmounted
let disposed = false
let reconnectTimer = null
function connect() {
  clearTimeout(reconnectTimer)
  if (ws) { ws.onclose = null; try { ws.close() } catch {} }
  const id = props.id
  ws = new WebSocket(wsUrl(`/ws/projects/${id}`))
  ws.onclose = () => {
    if (disposed || id !== props.id) return
    reconnectTimer = setTimeout(() => { connect(); load() }, 2000)
  }
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
  return outputs.value[rid]
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

async function openReport() {
  reportLang.value = lang.value
  report.value = { open: true, text: '…', busy: true }
  try {
    await buildReport(reportLang.value)
  } catch (e) {
    report.value = { open: true, text: '⚠️ ' + String(e), busy: false }
  }
}
// report, full logs and transcript are built by the backend (API-first:
// the same text is available to scripts and AI agents)
async function buildReport(lng) {
  const text = await api(`/projects/${props.id}/report?format=md&lang=${lng}`)
  report.value = { open: true, text, busy: false }
}
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
  return api(`/projects/${props.id}/logs`)
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
async function buildTranscript() {
  return api(`/projects/${props.id}/transcript`)
}
async function openTranscript() {
  transcript.value = { open: true, text: '', busy: true }
  try {
    transcript.value = { open: true, text: await buildTranscript(), busy: false }
  } catch (e) {
    transcript.value = { open: true, text: '⚠️ ' + String(e), busy: false }
  }
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
  load(); connect()
})
onMounted(() => {
  mq = window.matchMedia('(max-width: 900px)')
  narrow.value = mq.matches
  mq.addEventListener('change', onMq)
  load(); connect()
  // tick only while a crack is running, so its elapsed time stays live
  crackTick = setInterval(() => { if (crackActive.value.length) now.value = Date.now() / 1000 }, 1000)
})
onBeforeUnmount(() => {
  if (mq) mq.removeEventListener('change', onMq)
  endDrag()
  disposed = true
  clearInterval(crackTick)
  clearTimeout(refreshTimer)
  clearTimeout(reconnectTimer)
  if (ws) { ws.onclose = null; try { ws.close() } catch {} }
})
</script>

<template>
  <div class="flex h-full flex-col font-mono">
    <h1 class="sr-only">{{ project?.name }}</h1>
    <!-- action bar -->
    <div class="flex flex-wrap items-center gap-2 border-b border-edge bg-panel px-3 py-1.5 text-xs">
      <button @click="router.push(project?.ctf_id ? `/ctf/${project.ctf_id}` : '/')" class="kb px-2" :aria-label="t('proj.back_home')"><Icon name="chevronR" class="rotate-180" :size="12" /></button>
      <span class="font-bold text-fgx">{{ project?.name }}</span>
      <span class="rounded border px-2 py-0.5 text-[10px]" :class="statusChip(project?.status)">
        {{ project?.status }}
      </span>
      <span v-if="project?.solved" class="rounded border border-acc/50 bg-acc/10 px-2 py-0.5 text-[10px] text-acc"
            :title="project.flag">✓ {{ t('ctf.solved') }}</span>
      <RouterLink v-if="project?.ctf_id" :to="`/ctf/${project.ctf_id}`" class="text-[10px] text-dim underline hover:text-acc">
        {{ t('ctf.in_ctf') }} {{ project.category ? '· ' + project.category : '' }}
      </RouterLink>
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
        <h2 class="sr-only">{{ t('proj.files') }}</h2>
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
        <div ref="treeScrollRef" class="min-h-0 flex-1 overflow-auto p-1.5">
          <div v-for="n in visibleTree" :key="n._gid || n.id"
               :data-fid="n._group ? null : n.id"
               @click="n._group ? toggleNode(n) : selectFile(n.id)"
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
      <section class="flex min-h-0 min-w-0 flex-1 flex-col" :aria-label="t('proj.detail')"
               :class="narrow && mobilePane !== 'detail' ? 'hidden' : ''">
        <h2 class="sr-only">{{ t('proj.detail') }}</h2>
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
      </section>
      <div v-if="!narrow" class="sep sep-v" role="separator" aria-orientation="vertical" tabindex="0" :aria-label="t('proj.resize_panel')"
           @pointerdown="startDrag('right', $event)"
           @keydown.left.prevent="nudge('right', -16)" @keydown.right.prevent="nudge('right', 16)"></div>

      <!-- findings / terminal / logs (right) -->
      <aside class="flex min-h-0 flex-col border-l border-edge bg-panel"
             :class="narrow ? (mobilePane === 'panel' ? 'flex-1' : 'hidden') : 'shrink-0'"
             :style="narrow ? {} : { width: rightW + 'px' }">
        <h2 class="sr-only">{{ t('proj.tab_findings') }}</h2>
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
                · <b class="text-fglite">{{ c.ev ? toolLabel(c.ev.tool) : c.f.how }}</b>
              </div>
              <div class="mt-1 break-all text-[10px] text-dim">{{ c.f.chain_text }}</div>
              <div v-if="c.ev && c.ev.decoded" class="mt-1 break-all text-[10px] text-warn">
                {{ t('proj.decoded_with') }} {{ c.ev.decoded }}<span v-if="c.ev.match">: <code class="text-fglite">{{ c.ev.match.slice(0, 120) }}</code></span>
              </div>
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

          <template v-if="cracks.jobs.length">
            <div class="mb-1 mt-3 flex flex-wrap items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-info">
              <Icon name="key" :size="12" /> {{ t('proj.crackq', { n: cracks.jobs.length }) }}
              <span v-if="crackActive.length" class="font-normal normal-case tracking-normal text-dim">
                {{ t('proj.crackq_active', { n: crackActive.length, m: cracks.jobs.length - crackActive.length }) }}
              </span>
            </div>
            <div v-for="j in crackShown" :key="j.id"
                 class="mb-1 flex items-center gap-1.5 rounded border border-edge/70 px-1.5 py-1 text-[10px]">
              <span class="shrink-0 rounded border px-1 py-0.5 text-[9px]" :class="crackChip(j.status)">{{ crackLabel(j.status) }}</span>
              <span class="min-w-0 flex-1 truncate text-fglite" :title="j.name">{{ j.name }}</span>
              <span v-if="j.status === 'queued'" class="shrink-0 text-dim">{{ t('proj.crackq_pos', { n: queuePos(j) }) }}</span>
              <span v-else-if="j.status === 'running'" class="shrink-0 text-warn">{{ fmtDur(elapsed(j)) }}</span>
              <span v-else-if="j.status === 'found'" class="shrink-0 text-acc">
                {{ j.password }}<span v-if="j.wordlist" class="text-dim"> · {{ j.wordlist }}</span>
              </span>
              <span v-else class="shrink-0 text-dim">{{ fmtDur(elapsed(j)) }}</span>
              <button v-if="j.status === 'queued'" type="button" @click="cancelCrack(j)"
                      class="kb kb-danger shrink-0 px-1 py-0 text-[10px]" :aria-label="t('proj.crackq_cancel')"
                      :title="t('proj.crackq_cancel')">✕</button>
            </div>
          </template>

          <div class="mb-1 mt-4 flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-acc">
            <Icon name="link" :size="12" /> {{ t('proj.flag_route') }}
          </div>
          <pre class="max-h-44 overflow-auto whitespace-pre text-[10px] leading-5 text-fglite">{{ routeTreeText || t('proj.no_flag') }}</pre>
        </div>

        <!-- terminal -->
        <div v-show="rightTab === 'terminal'" class="flex min-h-0 flex-1 flex-col">
          <div class="flex items-center bg-panel2 px-3 py-1 text-left text-[10px] text-dim">{{ t('proj.terminal_label') }}</div>
          <div class="min-h-0 flex-1"><Terminal :key="props.id" :pid="props.id" /></div>
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
                  <span v-if="s.password" class="shrink-0 text-[9px] text-warn">🔑{{ s.password }}</span>
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
    <TextModal v-if="report.open" :title="t('report.title')" :text="report.text" :busy="report.busy"
               markdown :filename="`stegsuite-report-${props.id}.md`" @close="report.open = false">
      <template #controls>
        <label class="flex items-center gap-1.5 text-[10px] text-dim">
          {{ t('report.lang') }}
          <select v-model="reportLang" class="rounded border border-edge bg-ink px-1 py-0.5 text-[10px] uppercase focus:border-acc">
            <option value="en">English</option>
            <option value="it">Italiano</option>
          </select>
        </label>
      </template>
    </TextModal>

    <!-- transcript modal (copy/paste into an AI agent) -->
    <TextModal v-if="transcript.open" :title="t('proj.transcript')" icon="copy" :text="transcript.text"
               :busy="transcript.busy" width="900px" :filename="`stegsuite-transcript-${props.id}.md`"
               @close="transcript.open = false" />
  </div>
</template>
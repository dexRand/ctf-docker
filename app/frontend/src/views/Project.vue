<script setup>
import { ref, computed, onMounted, onBeforeUnmount, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api, wsUrl, fmtSize, fmtDate, STATUS_COLOR } from '../api'
import { mdToHtml } from '../md'
import Terminal from '../components/Terminal.vue'
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
const showTerm = ref(true)
const outputs = ref({})
const expanded = ref({})
const lightbox = ref(null)
const previewErr = ref(false)
const report = ref({ open: false, text: '', busy: false })
const err = ref('')
let ws = null
let refreshTimer = null

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
const visibleTree = computed(() => {
  const m = childrenByParent.value
  const out = []
  const walk = (pid, depth) => {
    const groups = new Map()
    for (const n of (m[pid] || [])) {
      const t = originTool(n)
      if (!groups.has(t)) groups.set(t, [])
      groups.get(t).push(n)
    }
    const multi = groups.size > 1
    for (const [tool, list] of groups) {
      if (multi) {
        const gid = `g:${pid}:${tool}`
        out.push({ _group: true, _gid: gid, _pid: pid, _tool: tool, _depth: depth, _kids: list.length, name: tool })
        if (collapsed.value.has(gid)) continue
        for (const n of list) {
          out.push({ ...n, _depth: depth + 1, _kids: (m[n.id] || []).length })
          if (!collapsed.value.has(n.id)) walk(n.id, depth + 1)
        }
      } else {
        for (const n of list) {
          out.push({ ...n, _depth: depth, _kids: (m[n.id] || []).length })
          if (!collapsed.value.has(n.id)) walk(n.id, depth)
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
const lockedIds = computed(() => new Set(locked.value.map((l) => l.file_id)))
const selectedNode = computed(() => tree.value.find((n) => n.id === selected.value) || null)
const childrenOf = (id) => tree.value.filter((n) => n.parent_id === id)
const selectedRuns = computed(() => runsByFile.value[selected.value] || [])
const flags = computed(() => findings.value.filter((f) => f.kind === 'flag'))
const passwords = computed(() => findings.value.filter((f) => f.kind === 'password'))
const notes = computed(() => findings.value.filter((f) => f.kind === 'note'))
const routeTreeText = computed(() => (routeNodes().length ? asciiRouteTree() : ''))
const routeIdSet = computed(() => new Set(routeNodes().map((n) => n.id)))
const producingToolByNode = computed(() => {
  const m = {}
  for (const n of tree.value) {
    const t = originTool(n)
    if (t === 'upload' || t === 'extracted') continue
    ;(m[n.parent_id] ||= new Set()).add(t)
  }
  return m
})
const findingToolKeys = computed(() => {
  const s = new Set()
  for (const f of findings.value) {
    for (const part of String(f.source || '').split(':')) if (part) s.add(`${f.file_id}:${part}`)
  }
  return s
})
const relevantRuns = computed(() => runs.value.filter((r) => {
  if (!routeIdSet.value.has(r.file_id)) return false
  if ((producingToolByNode.value[r.file_id] || new Set()).has(r.tool)) return true
  if (findingToolKeys.value.has(`${r.file_id}:${r.tool}`)) return true
  return ['crack', 'hashcat', 'fcrackzip'].includes(r.tool)
}))
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
  if (routeIdSet.value.has(n.id)) return 'text-emerald-400'
  if (nearIdSet.value.has(n.id)) return 'text-slate-100'
  return 'text-slate-500'
}
function groupColor(n) {
  if (!flags.value.length) return 'text-slate-400'
  const kids = childrenByParent.value[n._pid] || []
  const mine = kids.filter((c) => originTool(c) === n._tool)
  if (mine.some((c) => routeIdSet.value.has(c.id))) return 'text-emerald-400'
  if (mine.some((c) => nearIdSet.value.has(c.id))) return 'text-slate-100'
  return 'text-slate-500'
}

async function load() {
  try {
    project.value = await api(`/projects/${props.id}`)
    ;[findings.value, locked.value, wordlists.value] = await Promise.all([
      api(`/projects/${props.id}/findings`),
      api(`/projects/${props.id}/locked`),
      api('/wordlists'),
    ])
    runs.value = await api(`/projects/${props.id}/runs`)
    if (selected.value == null && tree.value.length) selected.value = tree.value[0].id
  } catch (e) { err.value = String(e) }
}

function connect() {
  ws = new WebSocket(wsUrl(`/ws/projects/${props.id}`))
  ws.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data) } catch { return }
    if (m.type === 'ping') return
    log.value.push(m)
    if (log.value.length > 800) log.value.splice(0, 400)
    if (['status', 'file', 'tool', 'crack'].includes(m.type)) scheduleRefresh()
  }
}
function scheduleRefresh() {
  if (refreshTimer) return
  refreshTimer = setTimeout(() => { refreshTimer = null; load() }, 600)
}
async function action(kind) {
  try { await api(`/projects/${props.id}/${kind}`, { method: 'POST' }) } catch (e) { err.value = String(e) }
}
async function del() {
  if (!confirm('Eliminare il progetto e tutti i file?')) return
  await api(`/projects/${props.id}`, { method: 'DELETE' })
  router.push('/')
}
async function crack(item, wl) {
  await api(`/projects/${props.id}/crack`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ file_id: item.file_id, wordlists: wl ? [wl] : null }),
  })
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
  return String(text || '').split('\n').filter((l) => l.startsWith('# ')).map((l) => l.slice(2))
}

// --- ASCII tree (box-drawing) ---
function childrenMap(nodes) {
  const m = {}
  for (const n of nodes) { (m[n.parent_id ?? 0] ||= []).push(n) }
  for (const k in m) m[k].sort((a, b) => a.order_index - b.order_index)
  return m
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
  report.value = { open: true, text: 'Building report…', busy: true }
  const P = project.value
  const L = []
  L.push(`# StegSuite report — ${P.name}`)
  L.push('')
  L.push(`- **Stato:** ${P.status}  ·  **Modalità:** ${P.mode}  ·  **File:** ${P.files}  ·  **Data:** ${fmtDate(P.created_at)}`)
  L.push('')
  L.push('## Findings')
  if (flags.value.length) {
    L.push('### Flag'); L.push('| Flag | Origine |'); L.push('|---|---|')
    for (const f of flags.value) L.push(`| \`${f.value}\` | ${f.source} |`)
  } else L.push('_Nessuna flag._')
  if (passwords.value.length) {
    L.push(''); L.push('### Password'); L.push('| Password | Origine |'); L.push('|---|---|')
    for (const p of passwords.value) L.push(`| \`${p.value}\` | ${p.source} |`)
  }
  if (notes.value.length) {
    L.push(''); L.push('### Note / bloccati'); L.push('| Nota | Tool |'); L.push('|---|---|')
    for (const n of notes.value) L.push(`| ${n.value} | ${n.source} |`)
  }
  L.push(''); L.push('## Percorso della flag')
  L.push('```')
  L.push(routeNodes().length ? asciiRouteTree() : '(nessuna flag trovata)')
  L.push('```')
  const rel = relevantRuns.value
  L.push(''); L.push(`## Passaggi rilevanti (${rel.length})`)
  if (rel.length) {
    L.push('| File | Tool | Stato | Sintesi |')
    L.push('|---|---|---|---|')
    for (const r of rel) {
      const f = treeById.value[r.file_id]
      L.push(`| ${f ? f.name : '?'} | ${r.tool} | ${r.status} | ${(r.summary || '').replace(/\|/g, '\\|')} |`)
    }
  } else L.push('_Nessun passaggio rilevante._')
  const routeFiles = routeNodes().filter((n) => n.parent_id != null)
  L.push(''); L.push(`## File sul percorso (${routeFiles.length})`)
  if (routeFiles.length) {
    L.push('| File | Dim | Prodotto da | Scarica |')
    L.push('|---|---|---|---|')
    for (const n of routeFiles) L.push(`| ${n.name} | ${fmtSize(n.size)} | ${originTool(n)} | [apri](${fileUrl(n)}) |`)
  } else L.push('_Nessun file intermedio._')
  L.push(''); L.push('## Comandi')
  let any = false
  for (const r of rel) {
    const o = outputs.value[r.id] != null ? outputs.value[r.id] : await out(r.id)
    const cmds = commandsOf(o)
    if (cmds.length) {
      any = true
      L.push('```')
      L.push(`# ${(treeById.value[r.file_id] || {}).name} — ${r.tool}`)
      for (const c of cmds) L.push(c)
      L.push('```')
    }
  }
  if (!any) L.push('_Nessun comando registrato._')
  const noise = tree.value.length - routeNodes().length
  L.push('')
  L.push(`> Analizzati ${tree.value.length} file e ${runs.value.length} tool; qui sono mostrati solo i passaggi che portano alla flag. Gli altri ${noise} file sono esplorabili nella GUI.`)
  report.value = { open: true, text: L.join('\n'), busy: false }
}
function copyReport() { navigator.clipboard?.writeText(report.value.text) }
function downloadReport() {
  const blob = new Blob([report.value.text], { type: 'text/markdown' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `stegsuite-report-${props.id}.md`
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
watch(() => props.id, () => { selected.value = null; outputs.value = {}; expanded.value = {}; log.value = []; load() })
onMounted(() => { load(); connect() })
onBeforeUnmount(() => { try { ws && ws.close() } catch {} })
</script>

<template>
  <div class="flex h-full flex-col">
    <!-- action bar -->
    <div class="flex flex-wrap items-center gap-3 border-b border-edge px-4 py-2">
      <button @click="router.push('/')" class="text-slate-400 hover:text-slate-200"><Icon name="chevronR" class="rotate-180" /></button>
      <span class="font-semibold">{{ project?.name }}</span>
      <span class="rounded px-2 py-0.5 text-xs" :class="STATUS_COLOR[project?.status]">{{ project?.status }}</span>
      <span class="text-xs text-slate-500">mode {{ project?.mode }} · {{ project?.files }} file · {{ fmtDate(project?.created_at) }}</span>
      <div class="ml-auto flex items-center gap-2">
        <button @click="action('start')" class="flex items-center gap-1 rounded bg-acc px-3 py-1 text-xs font-semibold text-white"><Icon name="play" :size="13" />Start</button>
        <button @click="action('pause')" class="rounded border border-edge px-3 py-1 text-xs"><Icon name="pause" :size="13" /></button>
        <button @click="action('resume')" class="rounded border border-edge px-3 py-1 text-xs"><Icon name="play" :size="13" /></button>
        <button @click="action('cancel')" class="rounded border border-edge px-3 py-1 text-xs"><Icon name="close" :size="13" /></button>
        <button @click="load" class="rounded border border-edge px-3 py-1 text-xs"><Icon name="refresh" :size="13" /></button>
        <button @click="openReport" class="flex items-center gap-1 rounded border border-edge px-3 py-1 text-xs hover:bg-panel"><Icon name="report" :size="13" />Report</button>
        <button @click="del" class="rounded border border-edge px-3 py-1 text-xs hover:bg-red-500/20"><Icon name="trash" :size="13" /></button>
      </div>
    </div>
    <p v-if="err" class="bg-red-500/10 px-4 py-1 text-xs text-red-300">{{ err }}</p>

    <div class="grid min-h-0 flex-1 grid-cols-[260px_1fr_340px] gap-0">
      <!-- file tree -->
      <div class="min-h-0 overflow-auto border-r border-edge p-2">
        <div class="mb-1 px-1 text-xs font-semibold uppercase text-slate-500">File ({{ tree.length }})</div>
        <div v-if="flags.length" class="mb-1 flex flex-wrap items-center gap-x-2 px-1 text-[10px]">
          <span class="text-emerald-400">● percorso flag</span>
          <span class="text-slate-100">● adiacente</span>
          <span class="text-slate-500">● via morta</span>
        </div>
        <div v-for="n in visibleTree" :key="n._gid || n.id"
             @click="n._group ? toggleNode(n) : (selected = n.id)"
             class="flex cursor-pointer items-center gap-1 rounded px-1 py-0.5 text-xs hover:bg-panel"
             :class="!n._group && selected === n.id ? 'bg-acc/20' : ''">
          <span :style="{ paddingLeft: (n._depth * 12) + 'px' }" class="flex min-w-0 items-center gap-1">
            <button v-if="n._kids" class="shrink-0 text-slate-500 hover:text-slate-200" @click.stop="toggleNode(n)">
              <Icon :name="collapsed.has(n._gid || n.id) ? 'chevronR' : 'chevronD'" :size="13" />
            </button>
            <span v-else class="w-[13px] shrink-0"></span>
            <Icon :name="n._group ? 'folder' : (lockedIds.has(n.id) ? 'lock' : 'file')" :size="13" class="shrink-0 text-slate-500" />
            <span class="truncate" :class="n._group ? groupColor(n) : nodeColor(n)" :title="n._group ? n.name : n.origin">{{ n._group ? n.name + ' (' + n._kids + ')' : n.name }}</span>
            <span v-if="!n._group" class="shrink-0 text-slate-600">{{ fmtSize(n.size) }}</span>
            <Icon v-if="!n._group && flags.some((f) => f.file_id === n.id)" name="flag" :size="12" class="shrink-0 text-emerald-400" />
          </span>
        </div>
      </div>

      <!-- detail -->
      <div class="flex min-h-0 flex-col">
        <div class="flex items-center gap-1 border-b border-edge px-2 py-1 text-xs">
          <button v-for="t in ['overview','estratti','preview']" :key="t" @click="tab = t"
                  class="rounded px-3 py-1" :class="tab === t ? 'bg-panel text-slate-100' : 'text-slate-400'">{{ t }}</button>
          <span class="ml-2 truncate text-slate-500">{{ selectedNode?.name }}</span>
        </div>
        <div class="min-h-0 flex-1 overflow-auto p-3">
          <template v-if="tab === 'overview'">
            <div v-if="!selectedRuns.length" class="text-sm text-slate-500">Nessun tool eseguito su questo file (ancora).</div>
            <div v-for="r in selectedRuns" :key="r.id" class="mb-2 rounded border border-edge bg-panel/40">
              <div class="flex cursor-pointer items-center gap-2 px-3 py-1.5 hover:bg-panel" @click="toggle(r.id)">
                <Icon :name="expanded[r.id] ? 'chevronD' : 'chevronR'" :size="14" class="text-slate-500" />
                <b class="text-sm">{{ r.tool }}</b>
                <span class="rounded bg-ink px-1.5 text-[10px]" :class="r.status==='done'?'text-emerald-400':r.status==='needs_password'?'text-amber-400':r.status==='skipped'?'text-slate-400':'text-red-400'">{{ r.status }}</span>
                <span v-if="r.needs_password" class="text-[10px] text-amber-400">password</span>
                <span class="truncate text-xs text-slate-500">{{ r.summary }}</span>
                <span class="ml-auto text-[10px] text-slate-600">{{ (r.artifacts||[]).length }} artefatti</span>
              </div>
              <div v-if="(r.artifacts||[]).length" class="flex flex-wrap gap-2 border-t border-edge p-2">
                <template v-for="a in r.artifacts" :key="a.id">
                  <img v-if="IMG.test(a.name)" :src="artUrl(a)" class="h-24 cursor-zoom-in rounded border border-edge bg-ink" :title="a.name" @click="lightbox = artUrl(a)" @error="(e) => (e.target.style.display = 'none')" />
                  <a v-else :href="artUrl(a)" class="flex items-center gap-1 rounded border border-edge px-2 py-1 text-[11px] hover:bg-ink" download><Icon name="download" :size="12" />{{ a.name }}</a>
                </template>
              </div>
              <pre v-if="expanded[r.id] && outputs[r.id] != null" class="ansi max-h-80 overflow-auto border-t border-edge bg-ink p-2" v-html="ansiToHtml(outputs[r.id])"></pre>
            </div>
          </template>

          <template v-else-if="tab === 'estratti'">
            <div v-if="!childrenOf(selected).length" class="text-sm text-slate-500">Nessun file estratto da questo nodo.</div>
            <div v-for="c in childrenOf(selected)" :key="c.id" @click="selected = c.id"
                 class="flex cursor-pointer items-center gap-1 rounded px-2 py-1 text-xs hover:bg-panel">
              <Icon name="file" :size="13" class="text-slate-500" /> {{ c.name }}
              <span class="text-slate-500">{{ fmtSize(c.size) }} · {{ originTool(c) }}</span>
            </div>
          </template>

          <template v-else>
            <div v-if="!selectedNode" class="text-slate-500">Seleziona un file.</div>
            <div v-else>
              <div v-if="IMG.test(selectedNode.name) && !previewErr">
                <img :src="fileUrl(selectedNode)" class="max-h-[60vh] cursor-zoom-in rounded border border-edge" @click="lightbox = fileUrl(selectedNode)" @error="previewErr = true" />
              </div>
              <audio v-else-if="AUD.test(selectedNode.name)" :src="fileUrl(selectedNode)" controls class="w-full" />
              <video v-else-if="VID.test(selectedNode.name)" :src="fileUrl(selectedNode)" controls class="max-h-[60vh] w-full rounded" />
              <pre v-else-if="TXT.test(selectedNode.name)" class="out max-h-[60vh] overflow-auto rounded border border-edge p-2">{{ outputs['file'+selectedNode.id] }}</pre>
              <div v-else class="text-sm text-slate-400">
                <a :href="fileUrl(selectedNode)" class="inline-flex items-center gap-1 text-indigo-300" download><Icon name="download" :size="14" />{{ selectedNode.name }}</a>
                <div class="mt-2 text-xs text-slate-500">{{ selectedNode.mime }} · {{ fmtSize(selectedNode.size) }}</div>
              </div>
            </div>
          </template>
        </div>
      </div>

      <!-- right -->
      <div class="flex min-h-0 flex-col border-l border-edge">
        <div class="max-h-[45%] overflow-auto p-3">
          <div class="mb-1 flex items-center gap-1 text-xs font-semibold uppercase text-slate-500"><Icon name="flag" :size="13" />Flag ({{ flags.length }})</div>
          <div v-for="f in flags" :key="f.id" class="mb-1 break-all text-xs text-emerald-300">{{ f.value }}
            <span class="text-slate-500">— {{ f.source }}</span></div>
          <div class="mb-1 mt-3 flex items-center gap-1 text-xs font-semibold uppercase text-slate-500"><Icon name="key" :size="13" />Password ({{ passwords.length }})</div>
          <div v-for="p in passwords" :key="p.id" class="text-xs text-red-300">{{ p.value }}
            <span class="text-slate-500">— {{ p.source }}</span></div>
          <div class="mb-1 mt-3 flex items-center gap-1 text-xs font-semibold uppercase text-slate-500"><Icon name="lock" :size="13" />Bloccati ({{ locked.length }})</div>
          <div v-for="l in locked" :key="l.file_id" class="mb-2 rounded border border-edge p-2">
            <div class="truncate text-xs">{{ l.name }} <span class="text-slate-500">({{ l.kind }})</span></div>
            <div class="mt-1 flex gap-1">
              <select v-model="l._wl" class="w-full rounded border border-edge bg-ink px-1 py-0.5 text-[11px]">
                <option value="">tutte</option>
                <option v-for="w in wordlists" :key="w.name" :value="w.name">{{ w.name }}</option>
              </select>
              <button @click="crack(l, l._wl)" class="rounded bg-acc px-2 text-[11px] font-semibold text-white">Crack</button>
            </div>
          </div>
        </div>
        <div class="border-t border-edge p-3">
          <div class="mb-1 flex items-center gap-1 text-xs font-semibold uppercase text-slate-500"><Icon name="link" :size="13" />Percorso flag</div>
          <pre class="max-h-44 overflow-auto whitespace-pre text-[11px] leading-5 text-slate-300">{{ routeTreeText || '(nessuna flag)' }}</pre>
        </div>
        <div class="min-h-0 flex-1 overflow-auto border-t border-edge bg-ink p-2">
          <div class="mb-1 flex items-center gap-1 text-xs font-semibold uppercase text-slate-500"><Icon name="terminal" :size="13" />Live log</div>
          <div v-for="(m, i) in log" :key="i" class="text-[11px]" :class="m.level === 'warn' ? 'text-amber-400' : 'text-slate-400'">
            <span class="text-slate-600">{{ m.type }}</span>
            <span v-if="m.message"> {{ m.message }}</span>
            <span v-else-if="m.type === 'file'"> · {{ m.name }}</span>
            <span v-else-if="m.type === 'tool'"> · {{ m.name }} → {{ m.tool }} ({{ m.status }})</span>
            <span v-else-if="m.type === 'crack'"> · {{ m.status }} <span v-if="m.password">→ {{ m.password }}</span></span>
          </div>
        </div>
      </div>
    </div>

    <!-- terminal -->
    <div class="border-t border-edge">
      <div class="flex items-center gap-2 bg-panel px-3 py-1 text-xs">
        <button class="flex items-center gap-1" @click="showTerm = !showTerm"><Icon :name="showTerm ? 'chevronD' : 'chevronR'" :size="13" />Terminale (bash, cwd = progetto)</button>
      </div>
      <div v-show="showTerm" class="h-56"><Terminal :pid="props.id" /></div>
    </div>

    <!-- lightbox -->
    <div v-if="lightbox" class="fixed inset-0 z-40 flex items-center justify-center bg-black/80" @click="lightbox = null">
      <img :src="lightbox" class="max-h-[92vh] max-w-[94vw] rounded border border-edge" />
    </div>

    <!-- report modal -->
    <div v-if="report.open" class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6" @click.self="report.open = false">
      <div class="flex max-h-[88vh] w-[980px] flex-col rounded-xl border border-edge bg-panel">
        <div class="flex items-center gap-2 border-b border-edge px-4 py-2">
          <Icon name="report" :size="16" /><b>Report</b>
          <button @click="copyReport" class="ml-auto flex items-center gap-1 rounded border border-edge px-2 py-0.5 text-xs"><Icon name="copy" :size="12" />Copia</button>
          <button @click="downloadReport" class="flex items-center gap-1 rounded border border-edge px-2 py-0.5 text-xs"><Icon name="download" :size="12" />.md</button>
          <button @click="report.open = false" class="rounded border border-edge px-2 py-0.5 text-xs"><Icon name="close" :size="12" /></button>
        </div>
        <div class="md min-h-0 flex-1 overflow-auto p-5" v-html="mdToHtml(report.text)"></div>
      </div>
    </div>
  </div>
</template>

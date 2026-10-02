<script setup>
import { ref, computed, onMounted, onBeforeUnmount, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api, wsUrl, fmtSize, fmtDate, STATUS_COLOR } from '../api'
import Terminal from '../components/Terminal.vue'

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
const err = ref('')
let ws = null
let refreshTimer = null

const IMG = /\.(png|jpe?g|gif|bmp|webp|tiff?)$/i
const AUD = /\.(wav|mp3|flac|ogg|m4a|aac|au)$/i
const VID = /\.(mp4|mkv|webm|avi|mov)$/i
const TXT = /\.(txt|md|json|xml|csv|log|strings|out)$/i

const tree = computed(() => (project.value?.tree || []).slice().sort((a, b) => a.order_index - b.order_index))
const runsByFile = computed(() => {
  const m = {}
  for (const r of runs.value) (m[r.file_id] ||= []).push(r)
  return m
})
const lockedIds = computed(() => new Set(locked.value.map((l) => l.file_id)))
const selectedNode = computed(() => tree.value.find((n) => n.id === selected.value) || null)
const childrenOf = (id) => tree.value.filter((n) => n.parent_id === id)
const selectedRuns = computed(() => runsByFile.value[selected.value] || [])
const runOf = (tool) => selectedRuns.value.find((r) => r.tool === tool)
const flags = computed(() => findings.value.filter((f) => f.kind === 'flag'))
const passwords = computed(() => findings.value.filter((f) => f.kind === 'password'))

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
  try {
    const t = await api(`/projects/${props.id}/files/${runOf1(rid)}/runs/${rid}`)
    outputs.value[rid] = t
  } catch (e) { outputs.value[rid] = String(e) }
}
function runOf1(rid) { return (runs.value.find((r) => r.id === rid) || {}).file_id }
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
watch(selected, (id) => { if (id != null) loadPreview(id) })
watch(() => props.id, () => { selected.value = null; outputs.value = {}; log.value = []; load() })
onMounted(() => { load(); connect() })
onBeforeUnmount(() => { try { ws && ws.close() } catch {} })
</script>

<template>
  <div class="flex h-full flex-col">
    <!-- action bar -->
    <div class="flex flex-wrap items-center gap-3 border-b border-edge px-4 py-2">
      <button @click="router.push('/')" class="text-slate-400 hover:text-slate-200">←</button>
      <span class="font-semibold">{{ project?.name }}</span>
      <span class="rounded px-2 py-0.5 text-xs" :class="STATUS_COLOR[project?.status]">
        {{ project?.status }}
      </span>
      <span class="text-xs text-slate-500">mode {{ project?.mode }} · {{ project?.files }} file · {{ fmtDate(project?.created_at) }}</span>
      <div class="ml-auto flex gap-2">
        <button @click="action('start')" class="rounded bg-acc px-3 py-1 text-xs font-semibold text-white">Start</button>
        <button @click="action('pause')" class="rounded border border-edge px-3 py-1 text-xs">Pause</button>
        <button @click="action('resume')" class="rounded border border-edge px-3 py-1 text-xs">Resume</button>
        <button @click="action('cancel')" class="rounded border border-edge px-3 py-1 text-xs">Cancel</button>
        <button @click="load" class="rounded border border-edge px-3 py-1 text-xs">↻</button>
        <button @click="del" class="rounded border border-edge px-3 py-1 text-xs hover:bg-red-500/20">Elimina</button>
      </div>
    </div>
    <p v-if="err" class="bg-red-500/10 px-4 py-1 text-xs text-red-300">{{ err }}</p>

    <div class="grid min-h-0 flex-1 grid-cols-[260px_1fr_320px] gap-0">
      <!-- file tree -->
      <div class="min-h-0 overflow-auto border-r border-edge p-2">
        <div class="mb-1 px-1 text-xs font-semibold uppercase text-slate-500">File ({{ tree.length }})</div>
        <div v-for="n in tree" :key="n.id" @click="selected = n.id"
             class="cursor-pointer truncate rounded px-2 py-1 text-xs hover:bg-panel"
             :class="selected === n.id ? 'bg-acc/20' : ''">
          <span :style="{ paddingLeft: (n.depth * 10) + 'px' }">
            <span v-if="lockedIds.has(n.id)" title="password richiesta">🔒</span>
            {{ n.name }}
            <span class="text-slate-500">{{ fmtSize(n.size) }}</span>
          </span>
        </div>
      </div>

      <!-- detail -->
      <div class="flex min-h-0 flex-col">
        <div class="flex gap-1 border-b border-edge px-2 py-1 text-xs">
          <button v-for="t in ['overview','estratti','preview']" :key="t" @click="tab = t"
                  class="rounded px-3 py-1" :class="tab === t ? 'bg-panel text-slate-100' : 'text-slate-400'">{{ t }}</button>
          <span class="ml-auto py-1 text-slate-500">{{ selectedNode?.name }}</span>
        </div>
        <div class="min-h-0 flex-1 overflow-auto p-3">
          <!-- Overview: tool runs -->
          <template v-if="tab === 'overview'">
            <div v-if="!selectedRuns.length" class="text-sm text-slate-500">Nessun tool eseguito su questo file (ancora).</div>
            <div v-for="r in selectedRuns" :key="r.id" class="mb-3 rounded border border-edge bg-panel/40">
              <div class="flex items-center gap-2 border-b border-edge px-3 py-1.5">
                <b class="text-sm">{{ r.tool }}</b>
                <span class="rounded bg-ink px-1.5 text-[10px]" :class="r.status==='done'?'text-emerald-400':r.status==='needs_password'?'text-amber-400':'text-red-400'">{{ r.status }}</span>
                <span v-if="r.needs_password" class="text-[10px] text-amber-400">password</span>
                <span class="truncate text-xs text-slate-500">{{ r.summary }}</span>
                <button class="ml-auto text-xs text-slate-400 hover:text-slate-200" @click="out(r.id)">output</button>
              </div>
              <div v-if="r.artifacts && r.artifacts.length" class="flex flex-wrap gap-2 p-2">
                <template v-for="a in r.artifacts" :key="a.id">
                  <img v-if="IMG.test(a.name)" :src="artUrl(a)" class="h-20 rounded border border-edge" :title="a.name" />
                  <a v-else :href="artUrl(a)" class="rounded border border-edge px-2 py-1 text-[11px] hover:bg-ink" download>{{ a.name }}</a>
                </template>
              </div>
              <pre v-if="outputs[r.id] != null" class="out max-h-72 overflow-auto border-t border-edge p-2 text-slate-300 ansi">{{ outputs[r.id] }}</pre>
            </div>
          </template>

          <!-- Estratti -->
          <template v-else-if="tab === 'estratti'">
            <div v-if="!childrenOf(selected).length" class="text-sm text-slate-500">Nessun file estratto da questo nodo.</div>
            <div v-for="c in childrenOf(selected)" :key="c.id" @click="selected = c.id"
                 class="cursor-pointer rounded px-2 py-1 text-xs hover:bg-panel">
              📄 {{ c.name }} <span class="text-slate-500">{{ fmtSize(c.size) }} · {{ c.origin }}</span>
            </div>
          </template>

          <!-- Preview -->
          <template v-else>
            <div v-if="!selectedNode" class="text-slate-500">Seleziona un file.</div>
            <div v-else>
              <img v-if="IMG.test(selectedNode.name)" :src="fileUrl(selectedNode)" class="max-h-[60vh] rounded border border-edge" />
              <audio v-else-if="AUD.test(selectedNode.name)" :src="fileUrl(selectedNode)" controls class="w-full" />
              <video v-else-if="VID.test(selectedNode.name)" :src="fileUrl(selectedNode)" controls class="max-h-[60vh] w-full rounded" />
              <pre v-else-if="TXT.test(selectedNode.name)" class="out max-h-[60vh] overflow-auto rounded border border-edge p-2">{{ outputs['file'+selectedNode.id] }}</pre>
              <div v-else class="text-sm text-slate-400">
                <a :href="fileUrl(selectedNode)" class="text-indigo-300" download>Scarica {{ selectedNode.name }}</a>
                <div class="mt-2 text-xs text-slate-500">{{ selectedNode.mime }} · {{ fmtSize(selectedNode.size) }}</div>
              </div>
            </div>
          </template>
        </div>
      </div>

      <!-- right: findings / locked / log -->
      <div class="flex min-h-0 flex-col border-l border-edge">
        <div class="max-h-[45%] overflow-auto p-3">
          <div class="mb-1 text-xs font-semibold uppercase text-slate-500">🚩 Flag ({{ flags.length }})</div>
          <div v-for="f in flags" :key="f.id" class="mb-1 break-all text-xs text-emerald-300">{{ f.value }}
            <span class="text-slate-500">— {{ f.source }}</span></div>
          <div class="mb-1 mt-3 text-xs font-semibold uppercase text-slate-500">🔑 Password ({{ passwords.length }})</div>
          <div v-for="p in passwords" :key="p.id" class="text-xs text-red-300">{{ p.value }}
            <span class="text-slate-500">— {{ p.source }}</span></div>

          <div class="mb-1 mt-3 text-xs font-semibold uppercase text-slate-500">🔒 Bloccati ({{ locked.length }})</div>
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
        <div class="min-h-0 flex-1 overflow-auto border-t border-edge bg-ink p-2">
          <div class="mb-1 text-xs font-semibold uppercase text-slate-500">Live log</div>
          <div v-for="(m, i) in log" :key="i" class="text-[11px]" :class="m.level === 'warn' ? 'text-amber-400' : 'text-slate-400'">
            <span class="text-slate-600">{{ m.type }}</span>
            <span v-if="m.message"> {{ m.message }}</span>
            <span v-else-if="m.type === 'file'"> ▶ {{ m.name }}</span>
            <span v-else-if="m.type === 'tool'"> · {{ m.name }} → {{ m.tool }} ({{ m.status }})</span>
            <span v-else-if="m.type === 'crack'"> · {{ m.status }} <span v-if="m.password">🔑 {{ m.password }}</span></span>
          </div>
        </div>
      </div>
    </div>

    <!-- terminal -->
    <div class="border-t border-edge">
      <div class="flex items-center gap-2 bg-panel px-3 py-1 text-xs">
        <button @click="showTerm = !showTerm">{{ showTerm ? '▾' : '▸' }} Terminale (cwd = progetto)</button>
      </div>
      <div v-show="showTerm" class="h-56"><Terminal :pid="props.id" /></div>
    </div>
  </div>
</template>

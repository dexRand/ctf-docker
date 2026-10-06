<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api, fmtDate, STATUS_COLOR } from '../api'
import { t } from '../i18n'
import Icon from '../components/Icon.vue'

const router = useRouter()
const STATS_WINDOW = 20
const files = ref([])
const name = ref('')
const mode = ref('check')
const busy = ref(false)
const drag = ref(false)
const projects = ref([])
const err = ref('')
const echo = ref('')
const clearing = ref(false)
const perProject = ref({})
const stats = ref({ projects: 0, files: 0, flags: 0, passwords: 0, runs: 0, perStatus: {}, perMode: {}, topTools: [], active: 0, solved: 0, done: 0, blocked: 0, solveRate: 0 })

const MODES = [
  { id: 'auto', flag: '--auto', color: 'text-acc' },
  { id: 'check', flag: '--check', color: 'text-warn' },
]

const STATUS_ORDER = ['queued', 'running', 'done', 'paused', 'error', 'created', 'cancelled']
const STATUS_BAR = {
  queued: '#f5c542', running: '#f5c542', done: '#45e08c', paused: '#5fd0f2',
  error: '#ff6166', created: '#384049', cancelled: '#384049',
}

const statCells = computed(() => [
  { label: t('home.stat_projects'), value: stats.value.projects, color: 'text-fglite' },
  { label: t('home.stat_active'), value: stats.value.active, color: 'text-warn' },
  { label: t('home.stat_solved'), value: stats.value.solved, color: 'text-acc' },
  { label: t('home.stat_flags'), value: stats.value.flags, color: 'text-acc' },
  { label: t('home.stat_blocked'), value: stats.value.blocked, color: 'text-warn' },
])

const blockedProjects = computed(() =>
  Object.values(perProject.value)
    .filter((d) => d.lockedN > 0)
    .sort((a, b) => b.lockedN - a.lockedN)
    .slice(0, 6)
)

const statusRows = computed(() => {
  const rows = STATUS_ORDER
    .filter((s) => stats.value.perStatus[s])
    .map((s) => ({ status: s, count: stats.value.perStatus[s] }))
  const total = Math.max(1, stats.value.projects)
  return rows.map((r) => ({
    ...r,
    pct: Math.max(4, Math.round((r.count / total) * 100)),
    bar: STATUS_BAR[r.status],
    text: STATUS_BAR[r.status] === '#45e08c' ? 'text-acc'
      : STATUS_BAR[r.status] === '#f5c542' ? 'text-warn'
      : STATUS_BAR[r.status] === '#5fd0f2' ? 'text-info'
      : STATUS_BAR[r.status] === '#ff6166' ? 'text-danger' : 'text-dim',
  }))
})

const modeRows = computed(() => [
  { mode: 'auto', count: stats.value.perMode.auto || 0 },
  { mode: 'check', count: stats.value.perMode.check || 0 },
])
const topTools = computed(() => stats.value.topTools)

async function loadStats() {
  const all = projects.value
  const list = all.slice(0, STATS_WINDOW)
  let flags = 0, passwords = 0, runs = 0
  const perStatus = {}, perMode = {}, toolCount = {}
  const detail = {}
  for (const p of all) {
    perStatus[p.status] = (perStatus[p.status] || 0) + 1
    perMode[p.mode] = (perMode[p.mode] || 0) + 1
  }
  for (const p of list) {
    let fd = [], rs = []
    try {
      ;[fd, rs] = await Promise.all([
        api(`/projects/${p.id}/findings`),
        api(`/projects/${p.id}/runs`),
      ])
    } catch { /* keep zeros for this project */ }
    const flagsN = (fd || []).filter((f) => f.kind === 'flag').length
    const cracked = new Set((fd || []).filter((f) => f.kind === 'password').map((f) => f.file_id))
    const lockedN = new Set((rs || []).filter((r) => r.needs_password && !cracked.has(r.file_id)).map((r) => r.file_id)).size
    flags += flagsN
    passwords += (fd || []).filter((f) => f.kind === 'password').length
    runs += (rs || []).length
    for (const r of rs || []) toolCount[r.tool] = (toolCount[r.tool] || 0) + 1
    detail[p.id] = { id: p.id, name: p.name, status: p.status, flagsN, lockedN }
  }
  const done = Object.values(detail).filter((d) => d.status === 'done').length
  const solved = Object.values(detail).filter((d) => d.flagsN > 0).length
  const blocked = Object.values(detail).filter((d) => d.lockedN > 0).length
  perProject.value = detail
  stats.value = {
    projects: all.length,
    files: all.reduce((s, p) => s + (p.files || 0), 0),
    flags, passwords, runs,
    active: (perStatus.running || 0) + (perStatus.queued || 0),
    solved, done, blocked,
    solveRate: done ? Math.round((solved / done) * 100) : 0,
    perStatus, perMode,
    topTools: Object.entries(toolCount).sort((a, b) => b[1] - a[1]).slice(0, 6),
  }
}

async function load() {
  try {
    projects.value = await api('/projects')
    await loadStats()
  } catch (e) { err.value = String(e) }
}
onMounted(load)

function onDrop(e) { drag.value = false; files.value = Array.from(e.dataTransfer.files || []) }
function onPick(e) { files.value = Array.from(e.target.files || []) }

const totalBytes = computed(() => files.value.reduce((s, f) => s + f.size, 0))

async function start() {
  if (!files.value.length) { err.value = t('home.select_file'); return }
  busy.value = true; err.value = ''
  const cmd = `stegsuite --${mode.value} ${files.value.map((f) => f.name).join(' ')}`
  echo.value = `$ ${cmd}`
  try {
    const fd = new FormData()
    fd.append('mode', mode.value)
    if (name.value) fd.append('name', name.value)
    for (const f of files.value) fd.append('files', f)
    const p = await api('/projects', { method: 'POST', body: fd })
    await api(`/projects/${p.id}/start`, { method: 'POST' })
    echo.value += `\n$ ... ${t('home.redirect')}`
    router.push(`/p/${p.id}`)
  } catch (e) { err.value = String(e) } finally { busy.value = false }
}

function fmtKb(n) {
  if (n >= 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + 'M'
  if (n >= 1024) return (n / 1024).toFixed(1) + 'K'
  return n + 'B'
}

async function del(id, e) {
  e.stopPropagation()
  if (!confirm(t('home.del_confirm'))) return
  await api(`/projects/${id}`, { method: 'DELETE' })
  load()
}

async function clearAll() {
  if (!projects.value.length) return
  if (!confirm(t('home.clear_confirm_1', { n: projects.value.length }))) return
  if (!confirm(t('home.clear_confirm_2'))) return
  clearing.value = true
  try { await api('/projects', { method: 'DELETE' }); await load() }
  catch (e) { err.value = String(e) } finally { clearing.value = false }
}

function open(id) { router.push(`/p/${id}`) }
</script>

<template>
  <div class="mx-auto max-w-5xl p-6 font-mono">
    <!-- hero / command console -->
    <section class="animate-fadeUp rounded border border-edge bg-panel shadow">
      <div class="flex items-center gap-2 border-b border-edge bg-panel2 px-3 py-1.5 text-[11px] text-dim">
        <span class="grid h-4 w-5 place-items-center rounded border border-acc/70 bg-acc/10 text-[9px] font-bold text-acc" aria-hidden="true">$_</span>
        <span class="font-bold text-fglite">{{ t('home.title_bar') }}</span>
        <span class="ml-auto text-acc">stegsuite -h</span>
      </div>

      <div class="p-4">
        <p class="text-xs text-dim">
          <span class="prompt">stegsuite --help</span> {{ t('home.help') }}
        </p>

        <!-- drop zone -->
        <div
          class="mt-3 cursor-pointer border border-dashed border-edge2 bg-ink/60 px-4 py-6 text-center transition"
          :class="drag ? 'border-acc text-acc' : 'hover:border-acc/70'"
          role="button" tabindex="0"
          @dragover.prevent="drag = true" @dragleave.prevent="drag = false" @drop.prevent="onDrop"
          @keydown.enter="() => {}"
          @click="$refs.filepicker && $refs.filepicker.click()"
        >
          <div class="flex items-center justify-center gap-2 text-sm text-dim">
            <Icon name="terminal" :size="14" class="text-acc" />
            <span>$ stegsuite --analyze</span>
            <span v-if="!files.length" class="animate-blink text-acc">▋</span>
          </div>
          <div class="mt-1 text-xs text-dim">
            {{ t('home.drop_hint') }}
            <span class="cursor-pointer text-acc underline underline-offset-2">{{ t('home.drop_browse') }}</span>
            <input ref="filepicker" type="file" multiple class="hidden" @change="onPick" />
          </div>
          <table v-if="files.length" class="mx-auto mt-3 min-w-[260px] text-left text-[11px] text-fglite">
            <tbody>
              <tr v-for="f in files" :key="f.name">
                <td class="pr-3 text-acc">[+]</td>
                <td class="max-w-[36ch] truncate pr-6">{{ f.name }}</td>
                <td class="text-right text-dim">{{ fmtKb(f.size) }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- modes + name + run -->
        <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
          <div v-for="m in MODES" :key="m.id" class="flex items-start gap-2 text-xs">
            <button type="button" class="font-semibold" :class="mode === m.id ? m.color : 'text-dim hover:text-fglite'"
                    @click="mode = m.id">
              {{ mode === m.id ? '> ' : '  ' }}{{ m.flag }}
            </button>
            <p class="max-w-[38ch] text-[11px] leading-4 text-dim">{{ t('home.mode_' + m.id) }}</p>
          </div>
          <input v-model="name" :placeholder="t('home.name_placeholder')"
                 class="min-w-[180px] rounded border border-edge bg-ink px-2.5 py-1.5 text-xs placeholder:text-dim focus:border-acc" />
          <button :disabled="busy || !files.length" @click="start"
                  class="kb kb-acc disabled:opacity-50" :aria-label="t('home.run_analysis')">
            <Icon name="play" :size="12" />{{ busy ? t('home.running') : t('home.run') }}
          </button>
        </div>

        <pre v-if="echo" class="mt-3 whitespace-pre-wrap rounded border border-edge bg-ink px-3 py-2 text-[11px] text-acc">{{ echo }}</pre>
        <p v-if="err" class="mt-2 text-xs text-danger">[!] {{ err }}</p>
      </div>
    </section>

    <!-- analytics strip -->
    <section class="mt-4 animate-fadeUp">
      <div class="flex items-center justify-between pr-1">
        <span class="text-[10px] uppercase tracking-widest text-dim">{{ t('home.recent_analysed', { n: STATS_WINDOW }) }}</span>
        <span v-if="stats.solveRate !== undefined" class="text-[10px] uppercase tracking-widest text-dim">
          {{ t('home.solve_rate', { pct: stats.solveRate }) }} <span class="text-acc">{{ stats.solved }}/{{ stats.done }}</span>
        </span>
      </div>
      <div class="mt-2 grid grid-cols-2 gap-3 md:grid-cols-5">
        <div v-for="c in statCells" :key="c.label" class="rounded border border-edge bg-panel p-3">
          <div class="text-[10px] uppercase tracking-widest text-dim">{{ c.label }}</div>
          <div class="mt-1 text-xl font-bold" :class="c.color">{{ c.value }}</div>
        </div>
      </div>

      <!-- blocked → crack -->
      <section v-if="blockedProjects.length" class="mt-3 rounded border border-warn/40 bg-warn/5">
        <div class="flex items-center gap-2 border-b border-warn/40 bg-warn/10 px-3 py-1.5 text-[11px] font-bold uppercase tracking-widest text-warn">
          <Icon name="lock" :size="12" /> {{ t('home.blocked_title') }}
          <span class="ml-auto">{{ blockedProjects.length }}</span>
        </div>
        <div class="grid gap-2 p-3 sm:grid-cols-2 lg:grid-cols-3">
          <button v-for="b in blockedProjects" :key="b.id" @click="open(b.id)"
                  class="flex items-center gap-2 rounded border border-edge bg-panel px-2.5 py-2 text-left text-[11px] transition hover:border-warn/70">
            <span class="shrink-0 text-warn">▣</span>
            <span class="min-w-0 flex-1 truncate text-fglite">{{ b.name }}</span>
            <span class="shrink-0 text-dim">{{ b.lockedN }}× {{ t('home.blocked_lock') }}</span>
          </button>
        </div>
        <p class="px-3 pb-2 text-[10px] text-dim">{{ t('home.blocked_hint') }}</p>
      </section>

      <div class="mt-3 grid gap-3 lg:grid-cols-2">
        <section class="rounded border border-edge bg-panel">
          <div class="flex items-center gap-2 border-b border-edge bg-panel2 px-3 py-1.5 text-[11px] font-bold uppercase tracking-widest text-dim">
            <Icon name="cpu" :size="12" /> {{ t('home.chart_status') }}
          </div>
          <div class="p-3">
            <p v-if="!stats.projects" class="text-xs text-dim">{{ t('home.no_data') }}</p>
            <div v-for="s in statusRows" :key="s.status" class="mb-2 last:mb-0">
              <div class="flex items-center justify-between text-[11px]">
                <span :class="s.text">{{ s.status }}</span>
                <span class="text-dim">{{ s.count }}</span>
              </div>
              <div class="mt-1 h-1.5 rounded bg-ink">
                <div class="h-1.5 rounded" :style="{ width: s.pct + '%', background: s.bar }"></div>
              </div>
            </div>
          </div>
        </section>

        <section class="rounded border border-edge bg-panel">
          <div class="flex items-center gap-2 border-b border-edge bg-panel2 px-3 py-1.5 text-[11px] font-bold uppercase tracking-widest text-dim">
            <Icon name="hash" :size="12" /> {{ t('home.chart_mode') }}
          </div>
          <div class="p-3">
            <div v-for="m in modeRows" :key="m.mode" class="mb-2 last:mb-0">
              <div class="flex items-center justify-between text-[11px]">
                <span :class="m.mode === 'auto' ? 'text-acc' : 'text-warn'">--{{ m.mode }}</span>
                <span class="text-dim">{{ m.count }}</span>
              </div>
              <div class="mt-1 h-1.5 rounded bg-ink">
                <div class="h-1.5 rounded" :style="{ width: Math.max(4, stats.projects ? Math.round(m.count / stats.projects * 100) : 0) + '%', background: m.mode === 'auto' ? '#45e08c' : '#f5c542' }"></div>
              </div>
            </div>
            <div class="mt-3 flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-dim">
              <Icon name="warn" :size="12" /> {{ t('home.top_tools') }}
            </div>
            <div v-if="topTools.length" class="mt-2 flex flex-wrap gap-1.5">
              <span v-for="[tool, n] in topTools" :key="tool" class="rounded border border-edge bg-panel2 px-2 py-0.5 text-[10px] text-fglite">
                {{ tool }}<span class="ml-1 text-dim">{{ n }}</span>
              </span>
            </div>
            <p v-else class="mt-1 text-[11px] text-dim">{{ t('home.no_data') }}</p>
          </div>
        </section>
      </div>
    </section>

    <!-- history -->
    <section class="mb-2 mt-8 flex items-center gap-3">
      <h2 class="flex items-center gap-2 text-sm font-bold uppercase tracking-widest text-acc">
        <Icon name="history" :size="14" />{{ t('home.history') }} <span class="text-dim">— {{ t('home.projects_count', { n: projects.length }) }}</span>
      </h2>
      <button v-if="projects.length" :disabled="clearing" @click="clearAll"
              class="kb kb-danger ml-auto text-[10px]">
        <Icon name="trash" :size="12" />{{ clearing ? '…' : t('home.clear_history') }}
      </button>
    </section>

    <section class="overflow-hidden rounded border border-edge shadow">
      <div class="flex items-center justify-between border-b border-edge bg-panel2 px-3 py-1 text-[11px] text-dim">
        <span>$ ls -la --human ~/projects</span>
        <span class="text-acc">total {{ projects.length }}</span>
      </div>
      <div class="overflow-auto">
        <table class="w-full text-[12px] leading-relaxed">
          <thead class="bg-panel text-left text-[10px] uppercase tracking-wider text-dim">
            <tr>
              <th class="px-3 py-1.5 font-medium">{{ t('home.col_name') }}</th>
              <th class="px-3 py-1.5 font-medium">{{ t('home.col_status') }}</th>
              <th class="px-3 py-1.5 font-medium">{{ t('home.col_mode') }}</th>
              <th class="px-3 py-1.5 font-medium">{{ t('home.col_files') }}</th>
              <th class="px-3 py-1.5 font-medium">{{ t('home.col_created') }}</th>
              <th class="px-3 py-1.5 text-right font-medium"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in projects" :key="p.id" @click="open(p.id)"
                class="cursor-pointer border-t border-edge/60 hover:bg-acc/5">
              <td class="px-3 py-1.5 text-fg">
                <span v-if="p.status === 'done'" class="mr-2 text-acc">✓</span>
                <span v-else-if="['running','queued'].includes(p.status)" class="mr-2 animate-blink text-warn">*</span>
                <span v-else-if="p.status === 'error'" class="mr-2 text-danger">✗</span>
                <span v-else class="mr-2 text-dim">·</span>
                <span v-if="perProject[p.id]?.lockedN > 0" class="mr-2 text-warn" :title="t('home.blocked_lock')">▣{{ perProject[p.id].lockedN }}</span>
                {{ p.name }}
              </td>
              <td class="px-3 py-1.5" :class="STATUS_COLOR[p.status] || 'text-dim'">{{ p.status }}</td>
              <td class="px-3 py-1.5 text-dim">--{{ p.mode }}</td>
              <td class="px-3 py-1.5 text-dim">{{ p.files }}</td>
              <td class="px-3 py-1.5 text-dim">{{ fmtDate(p.created_at) }}</td>
              <td class="px-3 py-1.5 text-right">
                <button @click="del(p.id, $event)" class="kb text-[10px] px-2"
                        :aria-label="t('home.delete_project')"><Icon name="trash" :size="11" /></button>
              </td>
            </tr>
            <tr v-if="!projects.length"><td colspan="6" class="px-3 py-8 text-center text-dim">
              <span class="text-acc">$</span> {{ t('home.empty') }}
            </td></tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>
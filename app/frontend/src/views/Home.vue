<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api, fmtDate, STATUS_COLOR } from '../api'
import { t } from '../i18n'
import Icon from '../components/Icon.vue'

const router = useRouter()
const files = ref([])
const name = ref('')
const mode = ref('check')
const busy = ref(false)
const drag = ref(false)
const projects = ref([])
const err = ref('')
const echo = ref('')
const clearing = ref(false)

const MODES = [
  { id: 'auto', flag: '--auto', color: 'text-acc' },
  { id: 'check', flag: '--check', color: 'text-warn' },
]

async function load() {
  try { projects.value = await api('/projects') } catch (e) { err.value = String(e) }
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
        <span class="h-2 w-2 rounded-full bg-danger/70"></span>
        <span class="h-2 w-2 rounded-full bg-warn/70"></span>
        <span class="h-2 w-2 rounded-full bg-acc/70"></span>
        <span class="ml-2">nuova-analisi — sh</span>
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
          <table v-if="files.length" class="mx-auto mt-3 min-w-[260px] text-left text-[11px] text-slate-300">
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
            <button type="button" class="font-semibold" :class="mode === m.id ? m.color : 'text-dim hover:text-slate-200'"
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
              <td class="px-3 py-1.5 text-slate-200">
                <span v-if="p.status === 'done'" class="mr-2 text-acc">✓</span>
                <span v-else-if="['running','queued'].includes(p.status)" class="mr-2 animate-blink text-warn">*</span>
                <span v-else-if="p.status === 'error'" class="mr-2 text-danger">✗</span>
                <span v-else class="mr-2 text-dim">·</span>
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
<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api, fmtDate, STATUS_COLOR } from '../api'
import Icon from '../components/Icon.vue'

const router = useRouter()
const files = ref([])
const name = ref('')
const mode = ref('check')
const busy = ref(false)
const drag = ref(false)
const projects = ref([])
const err = ref('')

async function load() {
  try { projects.value = await api('/projects') } catch (e) { err.value = String(e) }
}
onMounted(load)

function onDrop(e) { drag.value = false; files.value = Array.from(e.dataTransfer.files || []) }
function onPick(e) { files.value = Array.from(e.target.files || []) }

async function start() {
  if (!files.value.length) { err.value = 'Seleziona almeno un file.'; return }
  busy.value = true; err.value = ''
  try {
    const fd = new FormData()
    fd.append('mode', mode.value)
    if (name.value) fd.append('name', name.value)
    for (const f of files.value) fd.append('files', f)
    const p = await api('/projects', { method: 'POST', body: fd })
    await api(`/projects/${p.id}/start`, { method: 'POST' })
    router.push(`/p/${p.id}`)
  } catch (e) { err.value = String(e) } finally { busy.value = false }
}

async function del(id, e) {
  e.stopPropagation()
  if (!confirm('Eliminare il progetto e tutti i file?')) return
  await api(`/projects/${id}`, { method: 'DELETE' })
  load()
}

function open(id) { router.push(`/p/${id}`) }
</script>

<template>
  <div class="mx-auto max-w-5xl p-6">
    <div class="rounded-xl border border-edge bg-panel p-5">
      <h1 class="mb-4 text-xl font-semibold">Nuova analisi</h1>
      <div
        class="flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed border-edge p-8 text-center transition"
        :class="drag ? 'border-acc bg-acc/10' : 'hover:border-slate-500'"
        @dragover.prevent="drag = true" @dragleave.prevent="drag = false" @drop.prevent="onDrop">
        <Icon name="upload" :size="34" class="text-slate-400" />
        <div class="mt-2 text-sm text-slate-400">Trascina qui i file (più file insieme) oppure</div>
        <label class="mt-2 cursor-pointer rounded bg-acc px-3 py-1.5 text-sm font-medium text-white">
          Scegli file<input type="file" multiple class="hidden" @change="onPick" />
        </label>
        <ul class="mt-3 text-xs text-slate-400">
          <li v-for="f in files" :key="f.name">{{ f.name }} · {{ (f.size / 1024).toFixed(1) }} KB</li>
        </ul>
      </div>

      <div class="mt-4 flex flex-wrap items-center gap-5">
        <label class="flex items-center gap-2 text-sm">
          <input type="radio" value="auto" v-model="mode" /> <b>Auto</b>
          <span class="text-slate-500">(fa tutto e prova tutte le wordlist)</span>
        </label>
        <label class="flex items-center gap-2 text-sm">
          <input type="radio" value="check" v-model="mode" /> <b>Check</b>
          <span class="text-slate-500">(mi chiede cosa attaccare)</span>
        </label>
        <input v-model="name" placeholder="nome progetto (opzionale)"
               class="rounded border border-edge bg-ink px-3 py-1.5 text-sm" />
        <button :disabled="busy" @click="start"
                class="rounded bg-acc px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">
          {{ busy ? 'Avvio…' : 'Analizza' }}
        </button>
      </div>
      <p v-if="err" class="mt-3 text-sm text-red-400">{{ err }}</p>
    </div>

    <h2 class="mb-2 mt-8 text-sm font-semibold uppercase tracking-wide text-slate-500">History</h2>
    <div class="overflow-hidden rounded-xl border border-edge">
      <table class="w-full text-sm">
        <thead class="bg-panel text-left text-xs uppercase text-slate-500">
          <tr><th class="px-4 py-2">Nome</th><th class="px-4 py-2">Stato</th>
              <th class="px-4 py-2">Modalità</th><th class="px-4 py-2">File</th>
              <th class="px-4 py-2">Creato</th><th class="px-4 py-2"></th></tr>
        </thead>
        <tbody>
          <tr v-for="p in projects" :key="p.id" @click="open(p.id)"
              class="cursor-pointer border-t border-edge hover:bg-panel/60">
            <td class="px-4 py-2">{{ p.name }}</td>
            <td class="px-4 py-2" :class="STATUS_COLOR[p.status] || ''">{{ p.status }}</td>
            <td class="px-4 py-2 text-slate-400">{{ p.mode }}</td>
            <td class="px-4 py-2 text-slate-400">{{ p.files }}</td>
            <td class="px-4 py-2 text-slate-400">{{ fmtDate(p.created_at) }}</td>
            <td class="px-4 py-2 text-right">
              <button @click="del(p.id, $event)" class="inline-flex items-center gap-1 rounded border border-edge px-2 py-1 text-xs hover:bg-red-500/20"><Icon name="trash" :size="12" />Elimina</button>
            </td>
          </tr>
          <tr v-if="!projects.length"><td colspan="6" class="px-4 py-6 text-center text-slate-500">Nessun progetto.</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

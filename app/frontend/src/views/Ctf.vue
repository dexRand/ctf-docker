<script setup>
// One CTF: its challenges (scoreboard), upload a new challenge, autosolve.
import { ref, computed, onMounted, onBeforeUnmount, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api, uploadFile, fmtSize, STATUS_COLOR } from '../api'
import { notify } from '../toast'
import { t } from '../i18n'
import Icon from '../components/Icon.vue'

const props = defineProps({ id: { type: String, required: true } })
const router = useRouter()
const ctf = ref(null)
const err = ref('')
const files = ref([])
const chalName = ref('')
const category = ref('')
const busy = ref(false)
const pct = ref(0)
const fmt = ref('')
let timer = null

const CATEGORIES = ['forensics', 'stego', 'misc', 'crypto', 'rev', 'pwn', 'web', 'osint']
const challenges = computed(() => ctf.value?.challenge_list || [])
const auto = computed(() => ctf.value?.autosolve)
const autoActive = computed(() => !!auto.value?.active)

async function load() {
  try {
    ctf.value = await api(`/ctfs/${props.id}`)
    if (!fmt.value) fmt.value = ctf.value.flag_format
    err.value = ''
  } catch (e) { err.value = String(e) }
  // keep polling while something is moving
  clearTimeout(timer)
  const moving = autoActive.value || challenges.value.some((c) => ['queued', 'running'].includes(c.status))
  timer = setTimeout(load, moving ? 2000 : 15000)
}

async function addChallenge() {
  if (!files.value.length) return
  busy.value = true; pct.value = 0
  try {
    const fd = new FormData()
    fd.append('name', chalName.value || files.value[0].name)
    fd.append('category', category.value)
    fd.append('start', 'true')
    for (const f of files.value) fd.append('files', f)
    await uploadFile(`/ctfs/${props.id}/challenges`, fd, (p) => { pct.value = p })
    notify(t('toast.uploaded', { n: files.value.length }), 'ok')
    files.value = []; chalName.value = ''
    await load()
  } catch (e) { notify(String(e), 'error') } finally { busy.value = false }
}

async function toggleAutosolve() {
  try {
    if (autoActive.value) await api(`/ctfs/${props.id}/autosolve`, { method: 'DELETE' })
    else {
      await api(`/ctfs/${props.id}/autosolve`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ parallel: 2 }),
      })
    }
    await load()
  } catch (e) { notify(String(e), 'error') }
}

async function saveFormat() {
  try {
    await api(`/ctfs/${props.id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ flag_format: fmt.value }),
    })
    notify(t('ctf.save') + ' ✓', 'ok')
    await load()
  } catch (e) { notify(String(e), 'error') }
}

async function setSolved(c, solved) {
  try {
    await api(`/projects/${c.id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ solved, flag: solved ? (c.flag || c.flags[0] || '') : c.flag }),
    })
    await load()
  } catch (e) { notify(String(e), 'error') }
}

async function removeCtf() {
  if (!confirm(t('ctf.delete_confirm'))) return
  try { await api(`/ctfs/${props.id}`, { method: 'DELETE' }); router.push('/') } catch (e) { notify(String(e), 'error') }
}

function onDrop(e) { files.value = Array.from(e.dataTransfer.files || []) }
function onPick(e) { files.value = Array.from(e.target.files || []) }

watch(() => props.id, () => { ctf.value = null; fmt.value = ''; load() })
onMounted(load)
onBeforeUnmount(() => clearTimeout(timer))
</script>

<template>
  <div class="mx-auto max-w-5xl p-4 font-mono sm:p-6">
    <p v-if="err" class="text-xs text-danger">[!] {{ err }}</p>
    <template v-if="ctf">
      <!-- header -->
      <section class="rounded border border-edge bg-panel shadow">
        <div class="flex flex-wrap items-center gap-2 border-b border-edge bg-panel2 px-3 py-1.5 text-[11px]">
          <Icon name="flag" :size="13" class="text-acc" />
          <h1 class="text-sm font-bold text-fglite">{{ ctf.name }}</h1>
          <a v-if="ctf.url" :href="ctf.url" target="_blank" rel="noopener noreferrer" class="text-dim underline">{{ ctf.url }}</a>
          <span class="ml-auto text-acc">{{ t('ctf.solved_of', { s: ctf.solved, n: ctf.challenges }) }}</span>
        </div>
        <div class="flex flex-wrap items-center gap-2 p-3 text-xs">
          <label class="text-dim" for="fmt">{{ t('ctf.format') }}</label>
          <input id="fmt" v-model="fmt" class="min-w-[200px] rounded border border-edge bg-ink px-2 py-1 text-xs" />
          <button class="kb text-[10px]" @click="saveFormat">{{ t('ctf.save') }}</button>
          <button class="kb kb-acc ml-auto text-[10px]" @click="toggleAutosolve">
            <Icon :name="autoActive ? 'pause' : 'play'" :size="11" />
            {{ autoActive ? t('ctf.autosolve_stop') : t('ctf.autosolve') }}
          </button>
          <button class="kb kb-danger text-[10px]" @click="removeCtf"><Icon name="trash" :size="11" />{{ t('ctf.delete') }}</button>
        </div>
        <p v-if="auto" class="px-3 pb-2 text-[11px] text-warn">
          {{ t('ctf.autosolve_running', { f: auto.finished, t: auto.total, r: auto.running.length, q: auto.queued }) }}
        </p>
      </section>

      <!-- add a challenge -->
      <section class="mt-4 rounded border border-dashed border-edge2 bg-ink/60 p-3 text-xs"
               @dragover.prevent @drop.prevent="onDrop">
        <div class="flex flex-wrap items-center gap-2">
          <Icon name="upload" :size="13" class="text-acc" />
          <span class="font-bold text-fglite">{{ t('ctf.add') }}</span>
          <input type="file" multiple :aria-label="t('home.pick_files')" @change="onPick" class="text-[11px] text-dim" />
          <input v-model="chalName" :placeholder="t('ctf.chal_name')" :aria-label="t('ctf.chal_name')"
                 class="rounded border border-edge bg-ink px-2 py-1 text-xs" />
          <select v-model="category" :aria-label="t('ctf.category')" class="rounded border border-edge bg-ink px-2 py-1 text-xs">
            <option value="">{{ t('ctf.category') }}</option>
            <option v-for="c in CATEGORIES" :key="c" :value="c">{{ c }}</option>
          </select>
          <button class="kb kb-acc text-[10px]" :disabled="busy || !files.length" @click="addChallenge">
            <Icon name="play" :size="11" />{{ busy ? Math.round(pct * 100) + '%' : t('ctf.start_now') }}
          </button>
        </div>
        <p v-if="files.length" class="mt-2 text-[11px] text-dim">
          <span v-for="f in files" :key="f.name" class="mr-3">[+] {{ f.name }} {{ fmtSize(f.size) }}</span>
        </p>
      </section>

      <!-- scoreboard -->
      <section class="mt-4 overflow-hidden rounded border border-edge shadow">
        <table class="w-full text-[12px]">
          <thead class="bg-panel text-left text-[10px] uppercase tracking-wider text-dim">
            <tr>
              <th class="px-3 py-1.5">{{ t('home.col_name') }}</th>
              <th class="px-3 py-1.5">{{ t('ctf.category') }}</th>
              <th class="px-3 py-1.5">{{ t('home.col_status') }}</th>
              <th class="px-3 py-1.5">{{ t('ctf.flag') }}</th>
              <th class="px-3 py-1.5"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in challenges" :key="c.id" class="cursor-pointer border-t border-edge/60 hover:bg-acc/5"
                @click="router.push(`/p/${c.id}`)">
              <td class="px-3 py-1.5 text-fg">
                <span :class="c.solved ? 'text-acc' : 'text-dim'">{{ c.solved ? '✓' : '·' }}</span> {{ c.name }}
              </td>
              <td class="px-3 py-1.5 text-dim">{{ c.category || '—' }}</td>
              <td class="px-3 py-1.5" :class="STATUS_COLOR[c.status] || 'text-dim'">{{ c.status }}</td>
              <td class="max-w-[40ch] truncate px-3 py-1.5" :class="c.solved ? 'text-acc' : 'text-fglite'">
                {{ c.flag || c.flags[0] || '—' }}
                <span v-if="!c.flag && c.flags.length > 1" class="text-dim">(+{{ c.flags.length - 1 }})</span>
              </td>
              <td class="px-3 py-1.5 text-right" @click.stop>
                <button class="kb px-2 text-[10px]" @click="setSolved(c, !c.solved)">
                  {{ c.solved ? t('ctf.mark_open') : t('ctf.mark_solved') }}
                </button>
              </td>
            </tr>
            <tr v-if="!challenges.length"><td colspan="5" class="px-3 py-6 text-center text-dim">{{ t('ctf.empty') }}</td></tr>
          </tbody>
        </table>
      </section>
    </template>
  </div>
</template>

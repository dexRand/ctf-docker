<script setup>
// Modal showing a long text (report / transcript) with copy + download.
// `markdown` renders it through md.js (escaped, safe links); otherwise <pre>.
import { mdToHtml } from '../md'
import { t } from '../i18n'
import Icon from './Icon.vue'

const props = defineProps({
  title: { type: String, required: true },
  icon: { type: String, default: 'report' },
  text: { type: String, default: '' },
  busy: { type: Boolean, default: false },
  markdown: { type: Boolean, default: false },
  filename: { type: String, default: 'stegsuite.md' },
  width: { type: String, default: '980px' },
})
const emit = defineEmits(['close'])

function copy() { navigator.clipboard?.writeText(props.text) }
function download() {
  const url = URL.createObjectURL(new Blob([props.text], { type: 'text/markdown' }))
  const a = document.createElement('a')
  a.href = url
  a.download = props.filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
</script>

<template>
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-3 sm:p-6" @click.self="emit('close')">
    <div class="flex max-h-[88vh] flex-col rounded border border-edge bg-panel"
         :style="{ width: `min(${width}, calc(100vw - 1.5rem))` }">
      <div class="flex items-center gap-2 border-b border-edge bg-panel2 px-4 py-2 text-xs">
        <Icon :name="icon" :size="14" class="text-acc" /><b>{{ title }}</b>
        <span v-if="busy" class="animate-blink text-acc">▋</span>
        <slot name="controls" />
        <button @click="copy" class="kb ml-auto text-[10px]"><Icon name="copy" :size="11" />{{ t('report.copy') }}</button>
        <button @click="download" class="kb text-[10px]"><Icon name="download" :size="11" />.md</button>
        <button @click="emit('close')" class="kb text-[10px]" :aria-label="t('report.close')"><Icon name="close" :size="11" /></button>
      </div>
      <div v-if="markdown" class="md min-h-0 flex-1 overflow-auto p-5" v-html="mdToHtml(text)"></div>
      <pre v-else class="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-words p-4 text-[11px] leading-relaxed text-fglite">{{ text }}</pre>
    </div>
  </div>
</template>

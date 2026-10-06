<script setup>
import { toasts, dismiss } from '../toast'
import Icon from './Icon.vue'

const ICON = { error: 'warn', ok: 'check', info: 'term' }
const TONE = {
  error: 'border-danger/50 bg-danger/10 text-dangerlite',
  ok: 'border-acc/50 bg-acc/10 text-acc',
  info: 'border-edge bg-panel text-fglite',
}
const cls = (k) => TONE[k] || TONE.info
const ic = (k) => ICON[k] || ICON.info
</script>

<template>
  <div class="pointer-events-none fixed bottom-3 right-3 z-[60] flex w-[min(20rem,calc(100vw-1.5rem))] flex-col gap-2"
       role="status" aria-live="polite">
    <div v-for="t in toasts" :key="t.id"
         class="pointer-events-auto flex items-start gap-2 rounded border px-3 py-2 text-[11px] leading-snug shadow-lg"
         :class="cls(t.kind)">
      <Icon :name="ic(t.kind)" :size="12" class="mt-0.5 shrink-0" />
      <span class="min-w-0 flex-1 break-words">{{ t.message }}</span>
      <button type="button" class="shrink-0 text-dim hover:text-fglite" aria-label="close" @click="dismiss(t.id)">
        <Icon name="close" :size="11" />
      </button>
    </div>
  </div>
</template>

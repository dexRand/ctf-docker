<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { wsUrl } from '../api'

const props = defineProps({ pid: { type: String, required: true } })
const el = ref(null)
let term, fit, ws, onResize

onMounted(() => {
  term = new Terminal({
    fontSize: 12, cursorBlink: true, convertEol: false,
    theme: { background: '#0b1220', foreground: '#e2e8f0', cursor: '#6e56cf' },
  })
  fit = new FitAddon()
  term.loadAddon(fit)
  term.open(el.value)
  fit.fit()
  ws = new WebSocket(wsUrl(`/ws/projects/${props.pid}/terminal`))
  ws.onopen = () => { resize(); term.focus() }
  ws.onmessage = (e) => term.write(typeof e.data === 'string' ? e.data : '')
  term.onData((d) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify({ t: 'i', d })) })
  onResize = () => { fit.fit(); resize() }
  window.addEventListener('resize', onResize)
})

function resize() {
  if (ws && ws.readyState === 1 && term) ws.send(JSON.stringify({ t: 'r', c: term.cols, r: term.rows }))
}

onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  try { ws && ws.close() } catch {}
  try { term && term.dispose() } catch {}
})
</script>

<template>
  <div ref="el" class="h-full w-full bg-ink p-1"></div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { wsUrl } from '../api'

const props = defineProps({ pid: { type: String, required: true } })
const el = ref(null)
let term, fit, ws, onResize, ro

onMounted(() => {
  term = new Terminal({
    fontSize: 12, cursorBlink: true, convertEol: false, cursorStyle: 'block',
    theme: {
      // standard Linux-console / Debian palette: black bg, grey fg,
      // classic 16-color ANSI (aa/55 base tones)
      background: '#000000',
      foreground: '#aaaaaa',
      cursor: '#ffffff',
      cursorAccent: '#000000',
      selectionBackground: 'rgba(255, 255, 255, 0.4)',
      black: '#000000', red: '#aa0000', green: '#00aa00', yellow: '#aa5500',
      blue: '#0000aa', magenta: '#aa00aa', cyan: '#00aaaa', white: '#aaaaaa',
      brightBlack: '#555555', brightRed: '#ff5555', brightGreen: '#55ff55',
      brightYellow: '#ffff55', brightBlue: '#5555ff', brightMagenta: '#ff55ff',
      brightCyan: '#55ffff', brightWhite: '#ffffff',
    },
  })
  fit = new FitAddon()
  term.loadAddon(fit)
  term.open(el.value)
  fit.fit()
  ws = new WebSocket(wsUrl(`/ws/projects/${props.pid}/terminal`))
  ws.onopen = () => { resize(); term.focus() }
  ws.onmessage = (e) => term.write(typeof e.data === 'string' ? e.data : '')
  term.onData((d) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify({ t: 'i', d })) })
  onResize = () => { try { fit.fit() } catch {} ; resize() }
  window.addEventListener('resize', onResize)
  // the panel is kept mounted with v-show, so when its tab becomes visible the
  // container goes from 0x0 to a real size: ResizeObserver refits the terminal.
  ro = new ResizeObserver(onResize)
  ro.observe(el.value)
})

function resize() {
  if (ws && ws.readyState === 1 && term) ws.send(JSON.stringify({ t: 'r', c: term.cols, r: term.rows }))
}

onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  try { ro && ro.disconnect() } catch {}
  try { ws && ws.close() } catch {}
  try { term && term.dispose() } catch {}
})
</script>

<template>
  <div ref="el" class="h-full w-full bg-ink p-1"></div>
</template>

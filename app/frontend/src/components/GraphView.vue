<script setup>
import { ref, onMounted, onBeforeUnmount, watch } from 'vue'
import ForceGraph from 'force-graph'

const props = defineProps({
  nodes: { type: Array, default: () => [] },   // { id, name, tool, route, flag, cracked, locked }
  links: { type: Array, default: () => [] },   // { source, target, route }
  selected: { type: [Number, String], default: null },
})
const emit = defineEmits(['select'])

const el = ref(null)
let graph = null
let ro = null
let fitted = false
const cache = new Map() // id -> stable node object, so positions survive refreshes

const C_ROUTE = '#45e08c'
const C_WARN = '#f5c542'
const C_OFF = '#5b6672'

function buildData() {
  const keep = new Set()
  const nodes = props.nodes.map((n) => {
    keep.add(n.id)
    let o = cache.get(n.id)
    if (!o) { o = { id: n.id }; cache.set(n.id, o) }
    Object.assign(o, n)
    o.__color = (n.flag || n.route) ? C_ROUTE : (n.cracked || n.locked) ? C_WARN : C_OFF
    o.__r = n.flag ? 5 : n.route ? 4 : 3
    o.__sel = n.id === props.selected
    return o
  })
  for (const k of [...cache.keys()]) if (!keep.has(k)) cache.delete(k)
  return {
    nodes,
    links: props.links.map((l) => ({ source: l.source, target: l.target, __route: l.route })),
  }
}

function painter(node, ctx, scale) {
  const r = node.__r
  if (node.__sel) {
    ctx.beginPath(); ctx.arc(node.x, node.y, r + 4 / scale, 0, 2 * Math.PI)
    ctx.fillStyle = 'rgba(69,224,140,.18)'; ctx.fill()
  }
  ctx.beginPath(); ctx.arc(node.x, node.y, r, 0, 2 * Math.PI)
  ctx.fillStyle = node.__color; ctx.fill()
  if (node.__sel) { ctx.lineWidth = 1.4 / scale; ctx.strokeStyle = '#f4f7f9'; ctx.stroke() }
  const fs = 11 / scale
  ctx.font = `${fs}px ui-monospace, Menlo, Consolas, monospace`
  ctx.textAlign = 'center'
  ctx.textBaseline = 'top'
  ctx.fillStyle = node.flag ? C_ROUTE : '#c7d0d8'
  ctx.fillText(node.name, node.x, node.y + r + 1.6 / scale)
}

onMounted(() => {
  graph = ForceGraph()(el.value)
    .backgroundColor('#0c0e10')
    .nodeId('id')
    .nodeCanvasObject(painter)
    .nodePointerAreaPaint((n, color, ctx, scale) => {
      ctx.fillStyle = color
      // the dot
      ctx.beginPath(); ctx.arc(n.x, n.y, n.__r + 5, 0, 2 * Math.PI); ctx.fill()
      // and the label text below it, so clicking the name selects the node too
      const fs = 11 / (scale || 1)
      ctx.font = `${fs}px ui-monospace, Menlo, Consolas, monospace`
      const w = ctx.measureText(n.name).width
      ctx.fillRect(n.x - w / 2 - 2, n.y + n.__r, w + 4, fs + 4)
    })
    .linkColor((l) => (l.__route ? C_ROUTE : '#2b3238'))
    .linkWidth((l) => (l.__route ? 1.6 : 0.7))
    .linkDirectionalArrowLength(2.4)
    .linkDirectionalArrowRelPos(1)
    .linkDirectionalArrowColor((l) => (l.__route ? C_ROUTE : '#2b3238'))
    .nodeLabel((n) => `${n.name} — ${n.tool || ''}`)
    .warmupTicks(20)
    .cooldownTicks(200)
    .d3AlphaDecay(0.022)
    .d3VelocityDecay(0.35)
    .minZoom(0.3)
    .maxZoom(12)

  graph.graphData(buildData())

  // force-graph's canvas hit-test proved unreliable here (a click near a node
  // fired onNodeClick for a different, far node), so we pick the nearest node
  // ourselves from the pointer position.
  let down = null
  el.value.addEventListener('pointerdown', (ev) => { down = { x: ev.clientX, y: ev.clientY } })
  el.value.addEventListener('pointerup', (ev) => {
    const start = down
    down = null
    if (!start || Math.hypot(ev.clientX - start.x, ev.clientY - start.y) > 5) return // pan/drag
    const rect = el.value.getBoundingClientRect()
    const px = ev.clientX - rect.left
    const py = ev.clientY - rect.top
    let best = null
    let bestD = Infinity
    for (const n of graph.graphData().nodes) {
      const p = graph.graph2ScreenCoords(n.x, n.y)
      const d = Math.hypot(p.x - px, p.y - py)
      if (d < bestD) { bestD = d; best = n }
    }
    if (best && bestD <= (best.__r || 3) + 14) emit('select', best.id)
  })

  ro = new ResizeObserver(() => {
    const w = el.value.clientWidth
    const h = el.value.clientHeight
    if (!w || !h) return
    graph.width(w).height(h)
    if (!fitted) {
      fitted = true
      setTimeout(() => window.dispatchEvent(new Event('resize')), 0)
      setTimeout(() => graph.zoomToFit(700, 50), 600)
    }
  })
  ro.observe(el.value)
})

function refresh() {
  if (!graph) return
  graph.graphData(buildData())
  graph.nodeCanvasObject(painter)
  graph.resumeAnimation()
}
watch(() => props.nodes, refresh)
watch(() => props.links, refresh)
watch(() => props.selected, () => {
  if (!graph) return
  for (const o of cache.values()) o.__sel = o.id === props.selected
  graph.nodeCanvasObject(painter)
  graph.resumeAnimation()
})

function fit() { if (graph) graph.zoomToFit(500, 50) }
defineExpose({ fit })

onBeforeUnmount(() => {
  try { ro && ro.disconnect() } catch { /* noop */ }
  try { graph && graph._destructor() } catch { /* noop */ }
  graph = null
})
</script>

<template>
  <div ref="el" class="h-full w-full"></div>
</template>

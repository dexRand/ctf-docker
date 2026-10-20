// Resizable panes of the project view (left tree, right panel, log split):
// pointer drag + keyboard nudge, sizes persisted in localStorage.
import { ref } from 'vue'

export function usePaneResize(gridRef, logsRef) {
  function loadW(key, def) {
    try { const v = parseInt(localStorage.getItem('steg.pane.' + key) || '', 10); return isNaN(v) ? def : v } catch { return def }
  }
  const leftW = ref(loadW('left', 250))
  const rightW = ref(loadW('right', 380))
  const logSplit = ref(loadW('logsplit', 300))
  function clamp(v, mn, mx) { return Math.min(mx, Math.max(mn, v)) }
  // Delta-based drag: we capture the sizes at pointerdown and apply the pointer
  // offset. No rect math during the move, so the panes never jump or fight.
  let drag = null
  function startDrag(kind, e) {
    e.preventDefault()
    e.stopPropagation()
    const grid = gridRef.value?.getBoundingClientRect()
    const logsBox = logsRef.value?.parentElement?.getBoundingClientRect()
    drag = {
      kind, x: e.clientX, y: e.clientY,
      left: leftW.value, right: rightW.value, split: logSplit.value,
      gw: grid ? grid.width : 1400, lh: logsBox ? logsBox.height : 800,
    }
    window.addEventListener('pointermove', onDrag)
    window.addEventListener('pointerup', endDrag)
    document.body.style.cursor = kind === 'logsplit' ? 'row-resize' : 'col-resize'
    document.body.style.userSelect = 'none'
  }
  function onDrag(e) {
    if (!drag) return
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y
    if (drag.kind === 'left') {
      leftW.value = clamp(drag.left + dx, 180, Math.max(220, Math.min(560, drag.gw - drag.right - 380)))
    } else if (drag.kind === 'right') {
      rightW.value = clamp(drag.right - dx, 300, Math.max(340, Math.min(820, drag.gw - drag.left - 380)))
    } else if (drag.kind === 'logsplit') {
      logSplit.value = clamp(drag.split + dy, 80, Math.max(120, drag.lh - 150))
    }
  }
  function endDrag() {
    if (!drag) return
    drag = null
    window.removeEventListener('pointermove', onDrag)
    window.removeEventListener('pointerup', endDrag)
    document.body.style.cursor = ''
    document.body.style.userSelect = ''
    savePanes()
    window.dispatchEvent(new Event('resize'))
  }
  function savePanes() {
    try {
      localStorage.setItem('steg.pane.left', String(leftW.value))
      localStorage.setItem('steg.pane.right', String(rightW.value))
      localStorage.setItem('steg.pane.logsplit', String(logSplit.value))
    } catch { /* private mode */ }
  }
  // Keyboard support for the separators (role=separator): arrow keys resize.
  function nudge(kind, delta) {
    if (kind === 'left') leftW.value = clamp(leftW.value + delta, 180, 560)
    else if (kind === 'right') rightW.value = clamp(rightW.value - delta, 300, 820)
    else if (kind === 'logsplit') logSplit.value = clamp(logSplit.value + delta, 80, 640)
    savePanes()
    window.dispatchEvent(new Event('resize'))
  }

  return { leftW, rightW, logSplit, startDrag, endDrag, nudge }
}

// Tiny global toast store: `notify()` from any view, rendered once by
// <Toasts/> in App.vue. Kept framework-light on purpose.
import { ref } from 'vue'

export const toasts = ref([])
let seq = 0

export function notify(message, kind = 'info', ms = 4000) {
  const id = ++seq
  toasts.value.push({ id, message: String(message ?? ''), kind })
  if (ms > 0) setTimeout(() => dismiss(id), ms)
  return id
}

export function dismiss(id) {
  toasts.value = toasts.value.filter((t) => t.id !== id)
}

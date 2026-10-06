// Human-readable tool names, translated at runtime via i18n (`tools.*` keys).
// Keys are tool names as exposed by the API plus the pseudo-origins the UI
// invents ('upload', 'extracted', 'raw scan'). Missing keys fall back to the
// raw name, so a new tool is never blank.
import { t, tt } from './i18n'

export function toolLabel(name, lng) {
  if (!name) return ''
  const key = 'tools.' + name
  const v = lng ? tt(lng, key) : t(key)
  return v === key ? name : v
}
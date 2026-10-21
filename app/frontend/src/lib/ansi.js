// ANSI SGR colours (tool output) -> safe HTML: the text is escaped first and
// styles only come from fixed tables, so it can go through v-html.
const X16 = ['#000000', '#cd3131', '#0dbc79', '#e5e510', '#2472c8', '#bc3fbc', '#11a8cd', '#e5e5e5',
  '#666666', '#f14c4c', '#23d18b', '#f5f543', '#3b8eea', '#d670d6', '#29b8db', '#ffffff']
function xterm(n) {
  n = Number(n)
  if (n < 16) return X16[n]
  if (n < 232) { const k = n - 16, r = Math.floor(k / 36), g = Math.floor((k % 36) / 6), b = k % 6; const v = (x) => (x ? x * 40 + 55 : 0); return `rgb(${v(r)},${v(g)},${v(b)})` }
  const v = 8 + (n - 232) * 10; return `rgb(${v},${v},${v})`
}
export function ansiToHtml(s) {
  const esc = String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  let open = 0
  return esc.replace(/\x1b\[([0-9;]*)m/g, (_m, codes) => {
    const parts = codes.split(';').filter((x) => x !== '').map(Number)
    const css = []
    for (let i = 0; i < parts.length; i++) {
      const c = parts[i]
      if (c === 0) css.push('RESET')
      else if (c === 1) css.push('font-weight:600')
      else if (c >= 30 && c <= 37) css.push(`color:${X16[c - 30]}`)
      else if (c >= 90 && c <= 97) css.push(`color:${X16[c - 90 + 8]}`)
      else if (c >= 40 && c <= 47) css.push(`background:${X16[c - 40]}`)
      else if (c >= 100 && c <= 107) css.push(`background:${X16[c - 100 + 8]}`)
      else if (c === 38 && parts[i + 1] === 5) { css.push(`color:${xterm(parts[i + 2])}`); i += 2 }
      else if (c === 48 && parts[i + 1] === 5) { css.push(`background:${xterm(parts[i + 2])}`); i += 2 }
    }
    if (css.includes('RESET')) { const n = open; open = 0; return '</span>'.repeat(n) }
    open++
    return `<span style="${css.join(';')}">`
  }) + '</span>'.repeat(open)
}

// Minimal, dependency-free Markdown -> HTML (headings, tables, code, lists,
// bold, inline code). HTML is escaped first, so tool output is safe.
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
function inline(s) {
  return esc(s)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>')
}

export function mdToHtml(md) {
  const lines = String(md).split('\n')
  let html = '', i = 0, inCode = false
  let code = []
  while (i < lines.length) {
    const line = lines[i]
    if (line.trim().startsWith('```')) {
      if (inCode) { html += '<pre>' + esc(code.join('\n')) + '</pre>'; code = []; inCode = false }
      else inCode = true
      i++; continue
    }
    if (inCode) { code.push(line); i++; continue }
    if (/^\s*\|/.test(line) && i + 1 < lines.length && /^\s*\|[-: |]+\|\s*$/.test(lines[i + 1])) {
      const head = line.split('|').slice(1, -1).map((s) => s.trim())
      i += 2
      const rows = []
      while (i < lines.length && /^\s*\|/.test(lines[i])) {
        rows.push(lines[i].split('|').slice(1, -1).map((s) => s.trim())); i++
      }
      html += '<table><thead><tr>' + head.map((h) => `<th>${inline(h)}</th>`).join('') +
        '</tr></thead><tbody>' +
        rows.map((r) => '<tr>' + r.map((c) => `<td>${inline(c)}</td>`).join('') + '</tr>').join('') +
        '</tbody></table>'
      continue
    }
    const h = line.match(/^(#{1,6})\s+(.*)$/)
    if (h) { const n = h[1].length; html += `<h${n}>${inline(h[2])}</h${n}>`; i++; continue }
    if (/^\s*[-*]\s+/.test(line)) {
      html += '<ul>'
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        html += `<li>${inline(lines[i].replace(/^\s*[-*]\s+/, ''))}</li>`; i++
      }
      html += '</ul>'; continue
    }
    if (line.trim() === '') { i++; continue }
    html += `<p>${inline(line)}</p>`; i++
  }
  if (inCode) html += '<pre>' + esc(code.join('\n')) + '</pre>'
  return html
}

# Attribuzione — Agent Skills

Le skill in `.opencode/skills/`, i `references/` e i `commands/` provengono da
due progetti open source.

## addyosmani/agent-skills (MIT)

- **Upstream:** https://github.com/addyosmani/agent-skills
- **Versione importata:** 0.6.12
- **Licenza:** MIT © 2025 Addy Osmani (testo integrale in fondo)
- **Data di import:** 2026-10-01 — aggiornato **2026-10-10**

| Percorso locale            | Contenuto upstream                          |
| -------------------------- | ------------------------------------------- |
| `.opencode/skills/<nome>/` | `skills/<nome>/` (25 skill)                 |
| `.opencode/references/`    | `references/` (checklist condivise)         |
| `.opencode/commands/`      | `.claude/commands/*.md` (adattati a OpenCode) |

**Modifiche rispetto all'upstream:** nei comandi il namespace `agent-skills:<nome>`
è stato rimosso (le skill sono installate localmente e si invocano con il solo
nome) e il riferimento a `CLAUDE.md` è stato sostituito con `AGENTS.md`. Nessun
altro contenuto delle skill è stato modificato. Per riallineare: ri-copia le
directory `skills/` e `references/` e ri-applica il `sed` ai comandi
(`s/agent-skills://g; s/CLAUDE\.md/AGENTS.md/g`).

## pbakaus/impeccable (Apache-2.0)

- **Upstream:** https://github.com/pbakaus/impeccable
- **Versione skill:** 4.5.2 (engine `0.1.14`)
- **Licenza:** Apache License 2.0 — testo integrale in
  [`LICENSE-impeccable`](./LICENSE-impeccable), avvisi in
  [`NOTICE-impeccable.md`](./NOTICE-impeccable.md)
- **Data di import:** 2026-10-10

| Percorso locale                  | Contenuto upstream                            |
| -------------------------------- | --------------------------------------------- |
| `.opencode/skills/impeccable/`   | `.agents/skills/impeccable/` (SKILL.md + reference/ + scripts/ + agents/) |

Nessuna modifica al contenuto.

## Licenza MIT (addyosmani/agent-skills)

```text
MIT License

Copyright (c) 2025 Addy Osmani

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

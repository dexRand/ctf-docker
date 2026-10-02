# Attribuzione — Agent Skills

Le skill contenute in questa directory provengono dal progetto open source
[`addyosmani/agent-skills`](https://github.com/addyosmani/agent-skills)
(versione **0.6.11**), distribuito con licenza MIT (vedi
[`LICENSE-agent-skills`](./LICENSE-agent-skills)).

- **Upstream:** https://github.com/addyosmani/agent-skills
- **Versione importata:** 0.6.11
- **Licenza:** MIT © 2025 Addy Osmani
- **Data di import:** 2026-10-01

## Cosa è stato importato

| Percorso locale            | Contenuto upstream                          |
| -------------------------- | ------------------------------------------- |
| `.opencode/skills/<nome>/` | `skills/<nome>/` (25 skill)                 |
| `.opencode/references/`    | `references/` (checklist condivise)         |
| `.opencode/commands/`      | `.claude/commands/*.md` (adattati a OpenCode) |

## Modifiche rispetto all'upstream

- I comandi in `.opencode/commands/` sono stati adattati: il namespace
  `agent-skills:<nome>` è stato rimosso perché le skill sono installate
  localmente nel progetto e vengono invocate con il solo nome.
- Il riferimento a `CLAUDE.md` nei comandi è stato sostituito con `AGENTS.md`,
  il file di istruzioni usato da OpenCode.

Nessun altro contenuto delle skill è stato modificato. Per riallineare le skill
con l'upstream, ri-copia le directory da `skills/` e `references/` del
repository sorgente.

## Licenza (testo integrale)

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

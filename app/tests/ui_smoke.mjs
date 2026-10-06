// Headless-browser smoke test for the StegSuite SPA.
// Run through app/tests/ui_smoke.sh (real Chromium in a Docker container).
import { chromium } from 'playwright'

const BASE = process.env.BASE || 'http://127.0.0.1:19014'
const errors = []
let failures = 0
const check = (name, cond, extra = '') => {
  console.log(`  [${cond ? 'PASS' : 'FAIL'}] ${name}${extra ? '  ' + extra : ''}`)
  if (!cond) failures++
}

const browser = await chromium.launch({ args: ['--no-sandbox'] })
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
page.on('console', (m) => {
  if (m.type() === 'error' && !/Failed to load resource|favicon/i.test(m.text())) errors.push(m.text())
})
page.on('pageerror', (e) => errors.push('pageerror: ' + e.message))

// --- home (desktop) ---
await page.goto(BASE, { waitUntil: 'networkidle' })
check('home title', (await page.title()) === 'StegSuite')
check('home has run button', (await page.getByRole('button', { name: /run/i }).count()) > 0)
check('toast region present', (await page.locator('[role="status"]').count()) > 0)

// --- create a project through the API so the project view has data ---
const fd = new FormData()
fd.append('mode', 'auto')
fd.append('files', new Blob(['hello ITS{ui_smoke}'], { type: 'text/plain' }), 'a.txt')
const proj = await (await fetch(BASE + '/api/v1/projects', { method: 'POST', body: fd })).json()
await fetch(`${BASE}/api/v1/projects/${proj.id}/start`, { method: 'POST' })

await page.goto(`${BASE}/#/p/${proj.id}`, { waitUntil: 'networkidle' })
await page.waitForTimeout(1500)
const center = page.locator('main.min-w-0')
check('project: center pane visible', await center.isVisible())
check('project: findings tab present', (await page.getByRole('button', { name: /findings/i }).count()) > 0)
check('desktop: mobile switcher absent', (await page.getByRole('button', { name: 'detail', exact: true }).count()) === 0)

// --- mobile ---
await page.setViewportSize({ width: 375, height: 720 })
await page.waitForTimeout(400)
check('mobile: switcher visible', await page.getByRole('button', { name: 'files', exact: true }).isVisible())

await page.getByRole('button', { name: 'files', exact: true }).click()
await page.waitForTimeout(250)
check('mobile: files pane shown', await page.locator('aside').first().isVisible())
check('mobile: center pane hidden', !(await center.isVisible()))

await page.getByRole('button', { name: 'panel', exact: true }).click()
await page.waitForTimeout(250)
check('mobile: panel pane shown', await page.locator('aside').nth(1).isVisible())

await browser.close()
check('no console/page errors', errors.length === 0, errors.slice(0, 3).join(' | '))
console.log(failures === 0 ? '* ALL UI CHECKS PASSED' : `* ${failures} CHECK(S) FAILED`)
process.exit(failures ? 1 : 0)

import { createHash } from 'node:crypto'
import { expect, test } from '@playwright/test'
import { confirmFresh, freshCode, HUB, login, privateFill, privateFixture, trustedContext } from './private-fixture'

test('actual historical original access requires an approved reader role, exact purpose/descriptor MFA and one-use download', async () => {
  test.skip(process.env.VEYPORT_LAB_PHASE !== 'originals', 'Explicit actual post-execution lab phase required')
  const fixture = privateFixture()
  const sessions = await Promise.all([trustedContext(), trustedContext(), trustedContext()])
  try {
    const [officer, first, second] = await Promise.all(sessions.map(session => session.context.newPage()))
    await login(officer, 'officer')
    const initial = await officer.evaluate(async () => ({ user: await (await fetch('/api/auth/me')).json(), executions: await (await fetch('/api/executions?limit=50&offset=0', { cache: 'no-store' })).json() }))
    const execution = initial.executions.executions.find((item: { enhanced: boolean; evidence_state: string; script_sha256?: string }) => item.enhanced && item.evidence_state === 'confirmed' && item.script_sha256)
    expect(execution).toBeTruthy()
    if (!initial.user.capabilities.includes('audit.original.read')) {
      await officer.goto(`${HUB}/audit-logs`)
      await expect(officer.getByRole('button', { name: 'Request script original' })).toHaveCount(0)
      const refused = await officer.evaluate(async id => {
        const csrf = /(?:^|;\s*)__Host-veyport_csrf=([^;]+)/.exec(document.cookie)?.[1] ?? ''
        return (await fetch(`/api/executions/${id}/original-access/preview`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify({ purpose: 'Synthetic permission refusal', records: ['script'] }) })).status
      }, execution.id)
      expect(refused).toBe(403)
      await officer.goto(`${HUB}/settings?tab=security`)
      await officer.getByLabel('Target principal ID').fill(fixture.users.officer.id)
      await officer.getByLabel('Principal change reason').fill('Synthetic historical-read browser qualification; no human approval represented')
      await officer.getByRole('button', { name: 'Preview protected principal request' }).click()
      await officer.getByRole('button', { name: 'Request this protected principal change' }).click()
      await confirmFresh(officer, 'officer')
      const id = new URL(officer.url()).searchParams.get('request')
      expect(id).toMatch(/^[a-zA-Z0-9_-]{1,128}$/)
      const review = `${HUB}/settings?tab=security&request=${id}`
      for (const [page, person] of [[first, 'approver-a'], [second, 'approver-b']] as const) {
        await login(page, person); await page.goto(review)
        await page.getByRole('button', { name: 'Approve this exact request' }).click()
        await confirmFresh(page, person)
      }
      await officer.reload()
      await officer.getByRole('button', { name: 'Apply this exact request' }).click()
      await confirmFresh(officer, 'officer')
      await login(officer, 'officer')
    }
    const current = await officer.evaluate(async () => (await (await fetch('/api/audit-policy', { cache: 'no-store' })).json()).policy.version)
    expect(Number(execution.policy_version)).toBeLessThan(current)
    await officer.goto(`${HUB}/audit-logs`)
    const record = officer.locator('article').filter({ hasText: execution.id })
    await record.getByRole('button', { name: 'Request script original' }).click()
    await officer.getByLabel('Purpose', { exact: true }).fill('Investigate isolated synthetic historical execution')
    await officer.getByRole('button', { name: 'Continue to protected review' }).click()
    await expect(officer.getByRole('dialog')).toContainText(execution.script_sha256)
    await expect(officer.getByRole('dialog')).toContainText('Investigate isolated synthetic historical execution')
    let consumedURL = ''
    officer.on('request', request => { if (new URL(request.url()).pathname.startsWith('/api/audit-originals/')) consumedURL = request.url() })
    // Preparation may wait for TOTP/rate-limit spacing. Start the bounded
    // download listener afterward, before the action that consumes fresh MFA.
    await privateFill(officer.getByLabel('Fresh MFA code'), freshCode('officer'))
    const [download] = await Promise.all([
      officer.waitForEvent('download', { timeout: 35_000 }),
      officer.getByRole('button', { name: 'Confirm with fresh MFA' }).click(),
    ])
    const stream = await download.createReadStream()
    if (!stream) throw new Error('Original response stream unavailable')
    const hash = createHash('sha256')
    for await (const chunk of stream) hash.update(chunk)
    expect(hash.digest('hex')).toBe(execution.script_sha256)
    await expect(officer.getByRole('status')).toContainText('does not confirm that a file was saved')
    expect(new URL(officer.url()).pathname).toBe('/audit-logs')
    if (!consumedURL || !consumedURL.startsWith(`${HUB}/api/audit-originals/`)) throw new Error('Expected protected one-use read was not observed')
    const replayStatus = await officer.evaluate(async url => (await fetch(url, { cache: 'no-store' })).status, consumedURL)
    consumedURL = ''
    expect(replayStatus).toBe(403)
    expect(await officer.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0])
    await download.delete()
  } finally { await Promise.all(sessions.map(session => session.close())) }
})

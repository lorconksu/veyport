import { expect, test } from '@playwright/test'
import type { SecurityChange } from '../../../web/src/types/security'
import { confirmFresh, HUB, login, privateFixture, safeStatus, trustedContext } from './private-fixture'

test('actual initial bootstrap uses three synthetic people, exact review, fresh MFA and request-scoped viewer approvals', async () => {
  test.skip(process.env.VEYPORT_LAB_PHASE !== 'bootstrap', 'Explicit actual initial-state lab phase required')
  const fixture = privateFixture()
  const sessions = await Promise.all([trustedContext(), trustedContext(), trustedContext()])
  try {
    const [officer, first, second] = await Promise.all(sessions.map(session => session.context.newPage()))
    await login(officer, 'officer')
    console.info('[lab] officer authenticated')
    const initial = await officer.evaluate(async () => (await fetch('/api/audit-policy', { cache: 'no-store' })).json())
    expect(initial.governance_enrolled).toBe(false)
    expect(initial.policy.version).toBe(1)
    const resumeID = process.env.VEYPORT_LAB_REQUEST_ID
    if (resumeID && !/^[a-zA-Z0-9_-]{1,128}$/.test(resumeID)) throw new Error('Exact existing request ID required')
    let id: string | null = resumeID ?? null
    if (!id) {
      await officer.goto(`${HUB}/settings?tab=security`)
      await officer.getByLabel('Runtime limit (seconds)').fill(String(fixture.candidate_policy.runtime_seconds))
      await officer.getByLabel('Node IDs (comma separated)').fill(fixture.target_id)
      await officer.getByLabel('Retention (hours)').fill(String(fixture.candidate_policy.retention_hours))
      await officer.getByLabel('Archive destination').fill(fixture.candidate_policy.destination)
      await officer.getByLabel('Immutable credential reference').fill(fixture.candidate_policy.credential_ref)
      await officer.getByLabel('Trust key IDs (comma separated)').fill(fixture.candidate_policy.trust_key_ids.join(','))
      await officer.getByLabel('Qualification SHA-256').fill(fixture.candidate_policy.qualification_sha256)
      for (const [index, person] of (['officer', 'approver-a', 'approver-b'] as const).entries()) {
        await officer.getByLabel('Verified person ID').nth(index).fill(`isolated-synthetic-person-${person}`)
        await officer.getByLabel('Operator verification evidence').nth(index).fill('Isolated .59 synthetic fixture; no human or owner approval represented')
      }
      const nominations = officer.getByRole('group', { name: 'Initial officer and approver nominations' }).getByRole('combobox')
      await nominations.nth(0).selectOption(fixture.users['approver-a'].id)
      await nominations.nth(1).selectOption(fixture.users['approver-b'].id)
      await officer.getByLabel('Reason', { exact: true }).fill('Isolated three-person browser bootstrap; synthetic votes only')
      await officer.getByRole('button', { name: 'Preview request', exact: true }).click()
      await expect(officer.getByRole('heading', { name: 'Confirm exact request' })).toBeVisible()
      await officer.getByRole('button', { name: 'Request this change', exact: true }).click()
      await expect(officer.getByRole('dialog')).toContainText('security.request')
      await confirmFresh(officer, 'officer')
      id = new URL(officer.url()).searchParams.get('request')
    }
    expect(id).toMatch(/^[a-zA-Z0-9_-]{1,128}$/)
    const review = `${HUB}/settings?tab=security&request=${id}`
    const existing = await officer.evaluate(async id => {
      const response = await fetch(`/api/security/changes/${id}`, { cache: 'no-store' })
      if (!response.ok) throw new Error(`Existing request lookup status=${response.status}`)
      return response.json()
    }, id) as SecurityChange
    expect(existing.requester_id).toBe(fixture.users.officer.id)
    expect(existing.expected_version).toBe(1)
    expect(['requested', 'partially_approved', 'approved']).toContain(existing.state)
    expect(existing.change.kind).toBe('bootstrap')
    if (existing.change.kind !== 'bootstrap') throw new Error('Existing exact bootstrap required')
    expect(existing.change.policy).toEqual({ ...fixture.candidate_policy, profile: 'enhanced', actors: [] })
    expect(existing.change.nominations).toEqual((['officer', 'approver-a', 'approver-b'] as const).map(person => ({
      user_id: fixture.users[person].id, person_id: `isolated-synthetic-person-${person}`,
      roles: [person === 'officer' ? 'security-officer' : 'security-approver'],
      verification: 'Isolated .59 synthetic fixture; no human or owner approval represented',
    })))
    expect(existing.reason).toBe('Isolated three-person browser bootstrap; synthetic votes only')
    expect(new Date(existing.expires_at).getTime()).toBeGreaterThan(Date.now())
    console.info(resumeID ? '[lab] existing exact bootstrap resumed' : '[lab] exact bootstrap requested')
    for (const [page, person] of [[first, 'approver-a'], [second, 'approver-b']] as const) {
      await login(page, person)
      console.info(`[lab] ${person} authenticated`)
      expect(await safeStatus(page, '/api/security/changes')).toBe(403)
      expect(await safeStatus(page, '/api/security/principals')).toBe(403)
      await page.goto(review)
      await expect(page.getByRole('heading', { name: 'Review a specific request' })).toBeVisible()
      await expect(page.getByRole('heading', { name: 'Auditing', exact: true })).toHaveCount(0)
      const previousVote = existing.approvals?.find(vote => vote.user_id === fixture.users[person].id)
      if (previousVote) {
        expect(previousVote.invalidated_at).toBeUndefined()
        await expect(page.getByRole('button', { name: 'Approve this exact request' })).toHaveCount(0)
        console.info(`[lab] ${person} prior exact vote retained`)
        continue
      }
      await page.getByRole('button', { name: 'Approve this exact request' }).click()
      await expect(page.getByRole('dialog')).toContainText('security.approve')
      await confirmFresh(page, person)
      console.info(`[lab] ${person} exact approval completed`)
      await expect(page.getByRole('button', { name: 'Approve this exact request' })).toHaveCount(0)
    }
    await officer.goto(review)
    await expect(officer.getByRole('button', { name: 'Approve this exact request' })).toHaveCount(0)
    await officer.getByRole('button', { name: 'Apply this exact request' }).click()
    await expect(officer.getByRole('dialog')).toContainText('security.apply')
    await confirmFresh(officer, 'officer')
    console.info('[lab] exact bootstrap application completed')
    // Activation revokes nominee sessions as role/person identities change.
    await login(officer, 'officer')
    await officer.goto(review)
    await expect(officer.getByText(new RegExp(`Request ${id} · applied`))).toBeVisible()
    const active = await officer.evaluate(async () => (await fetch('/api/audit-policy', { cache: 'no-store' })).json())
    expect(active.state).toBe('enhanced')
    expect(active.governance_enrolled).toBe(true)
    expect(Object.values(active.readiness).every(value => value === true)).toBe(true)
    for (const page of [officer, first, second]) expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0])
    console.info('[lab] enhanced state and live readiness verified')
  } finally { await Promise.all(sessions.map(session => session.close())) }
})

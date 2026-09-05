import { describe, it, expect } from 'vitest'
import { formatRelative, isFuture, isNoAutoUnlock } from '@/lib/time'

const NOW = new Date('2026-09-05T12:00:00Z')

describe('formatRelative', () => {
  it('returns "just now" for under 60 seconds', () => {
    expect(formatRelative('2026-09-05T11:59:30Z', NOW)).toBe('just now')
    expect(formatRelative('2026-09-05T12:00:00Z', NOW)).toBe('just now')
  })

  it('returns singular "1 minute ago"', () => {
    expect(formatRelative('2026-09-05T11:58:59Z', NOW)).toBe('1 minute ago')
  })

  it('returns plural "N minutes ago"', () => {
    expect(formatRelative('2026-09-05T11:45:00Z', NOW)).toBe('15 minutes ago')
  })

  it('returns singular "1 hour ago"', () => {
    expect(formatRelative('2026-09-05T11:00:00Z', NOW)).toBe('1 hour ago')
  })

  it('returns plural "N hours ago"', () => {
    expect(formatRelative('2026-09-05T09:00:00Z', NOW)).toBe('3 hours ago')
  })

  it('returns singular "1 day ago"', () => {
    expect(formatRelative('2026-09-04T12:00:00Z', NOW)).toBe('1 day ago')
  })

  it('returns plural "N days ago"', () => {
    expect(formatRelative('2026-09-03T12:00:00Z', NOW)).toBe('2 days ago')
  })

  it('returns "on YYYY-MM-DD" beyond 30 days', () => {
    expect(formatRelative('2026-08-01T12:00:00Z', NOW)).toBe('on 2026-08-01')
  })

  it('defaults now to the current time when omitted', () => {
    const iso = new Date().toISOString()
    expect(formatRelative(iso)).toBe('just now')
  })
})

describe('isFuture', () => {
  it('is true for a timestamp after now', () => {
    expect(isFuture('2026-09-05T12:10:00Z', NOW)).toBe(true)
  })

  it('is false for a timestamp before now', () => {
    expect(isFuture('2026-09-05T11:50:00Z', NOW)).toBe(false)
  })

  it('is false for a timestamp equal to now', () => {
    expect(isFuture('2026-09-05T12:00:00Z', NOW)).toBe(false)
  })

  it('defaults now to the current time when omitted', () => {
    expect(isFuture('2099-01-01T00:00:00Z')).toBe(true)
  })
})

describe('isNoAutoUnlock', () => {
  it('is true for the far-future sentinel', () => {
    expect(isNoAutoUnlock('9999-12-31T00:00:00Z')).toBe(true)
  })

  it('is false for a normal future date', () => {
    expect(isNoAutoUnlock('2026-09-05T12:10:00Z')).toBe(false)
  })

  it('is false for null/undefined', () => {
    expect(isNoAutoUnlock(null)).toBe(false)
    expect(isNoAutoUnlock(undefined)).toBe(false)
  })
})

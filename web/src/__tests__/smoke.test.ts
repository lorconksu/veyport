import { describe, it, expect } from 'vitest'
import { Logo } from '../components/logo'

describe('test infrastructure', () => {
  it('loads application modules under vitest', () => {
    expect(typeof Logo).toBe('function')
  })
})

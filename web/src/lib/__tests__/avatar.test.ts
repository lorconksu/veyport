import { getAvatarColor, setAvatarColor, AVATAR_COLORS } from '../avatar'

describe('avatar', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  describe('AVATAR_COLORS', () => {
    it('exports an array of color strings', () => {
      expect(Array.isArray(AVATAR_COLORS)).toBe(true)
      expect(AVATAR_COLORS.length).toBeGreaterThan(0)
      for (const color of AVATAR_COLORS) {
        expect(color).toMatch(/^#[0-9a-f]{6}$/i)
      }
    })
  })

  describe('getAvatarColor', () => {
    it('returns a color from AVATAR_COLORS for a given username', () => {
      const color = getAvatarColor('admin')
      expect(AVATAR_COLORS).toContain(color)
    })

    it('is deterministic — same input yields same output', () => {
      const c1 = getAvatarColor('testuser')
      const c2 = getAvatarColor('testuser')
      expect(c1).toBe(c2)
    })

    it('returns different colors for different usernames (hash spread)', () => {
      const colors = new Set(['admin', 'bob', 'carol', 'dave', 'eve', 'frank', 'grace', 'heidi'].map(getAvatarColor))
      // At least 2 distinct colors out of 8 users
      expect(colors.size).toBeGreaterThan(1)
    })

    it('returns stored color from localStorage when valid', () => {
      const validColor = AVATAR_COLORS[2]
      localStorage.setItem('veyport_avatar_color', validColor)
      const result = getAvatarColor('admin')
      expect(result).toBe(validColor)
    })

    it('falls back to hash-derived color when stored color is not in AVATAR_COLORS', () => {
      localStorage.setItem('veyport_avatar_color', '#123456')
      const result = getAvatarColor('admin')
      expect(AVATAR_COLORS).toContain(result)
    })

    it('handles empty username without throwing', () => {
      const color = getAvatarColor('')
      expect(AVATAR_COLORS).toContain(color)
    })

    it('handles unicode username without throwing', () => {
      const color = getAvatarColor('用户名')
      expect(AVATAR_COLORS).toContain(color)
    })
  })

  describe('setAvatarColor', () => {
    it('stores the color in localStorage', () => {
      setAvatarColor('#3b82f6')
      expect(localStorage.getItem('veyport_avatar_color')).toBe('#3b82f6')
    })

    it('stored color is returned by getAvatarColor when valid', () => {
      const color = AVATAR_COLORS[0]
      setAvatarColor(color)
      expect(getAvatarColor('anyone')).toBe(color)
    })
  })
})

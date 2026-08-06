import type { FileNode } from '@/types/api'
import {
  decodeBase64Utf8,
  escapeHtml,
  extensionToLanguage,
  formatFileSize,
  highlightFileContent,
  isMarkdownFile,
  sortFileNodes,
} from '../file-viewer'

describe('file-viewer', () => {
  describe('formatFileSize', () => {
    it('formats bytes and larger units', () => {
      expect(formatFileSize(0)).toBe('0 B')
      expect(formatFileSize(512)).toBe('512 B')
      expect(formatFileSize(1536)).toBe('1.5 KB')
      expect(formatFileSize(1024 * 1024)).toBe('1.0 MB')
    })
  })

  describe('extensionToLanguage', () => {
    it('maps known extensions and Dockerfile names', () => {
      expect(extensionToLanguage('server.ts')).toBe('typescript')
      expect(extensionToLanguage('notes.md')).toBe('markdown')
      expect(extensionToLanguage('Dockerfile')).toBe('dockerfile')
      expect(extensionToLanguage('Dockerfile.prod')).toBe('dockerfile')
    })

    it('falls back to plaintext for unknown extensions', () => {
      expect(extensionToLanguage('archive.unknown')).toBe('plaintext')
    })
  })

  describe('isMarkdownFile', () => {
    it('detects markdown paths', () => {
      expect(isMarkdownFile('/docs/readme.md')).toBe(true)
      expect(isMarkdownFile('/docs/readme.MARKDOWN')).toBe(true)
      expect(isMarkdownFile('/docs/readme.txt')).toBe(false)
    })
  })

  describe('sortFileNodes', () => {
    it('sorts directories before files and then alphabetically', () => {
      const nodes: FileNode[] = [
        { name: 'zeta.txt', path: '/zeta.txt', is_dir: false, size: 1, readable: true },
        { name: 'alpha', path: '/alpha', is_dir: true, size: 0, readable: true },
        { name: 'beta', path: '/beta', is_dir: true, size: 0, readable: true },
        { name: 'aardvark.txt', path: '/aardvark.txt', is_dir: false, size: 1, readable: true },
      ]

      expect(sortFileNodes(nodes).map((node) => node.name)).toEqual([
        'alpha',
        'beta',
        'aardvark.txt',
        'zeta.txt',
      ])
    })
  })

  describe('decodeBase64Utf8', () => {
    it('decodes valid base64-encoded UTF-8', () => {
      expect(decodeBase64Utf8(btoa('hello world'))).toBe('hello world')
    })

    it('returns a fallback message for invalid base64', () => {
      expect(decodeBase64Utf8('%%%not-base64%%%')).toBe('[Unable to decode file content]')
    })

    it('returns null for empty content', () => {
      expect(decodeBase64Utf8(undefined)).toBeNull()
    })
  })

  describe('escapeHtml', () => {
    it('escapes special HTML characters', () => {
      expect(escapeHtml('<tag>&value>')).toBe('&lt;tag&gt;&amp;value&gt;')
    })
  })

  describe('highlightFileContent', () => {
    it('returns sanitized highlighted HTML for known file types', () => {
      const html = highlightFileContent('const value = 1', 'main.ts')
      expect(html).toContain('hljs-keyword')
      expect(html).toContain('const')
    })

    it('escapes unsafe content when rendering plaintext', () => {
      const html = highlightFileContent('<img src=x onerror=alert(1)>', 'notes.txt')
      expect(html).toContain('&lt;img')
      expect(html).not.toContain('<img')
    })
  })
})

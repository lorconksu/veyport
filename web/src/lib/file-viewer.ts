import DOMPurify from 'dompurify'
import hljs from 'highlight.js/lib/core'
import bash from 'highlight.js/lib/languages/bash'
import css from 'highlight.js/lib/languages/css'
import dockerfile from 'highlight.js/lib/languages/dockerfile'
import go from 'highlight.js/lib/languages/go'
import ini from 'highlight.js/lib/languages/ini'
import javascript from 'highlight.js/lib/languages/javascript'
import json from 'highlight.js/lib/languages/json'
import markdown from 'highlight.js/lib/languages/markdown'
import nginx from 'highlight.js/lib/languages/nginx'
import plaintext from 'highlight.js/lib/languages/plaintext'
import python from 'highlight.js/lib/languages/python'
import shell from 'highlight.js/lib/languages/shell'
import sql from 'highlight.js/lib/languages/sql'
import typescript from 'highlight.js/lib/languages/typescript'
import xml from 'highlight.js/lib/languages/xml'
import yaml from 'highlight.js/lib/languages/yaml'
import type { FileNode } from '@/types/api'

let languagesRegistered = false

function registerLanguageOnce(name: string, language: Parameters<typeof hljs.registerLanguage>[1]) {
  if (!hljs.getLanguage(name)) {
    hljs.registerLanguage(name, language)
  }
}

function ensureHighlightLanguagesRegistered() {
  if (languagesRegistered) return

  registerLanguageOnce('bash', bash)
  registerLanguageOnce('css', css)
  registerLanguageOnce('dockerfile', dockerfile)
  registerLanguageOnce('go', go)
  registerLanguageOnce('ini', ini)
  registerLanguageOnce('javascript', javascript)
  registerLanguageOnce('json', json)
  registerLanguageOnce('markdown', markdown)
  registerLanguageOnce('nginx', nginx)
  registerLanguageOnce('plaintext', plaintext)
  registerLanguageOnce('python', python)
  registerLanguageOnce('shell', shell)
  registerLanguageOnce('sql', sql)
  registerLanguageOnce('typescript', typescript)
  registerLanguageOnce('xml', xml)
  registerLanguageOnce('yaml', yaml)

  languagesRegistered = true
}

ensureHighlightLanguagesRegistered()

export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  const value = bytes / Math.pow(1024, i)
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

export function extensionToLanguage(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  const map: Record<string, string> = {
    js: 'javascript',
    jsx: 'javascript',
    ts: 'typescript',
    tsx: 'typescript',
    py: 'python',
    go: 'go',
    sh: 'bash',
    bash: 'bash',
    zsh: 'bash',
    json: 'json',
    yaml: 'yaml',
    yml: 'yaml',
    xml: 'xml',
    html: 'xml',
    htm: 'xml',
    svg: 'xml',
    css: 'css',
    scss: 'css',
    sql: 'sql',
    md: 'markdown',
    markdown: 'markdown',
    ini: 'ini',
    toml: 'ini',
    conf: 'ini',
    cfg: 'ini',
    properties: 'ini',
    dockerfile: 'dockerfile',
    nginx: 'nginx',
    log: 'plaintext',
    txt: 'plaintext',
    env: 'bash',
  }

  if (filename.toLowerCase() === 'dockerfile' || filename.toLowerCase().startsWith('dockerfile.')) {
    return 'dockerfile'
  }

  return map[ext] || 'plaintext'
}

export function isMarkdownFile(path: string): boolean {
  return /\.(md|markdown)$/i.test(path)
}

export function sortFileNodes(nodes: FileNode[]): FileNode[] {
  return [...nodes].sort((a, b) => {
    if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1
    return a.name.localeCompare(b.name)
  })
}

export function decodeBase64Utf8(content: string | null | undefined): string | null {
  if (!content) return null

  try {
    const bytes = Uint8Array.from(atob(content), (c) => c.codePointAt(0)!)
    return new TextDecoder('utf-8').decode(bytes)
  } catch {
    return '[Unable to decode file content]'
  }
}

function sanitizeHljsHtml(html: string): string {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['span'],
    ALLOWED_ATTR: ['class'],
  })
}

export function escapeHtml(text: string): string {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
}

export function highlightFileContent(content: string, filename: string): string {
  const language = extensionToLanguage(filename)

  try {
    const result = hljs.highlight(content, { language })
    return sanitizeHljsHtml(result.value)
  } catch {
    try {
      const result = hljs.highlight(content, { language: 'plaintext' })
      return sanitizeHljsHtml(result.value)
    } catch {
      return escapeHtml(content)
    }
  }
}

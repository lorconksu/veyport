import { useState, useEffect, useRef } from 'react'
import ReactMarkdown from 'react-markdown'
import type { Components } from 'react-markdown'
import remarkGfm from 'remark-gfm'
import mermaid from 'mermaid'
import DOMPurify from 'dompurify'
import hljs from 'highlight.js/lib/core'

// Initialize mermaid with dark theme
mermaid.initialize({
  startOnLoad: false,
  securityLevel: 'strict',
  theme: 'dark',
  themeVariables: {
    primaryColor: '#3b82f6',
    primaryTextColor: '#e0e0e0',
    lineColor: '#555',
    secondaryColor: '#1e293b',
    tertiaryColor: '#1a1a2e',
  },
})

/**
 * Sanitize highlight.js output (defense-in-depth).
 */
function sanitizeHljsHtml(html: string): string {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['span'],
    ALLOWED_ATTR: ['class'],
  })
}

function markdownChildrenToText(children: React.ReactNode): string {
  if (Array.isArray(children)) {
    return children.map(markdownChildrenToText).join('')
  }
  if (typeof children === 'string' || typeof children === 'number' || typeof children === 'boolean') {
    return String(children)
  }
  return ''
}

// Mermaid diagram component
/* c8 ignore start */
function MermaidDiagram({ chart }: Readonly<{ chart: string }>) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [svg, setSvg] = useState<string>('')
  const [error, setError] = useState<string>('')

  useEffect(() => {
    const id = `mermaid-${crypto.randomUUID()}`
    mermaid
      .render(id, chart)
      .then((result) => {
        // Sanitize SVG output with DOMPurify to prevent XSS from malicious mermaid blocks
        const sanitizedSvg = DOMPurify.sanitize(result.svg, {
          USE_PROFILES: { svg: true, svgFilters: true },
          ADD_TAGS: ['use'],
        })
        setSvg(sanitizedSvg)
      })
      .catch((err) => setError(String(err)))
  }, [chart])

  if (error) {
    return (
      <pre className="p-3 bg-base border border-border rounded-lg text-xs text-status-error overflow-x-auto">
        {error}
      </pre>
    )
  }
  return (
    <div
      ref={containerRef}
      className="my-4 flex justify-center overflow-x-auto"
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  )
}
/* c8 ignore stop */

// Custom code block renderer for ReactMarkdown — renders mermaid blocks as diagrams
/* c8 ignore start */
const markdownComponents: Components = {
  code({ className, children, ...props }) {
    const match = /language-(\w+)/.exec(className || '')
    const lang = match?.[1]
    const content = markdownChildrenToText(children).replace(/\n$/, '')

    if (lang === 'mermaid') {
      return <MermaidDiagram chart={content} />
    }

    // Inline code (no language class)
    if (!lang) {
      return <code className={className} {...props}>{content}</code>
    }

    // Block code — use highlight.js
    try {
      const hljsLang = hljs.getLanguage(lang) ? lang : 'plaintext'
      const result = hljs.highlight(content, { language: hljsLang })
      // Only sanitizeHljsHtml's DOMPurify span/class allowlist reaches this sink.
      // Markdown and highlighted source text are never rendered as raw HTML.
      return (
        <code
          className="hljs"
          dangerouslySetInnerHTML={{ /* nosemgrep: typescript.react.security.audit.react-dangerouslysetinnerhtml.react-dangerouslysetinnerhtml */ __html: sanitizeHljsHtml(result.value) }}
        />
      )
    } catch {
      return <code className={className} {...props}>{content}</code>
    }
  },
}
/* c8 ignore stop */

interface MarkdownViewerProps {
  content: string
}

export default function MarkdownViewer({ content }: Readonly<MarkdownViewerProps>) {
  return (
    <div className="markdown-body p-6">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={markdownComponents}>
        {content}
      </ReactMarkdown>
    </div>
  )
}

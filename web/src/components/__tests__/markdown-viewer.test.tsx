import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import mermaid from 'mermaid'
import hljs from 'highlight.js/lib/core'
import '@/lib/file-viewer'
import MarkdownViewer from '../markdown-viewer'

afterEach(() => {
  vi.restoreAllMocks()
})

function fencedCode(language: string, content: string) {
  return `\`\`\`${language}\n${content}\n\`\`\``
}

describe('MarkdownViewer', () => {
  it('renders headings, links, and GitHub-flavored Markdown', () => {
    render(<MarkdownViewer content={[
      '# Runbook',
      '[Documentation](https://example.com/docs)',
      '~~Retired~~',
      '| Command | Status |\n| --- | --- |\n| deploy | ready |',
      '- [x] Verified',
    ].join('\n\n')} />)

    expect(screen.getByRole('heading', { name: 'Runbook', level: 1 })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Documentation' })).toHaveAttribute('href', 'https://example.com/docs')
    expect(screen.getByText('Retired').tagName).toBe('DEL')
    expect(screen.getByRole('cell', { name: 'ready' })).toBeInTheDocument()
    expect(screen.getByRole('checkbox')).toBeChecked()
    expect(screen.getByRole('checkbox')).toBeDisabled()
  })

  it('keeps raw HTML literal and removes unsafe Markdown link destinations', () => {
    const content = '<img src=x onerror="alert(1)">\n\n[unsafe](javascript:alert%281%29)'
    const { container } = render(<MarkdownViewer content={content} />)

    expect(screen.getByText('<img src=x onerror="alert(1)">')).toBeInTheDocument()
    expect(screen.getByText('unsafe')).toHaveAttribute('href', '')
    expect(container.querySelector('img, script, [onerror]')).toBeNull()
  })

  it('renders inline and unlabelled code as literal text without highlighting', () => {
    const highlight = vi.spyOn(hljs, 'highlight')
    const { container } = render(<MarkdownViewer content={'Use `<tag>` here.\n\n' + fencedCode('', '  <img onerror="alert(1)">\n')} />)
    const code = container.querySelectorAll('code')

    expect(code).toHaveLength(2)
    expect(code[0]).toHaveTextContent('<tag>')
    expect(code[1].textContent).toBe('  <img onerror="alert(1)">\n')
    expect(container.querySelector('img')).toBeNull()
    expect(highlight).not.toHaveBeenCalled()
  })

  it('uses the supported highlighter for a known language and escapes HTML source', () => {
    const highlight = vi.spyOn(hljs, 'highlight')
    const source = 'const markup = "<img src=x onerror=alert(1)>";'
    const { container } = render(<MarkdownViewer content={fencedCode('javascript', source)} />)
    const code = container.querySelector('code')

    expect(highlight).toHaveBeenCalledWith(source, { language: 'javascript' })
    expect(code).toHaveClass('hljs')
    expect(code?.querySelector('.hljs-keyword')).toHaveTextContent('const')
    expect(code?.textContent).toBe(source)
    expect(container.querySelector('img, [onerror]')).toBeNull()
  })

  it('highlights an unknown language as plaintext without interpreting markup', () => {
    const highlight = vi.spyOn(hljs, 'highlight')
    const source = '<svg onload="alert(1)">& content</svg>'
    const { container } = render(<MarkdownViewer content={fencedCode('unknownlang', source)} />)

    expect(highlight).toHaveBeenCalledWith(source, { language: 'plaintext' })
    expect(container.querySelector('code')).toHaveClass('hljs')
    expect(container.querySelector('code')?.textContent).toBe(source)
    expect(container.querySelector('svg')).toBeNull()
  })

  it('sanitizes highlighter HTML while retaining span classes and escaped code', () => {
    const result = hljs.highlight('const value = 1', { language: 'javascript' })
    vi.spyOn(hljs, 'highlight').mockReturnValueOnce({
      ...result,
      value: '<span class="hljs-keyword" onclick="alert(1)" style="color:red" title="unsafe">const</span> '
        + '&lt;img src=x onerror=alert(1)&gt;'
        + '<img src=x onerror="alert(1)"><script>alert(1)</script>'
        + '<a href="javascript:alert(1)">link text</a>'
        + '<svg onload="alert(1)"><circle /></svg>',
    })
    const { container } = render(<MarkdownViewer content={fencedCode('javascript', 'const value = 1')} />)
    const code = container.querySelector('code')!

    expect(code.querySelector('span')).toHaveAttribute('class', 'hljs-keyword')
    expect(code.querySelector('span')?.getAttributeNames()).toEqual(['class'])
    expect(Array.from(code.querySelectorAll('*'), (element) => element.tagName)).toEqual(['SPAN'])
    expect(code.textContent).toBe('const <img src=x onerror=alert(1)>link text')
  })

  it('falls back to literal code if highlighting fails', () => {
    vi.spyOn(hljs, 'highlight').mockImplementationOnce(() => {
      throw new Error('highlighter unavailable')
    })
    const source = '<img src=x onerror="alert(1)">\nconst value = 1'
    const { container } = render(<MarkdownViewer content={fencedCode('javascript', source)} />)

    expect(container.querySelector('code')).toHaveClass('language-javascript')
    expect(container.querySelector('code')?.textContent).toBe(source)
    expect(container.querySelector('img')).toBeNull()
    expect(screen.queryByText('highlighter unavailable')).not.toBeInTheDocument()
  })

  it('sanitizes Mermaid SVG and retains diagram shapes, filters, and safe references', async () => {
    const chart = 'graph TD\nA --> B'
    const renderDiagram = vi.spyOn(mermaid, 'render').mockResolvedValueOnce({
      svg: '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">'
        + '<script>alert(1)</script><foreignObject><div>unsafe HTML</div></foreignObject>'
        + '<defs><circle id="node" r="4"/><filter id="blur"><feGaussianBlur stdDeviation="1"/></filter></defs>'
        + '<use href="#node"/><use href="javascript:alert(1)"/>'
        + '<g onclick="alert(1)"><path d="M0 0 L10 10"/><text>Safe diagram</text></g></svg>',
      bindFunctions: undefined,
    })
    const { container } = render(<MarkdownViewer content={fencedCode('mermaid', chart)} />)

    expect(await screen.findByText('Safe diagram')).toBeInTheDocument()
    expect(renderDiagram).toHaveBeenCalledWith(expect.stringMatching(/^mermaid-/), chart)
    const svg = container.querySelector('svg')!
    expect(svg).not.toHaveAttribute('onload')
    expect(svg.querySelector('circle')).toHaveAttribute('id', 'node')
    expect(svg.querySelector('filter feGaussianBlur')).toHaveAttribute('stdDeviation', '1')
    expect(svg.querySelector('path')).toHaveAttribute('d', 'M0 0 L10 10')
    expect(svg.querySelectorAll('use')).toHaveLength(2)
    expect(svg.querySelector('use')).toHaveAttribute('href', '#node')
    expect(svg.querySelectorAll('use')[1]).not.toHaveAttribute('href')
    expect(svg.querySelector('script, foreignObject, div, [onload], [onclick]')).toBeNull()
  })

  it.each([
    new Error('<img src=x onerror="alert(1)">'),
    '<svg onload="alert(1)">invalid chart</svg>',
  ])('displays Mermaid rejection as literal text: %s', async (error) => {
    vi.spyOn(mermaid, 'render').mockRejectedValueOnce(error)
    const { container } = render(<MarkdownViewer content={fencedCode('mermaid', 'invalid chart')} />)

    const message = await screen.findByText(String(error))
    expect(message.tagName).toBe('PRE')
    expect(message).toHaveClass('text-status-error')
    expect(message.textContent).toBe(String(error))
    expect(container.querySelector('img, svg, [onerror], [onload]')).toBeNull()
  })

  it('renders updated Mermaid source with a new diagram ID', async () => {
    const renderDiagram = vi.spyOn(mermaid, 'render')
      .mockResolvedValueOnce({ svg: '<svg><text>First diagram</text></svg>', bindFunctions: undefined })
      .mockResolvedValueOnce({ svg: '<svg><text>Updated diagram</text></svg>', bindFunctions: undefined })
    const { rerender } = render(<MarkdownViewer content={fencedCode('mermaid', 'graph TD\nA --> B')} />)
    expect(await screen.findByText('First diagram')).toBeInTheDocument()

    rerender(<MarkdownViewer content={fencedCode('mermaid', 'graph TD\nB --> C')} />)

    expect(await screen.findByText('Updated diagram')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('First diagram')).not.toBeInTheDocument())
    expect(renderDiagram).toHaveBeenNthCalledWith(2, expect.stringMatching(/^mermaid-/), 'graph TD\nB --> C')
    expect(renderDiagram.mock.calls[0][0]).not.toBe(renderDiagram.mock.calls[1][0])
  })
})

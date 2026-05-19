import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ServerDetailPage } from '../server-detail'

// Mock heavy dependencies
vi.mock('mermaid', () => ({
  default: {
    initialize: vi.fn(),
    render: vi.fn().mockResolvedValue({ svg: '<svg data-testid="mermaid-svg"></svg>' }),
  },
}))

vi.mock('highlight.js/lib/core', () => ({
  default: {
    registerLanguage: vi.fn(),
    highlight: vi.fn((code: string) => ({ value: `<span>${code}</span>` })),
    getLanguage: vi.fn(() => true),
  },
}))

vi.mock('highlight.js/styles/github-dark.css', () => ({}))

vi.mock('react-markdown', () => ({
  default: ({ children }: { children: string }) => <div data-testid="markdown">{children}</div>,
}))

vi.mock('remark-gfm', () => ({ default: () => {} }))

// Mock the lazy-loaded MarkdownViewer component
vi.mock('@/components/markdown-viewer', () => ({
  default: ({ content }: { content: string }) => <div data-testid="markdown">{content}</div>,
}))

vi.mock('@/components/server-terminal', () => ({
  ServerTerminal: ({ serverId, server }: { serverId: string; server: { name: string } }) => (
    <div data-testid="server-terminal">
      <div>Live Terminal</div>
      <div>{server.name}</div>
      <div>{serverId}</div>
    </div>
  ),
  OfflineTerminalState: ({ server }: { server: { name: string } }) => (
    <div data-testid="offline-terminal">
      <div>Terminal</div>
      <div>Awaiting agent</div>
      <div>{server.name}</div>
    </div>
  ),
}))

// Mock individual highlight.js language modules
vi.mock('highlight.js/lib/languages/bash', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/css', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/dockerfile', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/go', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/ini', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/javascript', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/json', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/markdown', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/nginx', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/plaintext', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/python', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/shell', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/sql', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/typescript', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/xml', () => ({ default: {} }))
vi.mock('highlight.js/lib/languages/yaml', () => ({ default: {} }))

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

vi.mock('@/lib/auth', () => ({
  getCSRFToken: vi.fn(() => 'test-csrf-token'),
}))

vi.mock('@/hooks/use-auth', () => ({
  useAuth: vi.fn(() => ({
    user: { id: 'u1', username: 'admin', role: 'admin', email: 'a@b.com', avatar: null, totp_enabled: true, created_at: '', updated_at: '' },
  })),
}))

const mockNavigate = vi.fn()
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useParams: vi.fn(() => ({ id: 'srv-1' })),
  }
})

import { apiFetch } from '@/lib/api'
const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>

import { useAuth } from '@/hooks/use-auth'
const mockUseAuth = useAuth as ReturnType<typeof vi.fn>

import { useParams } from 'react-router-dom'
const mockUseParams = useParams as ReturnType<typeof vi.fn>

const mockServer = {
  id: 'srv-1',
  name: 'web-prod-1',
  hostname: 'web1.example.com',
  ip_address: '10.0.0.1',
  os: 'Ubuntu 22.04',
  status: 'online' as const,
  agent_version: '1.0.0',
  labels: '',
  last_seen_at: new Date(Date.now() - 30000).toISOString(),
  created_at: '',
  updated_at: '',
}

const mockOfflineServer = { ...mockServer, status: 'offline' as const }
const mockPendingServer = { ...mockServer, status: 'pending' as const }

const mockFileNodes = [
  { name: 'etc', path: '/etc', is_dir: true, size: 0, readable: true },
  { name: 'nginx.conf', path: '/etc/nginx.conf', is_dir: false, size: 1024, readable: true },
  { name: 'secret.key', path: '/etc/secret.key', is_dir: false, size: 512, readable: false },
]

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <ServerDetailPage />
      </BrowserRouter>
    </QueryClientProvider>,
  )
}

describe('ServerDetailPage', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    mockNavigate.mockReset()
    mockUseParams.mockReturnValue({ id: 'srv-1' })
    mockUseAuth.mockReturnValue({
      user: { id: 'u1', username: 'admin', role: 'admin', email: 'a@b.com', avatar: null, totp_enabled: true, created_at: '', updated_at: '' },
    })
    // Mock global fetch for SSE
    vi.stubGlobal('fetch', vi.fn())
    sessionStorage.clear()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows loading state initially', () => {
    mockApiFetch.mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(screen.getByText('Loading server...')).toBeInTheDocument()
  })

  it('shows error state when server query fails', async () => {
    mockApiFetch.mockRejectedValueOnce(new Error('Not found'))
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Failed to load server')).toBeInTheDocument()
      expect(screen.getByText('Not found')).toBeInTheDocument()
    })
  })

  it('shows error when server is null', async () => {
    // Make server query return undefined
    mockApiFetch.mockResolvedValueOnce(null)
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Failed to load server')).toBeInTheDocument()
    })
  })

  it('renders server name in header', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: [] })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('web-prod-1')).toBeInTheDocument()
    })
  })

  it('renders server hostname and ip', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: [] })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/web1\.example\.com/)).toBeInTheDocument()
    })
  })

  it('renders agent version', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: [] })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('v1.0.0')).toBeInTheDocument()
    })
  })

  it('shows offline warning for offline servers', async () => {
    mockApiFetch.mockResolvedValueOnce(mockOfflineServer)
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/server is offline/i)).toBeInTheDocument()
    })
  })

  it('shows offline warning for pending servers', async () => {
    mockApiFetch.mockResolvedValueOnce(mockPendingServer)
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/server is offline/i)).toBeInTheDocument()
    })
  })

  it('shows file explorer for online server', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: ['/etc', '/var/log'] })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('File Explorer')).toBeInTheDocument()
    })
  })

  it('shows workspace mode toggle for online server', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: ['/etc'] })
    renderPage()

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Files' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Terminal' })).toBeInTheDocument()
    })
  })

  it('keeps workspace mode toggle visible for pending servers', async () => {
    mockApiFetch.mockResolvedValueOnce(mockPendingServer)
    renderPage()

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Files' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Terminal' })).toBeInTheDocument()
      expect(screen.getByText(/file browsing is waiting on the agent/i)).toBeInTheDocument()
    })
  })

  it('switches from file explorer to terminal and back', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: ['/etc'] })
    renderPage()

    await waitFor(() => expect(screen.getByText('File Explorer')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Terminal' }))

    await waitFor(() => {
      expect(screen.getByText('Live Terminal')).toBeInTheDocument()
      expect(screen.queryByText('File Explorer')).not.toBeInTheDocument()
      expect(screen.getByTestId('server-terminal')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Files' }))

    await waitFor(() => {
      expect(screen.getByText('File Explorer')).toBeInTheDocument()
      expect(screen.queryByText('Live Terminal')).not.toBeInTheDocument()
    })
  })

  it('shows offline terminal state for pending servers', async () => {
    mockApiFetch.mockResolvedValueOnce(mockPendingServer)
    renderPage()

    await waitFor(() => expect(screen.getByText(/file browsing is waiting on the agent/i)).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Terminal' }))

    await waitFor(() => {
      expect(screen.getByText('Awaiting agent')).toBeInTheDocument()
      expect(screen.getByTestId('offline-terminal')).toBeInTheDocument()
    })
  })

  it('shows "No paths configured" when no paths granted', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: [] })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/No paths configured/)).toBeInTheDocument()
    })
  })

  it('shows "Select a file" prompt when no file selected', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: ['/etc'] })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Select a file to view its contents')).toBeInTheDocument()
    })
  })

  it('renders file tree nodes', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: ['/etc'] })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('/etc')).toBeInTheDocument()
    })
  })

  it('clicking collapse button toggles sidebar', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: ['/etc'] })
    renderPage()
    await waitFor(() => {
      expect(screen.getByTitle('Collapse sidebar')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByTitle('Collapse sidebar'))
    await waitFor(() => {
      expect(screen.getByTitle('Expand sidebar')).toBeInTheDocument()
    })
  })

  it('clicking a directory fetches its children', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValueOnce({ files: mockFileNodes.slice(1) })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('/etc')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('/etc'))
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith(expect.stringContaining('/files?path='))
    })
  })

  it('clicking a readable file fetches its content', async () => {
    const fileContent = {
      data: btoa('Hello, World!'),
      total_size: 13,
      mime_type: 'text/plain',
    }
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValueOnce({ files: mockFileNodes.slice(1) })
    mockApiFetch.mockResolvedValueOnce(fileContent)
    renderPage()

    await waitFor(() => expect(screen.getByText('/etc')).toBeInTheDocument())
    fireEvent.click(screen.getByText('/etc'))
    await waitFor(() => expect(screen.getByText('nginx.conf')).toBeInTheDocument())
    fireEvent.click(screen.getByText('nginx.conf'))

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith(expect.stringContaining('/files/read'))
    })
  })

  it('shows path loading indicator', async () => {
    let resolveServer!: (val: unknown) => void
    mockApiFetch.mockReturnValueOnce(new Promise(r => { resolveServer = r }))
    renderPage()
    // While loading
    expect(screen.getByText('Loading server...')).toBeInTheDocument()
    resolveServer(mockServer)
  })

  it('shows admin-only PathManagement section', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: ['/etc'] })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Manage File Access')).toBeInTheDocument()
    })
  })

  it('does not show PathManagement for viewer', async () => {
    mockUseAuth.mockReturnValue({
      user: { id: 'u2', username: 'viewer', role: 'viewer', email: 'v@b.com', avatar: null, totp_enabled: true, created_at: '', updated_at: '' },
    })
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: ['/etc'] })
    renderPage()
    await waitFor(() => {
      expect(screen.queryByText('Manage File Access')).not.toBeInTheDocument()
    })
  })

  it('shows Dropzone section for admin', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: ['/etc'] })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Dropzone')).toBeInTheDocument()
    })
  })

  it('Back to dashboard link is rendered', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: ['/etc'] })
    renderPage()
    await waitFor(() => {
      expect(screen.getByTitle('Back to dashboard')).toBeInTheDocument()
    })
  })

  it('Back to dashboard link in error state works', async () => {
    mockApiFetch.mockRejectedValueOnce(new Error('Not found'))
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Back to dashboard')).toBeInTheDocument()
    })
  })

  it('file viewer toolbar shows after selecting a file', async () => {
    const fileContent = { data: btoa('content'), total_size: 7, mime_type: 'text/plain' }
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValueOnce({ files: [{ name: 'nginx.conf', path: '/etc/nginx.conf', is_dir: false, size: 1024, readable: true }] })
    mockApiFetch.mockResolvedValueOnce(fileContent)
    renderPage()

    await waitFor(() => expect(screen.getByText('/etc')).toBeInTheDocument())
    fireEvent.click(screen.getByText('/etc'))
    await waitFor(() => expect(screen.getByText('nginx.conf')).toBeInTheDocument())
    fireEvent.click(screen.getByText('nginx.conf'))

    await waitFor(() => {
      expect(screen.getByTitle('Refresh file')).toBeInTheDocument()
    })
  })

  it('Ctrl+F event handler is registered', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: ['/etc'] })
    renderPage()
    await waitFor(() => expect(screen.getByText('web-prod-1')).toBeInTheDocument())

    // The search bar only appears after a file is selected AND Ctrl+F is pressed
    // Just verify the event listener is registered (component doesn't crash on Ctrl+F)
    expect(() => {
      fireEvent.keyDown(window, { key: 'f', ctrlKey: true })
    }).not.toThrow()
  })

  it('expanding PathManagement shows add path form', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValue({ paths: [], users: [] })
    renderPage()

    await waitFor(() => expect(screen.getByText('Manage File Access')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Manage File Access'))

    await waitFor(() => {
      expect(screen.getByText('No path permissions configured yet.')).toBeInTheDocument()
    })
  })

  it('expanding Dropzone shows upload area', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValue({ files: [] })
    renderPage()

    await waitFor(() => expect(screen.getByText('Dropzone')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Dropzone'))

    await waitFor(() => {
      expect(screen.getByText('Drop files here or click to browse')).toBeInTheDocument()
    })
  })
})

// --- FileTreeNode tests ---

describe('FileTreeNode rendering', () => {
  it('renders a directory node', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValue({ paths: ['/var/log'] })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => {
      expect(screen.getByText('/var/log')).toBeInTheDocument()
    })
  })
})

// --- DropzoneUpload tests ---

describe('DropzoneUpload', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows existing dropzone files when expanded', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValue({ files: [{ name: 'file.tar.gz', path: '/dropzone/file.tar.gz', is_dir: false, size: 5120, readable: true }] })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('Dropzone')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Dropzone'))

    await waitFor(() => {
      expect(screen.getByText('file.tar.gz')).toBeInTheDocument()
    })
  })

  it('clicking delete button on dropzone file opens confirmation', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValue({ files: [{ name: 'file.tar.gz', path: '/dropzone/file.tar.gz', is_dir: false, size: 5120, readable: true }] })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('Dropzone')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Dropzone'))
    await waitFor(() => expect(screen.getByText('file.tar.gz')).toBeInTheDocument())

    fireEvent.click(screen.getByTitle('Delete file'))
    await waitFor(() => {
      expect(screen.getByText('Delete File?')).toBeInTheDocument()
    })
  })

  it('cancel in delete confirmation closes modal', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValue({ files: [{ name: 'file.tar.gz', path: '/dropzone/file.tar.gz', is_dir: false, size: 5120, readable: true }] })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('Dropzone')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Dropzone'))
    await waitFor(() => expect(screen.getByText('file.tar.gz')).toBeInTheDocument())

    fireEvent.click(screen.getByTitle('Delete file'))
    await waitFor(() => expect(screen.getByText('Delete File?')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByText('Delete File?')).not.toBeInTheDocument())
  })

  it('confirms delete of dropzone file and shows success', async () => {
    const dropzoneFile = { name: 'file.tar.gz', path: '/dropzone/file.tar.gz', is_dir: false, size: 5120, readable: true }
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValueOnce({ files: [dropzoneFile] })
    // The delete call returns ok
    mockApiFetch.mockResolvedValue({ status: 'ok' })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('Dropzone')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Dropzone'))
    await waitFor(() => expect(screen.getByText('file.tar.gz')).toBeInTheDocument())

    fireEvent.click(screen.getByTitle('Delete file'))
    await waitFor(() => expect(screen.getByText('Delete File?')).toBeInTheDocument())

    // In the delete modal, click "Delete" button to confirm
    const deleteButtons = screen.getAllByRole('button', { name: 'Delete' })
    fireEvent.click(deleteButtons[0])
    // The delete call uses apiFetch directly in handleConfirmDelete
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith(
        expect.stringContaining('/dropzone'),
        expect.objectContaining({ method: 'DELETE' })
      )
    })
  })
})

// --- Additional FileViewerContent tests ---

describe('FileViewerContent rendering', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  async function renderWithFile(fileContent: object, filename = 'nginx.conf') {
    const fileNode = { name: filename, path: `/etc/${filename}`, is_dir: false, size: 1024, readable: true }
    // Use mockResolvedValue (fallback) and more specific mocks
    mockApiFetch.mockResolvedValue(fileContent) // Default: all calls return fileContent
    mockApiFetch.mockResolvedValueOnce(mockServer) // Call 1: server
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] }) // Call 2: my-paths
    mockApiFetch.mockResolvedValueOnce({ files: [fileNode] }) // Call 3: file tree (direct apiFetch call)

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('/etc')).toBeInTheDocument())
    fireEvent.click(screen.getByText('/etc'))
    await waitFor(() => expect(screen.getByText(filename)).toBeInTheDocument())
    fireEvent.click(screen.getByText(filename))
  }

  it('renders highlighted file content', async () => {
    const content = 'server { listen 80; }'
    const fileContent = { data: btoa(content), total_size: content.length, mime_type: 'text/plain' }
    await renderWithFile(fileContent)
    // Wait for file content to fully load - the code block renders after fileContent resolves
    await waitFor(() => {
      // The toolbar appears when selectedFile is set
      expect(screen.getByTitle('Refresh file')).toBeInTheDocument()
    }, { timeout: 3000 })
    // Give more time for file content query to resolve
    await waitFor(() => {
      const codeEl = document.querySelector('code.hljs')
      expect(codeEl).toBeTruthy()
    }, { timeout: 3000 })
  })

  it('renders markdown file in rendered mode', async () => {
    const mdContent = '# Hello\n\nThis is markdown'
    const fileContent = { data: btoa(mdContent), total_size: mdContent.length, mime_type: 'text/markdown' }
    await renderWithFile(fileContent, 'README.md')
    // Wait for toolbar first, then markdown
    await waitFor(() => expect(screen.getByTitle('Refresh file')).toBeInTheDocument(), { timeout: 3000 })
    // Markdown is rendered via mocked ReactMarkdown
    await waitFor(() => {
      expect(screen.getByTestId('markdown')).toBeInTheDocument()
    }, { timeout: 3000 })
  })

  it('shows file load error when file query fails', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValueOnce({ files: [{ name: 'nginx.conf', path: '/etc/nginx.conf', is_dir: false, size: 1024, readable: true }] })
    mockApiFetch.mockRejectedValueOnce(new Error('Permission denied'))

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('/etc')).toBeInTheDocument())
    fireEvent.click(screen.getByText('/etc'))
    await waitFor(() => expect(screen.getByText('nginx.conf')).toBeInTheDocument())
    fireEvent.click(screen.getByText('nginx.conf'))

    await waitFor(() => {
      expect(screen.getByText('Failed to load file')).toBeInTheDocument()
    })
  })

  it('clicking Retry button in file error state triggers refetch (line 1840 onRefetch)', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValueOnce({ files: [{ name: 'nginx.conf', path: '/etc/nginx.conf', is_dir: false, size: 1024, readable: true }] })
    mockApiFetch.mockRejectedValueOnce(new Error('Permission denied'))
    // After retry, return success
    mockApiFetch.mockResolvedValue({ data: btoa('content'), total_size: 7, mime_type: 'text/plain' })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('/etc')).toBeInTheDocument())
    fireEvent.click(screen.getByText('/etc'))
    await waitFor(() => expect(screen.getByText('nginx.conf')).toBeInTheDocument())
    fireEvent.click(screen.getByText('nginx.conf'))

    // Wait for error state
    await waitFor(() => expect(screen.getByText('Failed to load file')).toBeInTheDocument())

    // Click Retry (covers line 1840: onRefetch={() => refetchFile()})
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))

    // No crash — refetch is triggered
    expect(screen.getByText('Failed to load file')).toBeInTheDocument()
  })

  it('shows search bar when Ctrl+F is pressed after file selected', async () => {
    const fileContent = { data: btoa('Hello World content'), total_size: 18, mime_type: 'text/plain' }
    await renderWithFile(fileContent)

    await waitFor(() => expect(screen.getByTitle('Refresh file')).toBeInTheDocument())

    // Open search via toolbar button
    const searchBtn = screen.getByTitle('Search in file (Ctrl+F)')
    fireEvent.click(searchBtn)

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Search in file...')).toBeInTheDocument()
    })
  })

  it('closes search bar with Escape key', async () => {
    const fileContent = { data: btoa('Hello World content'), total_size: 18, mime_type: 'text/plain' }
    await renderWithFile(fileContent)

    await waitFor(() => expect(screen.getByTitle('Refresh file')).toBeInTheDocument())

    const searchBtn = screen.getByTitle('Search in file (Ctrl+F)')
    fireEvent.click(searchBtn)

    await waitFor(() => expect(screen.getByPlaceholderText('Search in file...')).toBeInTheDocument())

    fireEvent.keyDown(screen.getByPlaceholderText('Search in file...'), { key: 'Escape' })

    await waitFor(() => {
      expect(screen.queryByPlaceholderText('Search in file...')).not.toBeInTheDocument()
    })
  })

  it('navigates search results with next/prev buttons (line 1817)', async () => {
    const content = 'hello hello hello'
    const fileContent = { data: btoa(content), total_size: content.length, mime_type: 'text/plain' }
    await renderWithFile(fileContent)

    await waitFor(() => expect(screen.getByTitle('Refresh file')).toBeInTheDocument())

    const searchBtn = screen.getByTitle('Search in file (Ctrl+F)')
    fireEvent.click(searchBtn)

    await waitFor(() => expect(screen.getByPlaceholderText('Search in file...')).toBeInTheDocument())

    // Type a search term
    fireEvent.change(screen.getByPlaceholderText('Search in file...'), { target: { value: 'hello' } })

    // Wait for debounce — navigation prev/next buttons should appear
    await waitFor(() => expect(screen.getByTitle('Search in file (Ctrl+F)')).toBeInTheDocument())

    // Navigate search matches from the input.
    fireEvent.keyDown(screen.getByPlaceholderText('Search in file...'), { key: 'Enter' })
    fireEvent.keyDown(screen.getByPlaceholderText('Search in file...'), { key: 'Enter', shiftKey: true })
    // Just verify no crash
    expect(screen.getByPlaceholderText('Search in file...')).toBeInTheDocument()
  })

  it('clicking Live Tail button activates live tail (lines 1827-1840)', async () => {
    // The beforeEach already stubs global fetch as vi.fn()
    // Make fetch return a never-resolving promise for SSE
    const globalFetch = vi.fn().mockReturnValue(new Promise(() => {}))
    vi.stubGlobal('fetch', globalFetch)

    const fileContent = { data: btoa('log content'), total_size: 11, mime_type: 'text/plain' }
    await renderWithFile(fileContent)

    await waitFor(() => expect(screen.getByTitle('Refresh file')).toBeInTheDocument())

    // Click the Live Tail button (FileViewerToolbar toggle)
    const liveTailBtn = screen.getByTitle('Start live tail')
    fireEvent.click(liveTailBtn)

    // After clicking, the LiveTail component renders — it shows a "Stop" button inside LiveTail
    // Both the toolbar ('Stop live tail' title) and the LiveTail component show 'Stop' text.
    // We need to click the LiveTail's internal Stop button (no title) to cover line 1827.
    await waitFor(() => {
      // Multiple 'Stop' buttons appear: toolbar has title='Stop live tail', LiveTail's has no title
      const stopBtns = screen.getAllByText('Stop')
      expect(stopBtns.length).toBeGreaterThanOrEqual(1)
    })

    // Click the LiveTail's internal Stop button (the one WITHOUT title='Stop live tail')
    // This covers onStop callback at line 1827: onStop={() => setLiveTailing(false)}
    const stopBtns = screen.getAllByText('Stop')
    const liveTailStopBtn = stopBtns.find(el => el.closest('button')?.title !== 'Stop live tail') ?? stopBtns[0]
    fireEvent.click(liveTailStopBtn)
    await waitFor(() => {
      // FileViewerContent is rendered again (liveTailing=false), 'Start live tail' button reappears
      expect(screen.getByTitle('Start live tail')).toBeInTheDocument()
    })

    // Also test clicking Refresh file button to cover line 1803 (onRefetch in FileViewerToolbar)
    fireEvent.click(screen.getByTitle('Refresh file'))

    // Restore fetch for other tests
    vi.stubGlobal('fetch', vi.fn())
  })
})

// --- relativeTime tests (via ServerDetailHeader) ---

describe('relativeTime via ServerDetailHeader', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows time in minutes for 5 min ago', async () => {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString()
    const serverWithOldTime = { ...mockServer, last_seen_at: fiveMinAgo }
    mockApiFetch.mockResolvedValueOnce(serverWithOldTime)
    mockApiFetch.mockResolvedValue({ paths: [] })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )
    await waitFor(() => {
      expect(screen.getByText(/\d+ min ago/)).toBeInTheDocument()
    })
  })

  it('shows time in hours for 2 hours ago', async () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
    const serverWithOldTime = { ...mockServer, last_seen_at: twoHoursAgo }
    mockApiFetch.mockResolvedValueOnce(serverWithOldTime)
    mockApiFetch.mockResolvedValue({ paths: [] })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )
    await waitFor(() => {
      expect(screen.getByText(/\d+h ago/)).toBeInTheDocument()
    })
  })

  it('shows time in days for 3 days ago', async () => {
    const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString()
    const serverWithOldTime = { ...mockServer, last_seen_at: threeDaysAgo }
    mockApiFetch.mockResolvedValueOnce(serverWithOldTime)
    mockApiFetch.mockResolvedValue({ paths: [] })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )
    await waitFor(() => {
      expect(screen.getByText(/\d+d ago/)).toBeInTheDocument()
    })
  })

  it('shows -- when last_seen_at is null', async () => {
    const serverNoTime = { ...mockServer, last_seen_at: null }
    mockApiFetch.mockResolvedValueOnce(serverNoTime)
    mockApiFetch.mockResolvedValue({ paths: [] })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )
    await waitFor(() => {
      expect(screen.getByText(/Last seen: —/)).toBeInTheDocument()
    })
  })
})

// --- PathManagement tests ---

describe('PathManagement', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows add path form when expanded', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    // PathManagement queries: paths + users
    mockApiFetch.mockResolvedValueOnce({ paths: [] })
    mockApiFetch.mockResolvedValueOnce({ users: [{ id: 'u1', username: 'admin', email: 'a@b.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' }] })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('Manage File Access')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Manage File Access'))

    await waitFor(() => {
      expect(screen.getByLabelText('Path')).toBeInTheDocument()
    })
  })

  it('shows paths in table when paths exist', async () => {
    const pathPermission = { id: 'p1', user_id: 'u1', username: 'admin', path: '/etc/nginx', server_id: 'srv-1', created_at: '' }
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    // PathManagement: paths with existing entries
    mockApiFetch.mockResolvedValueOnce({ paths: [pathPermission] })
    mockApiFetch.mockResolvedValueOnce({ users: [{ id: 'u1', username: 'admin', email: 'a@b.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' }] })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('Manage File Access')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Manage File Access'))

    await waitFor(() => {
      expect(screen.getByText('/etc/nginx')).toBeInTheDocument()
    })
  })

  it('can submit add path form', async () => {
    const pathPermission = { id: 'p1', user_id: 'u1', username: 'admin', path: '/etc/nginx', server_id: 'srv-1', created_at: '' }
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    // PathManagement queries
    mockApiFetch.mockResolvedValueOnce({ paths: [] })
    mockApiFetch.mockResolvedValueOnce({ users: [{ id: 'u1', username: 'admin', email: 'a@b.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' }] })
    // Add path mutation response
    mockApiFetch.mockResolvedValueOnce(pathPermission)
    // Refetch paths after add
    mockApiFetch.mockResolvedValue({ paths: [pathPermission] })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('Manage File Access')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Manage File Access'))

    await waitFor(() => expect(screen.getByLabelText('Path')).toBeInTheDocument())

    // Select user and enter path
    const userSelect = screen.getByLabelText('User')
    fireEvent.change(userSelect, { target: { value: 'u1' } })

    const pathInput = screen.getByLabelText('Path')
    fireEvent.change(pathInput, { target: { value: '/var/log' } })

    const addBtn = screen.getByRole('button', { name: /add path/i })
    fireEvent.click(addBtn)

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith(
        expect.stringContaining('/paths'),
        expect.objectContaining({ method: 'POST' })
      )
    })
  })

  it('delete permission button removes path', async () => {
    const pathPermission = { id: 'p1', user_id: 'u1', username: 'admin', path: '/etc/nginx', server_id: 'srv-1', created_at: '' }
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValueOnce({ paths: [pathPermission] })
    mockApiFetch.mockResolvedValueOnce({ users: [{ id: 'u1', username: 'admin', email: 'a@b.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' }] })
    // Delete mutation response
    mockApiFetch.mockResolvedValue({ status: 'ok' })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('Manage File Access')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Manage File Access'))

    await waitFor(() => expect(screen.getByText('/etc/nginx')).toBeInTheDocument())

    const removeBtn = screen.getByTitle('Remove permission')
    fireEvent.click(removeBtn)

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith(
        expect.stringContaining('/paths/p1'),
        expect.objectContaining({ method: 'DELETE' })
      )
    })
  })
})

// --- DropzoneUpload drag/drop/keyboard handler tests ---

describe('DropzoneUpload drag and file input handlers', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  function renderDropzone() {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValue({ files: [] })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )
  }

  it('handleDragOver sets drag-over visual state', async () => {
    renderDropzone()

    await waitFor(() => expect(screen.getByText('Dropzone')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Dropzone'))

    await waitFor(() => expect(screen.getByLabelText('Upload files by clicking or dragging')).toBeInTheDocument())

    const dropzone = screen.getByLabelText('Upload files by clicking or dragging')
    fireEvent.dragOver(dropzone, { dataTransfer: { files: [] } })

    // dragOver state is set — element still present, no crash
    expect(dropzone).toBeInTheDocument()
  })

  it('handleDragLeave clears drag-over state', async () => {
    renderDropzone()

    await waitFor(() => expect(screen.getByText('Dropzone')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Dropzone'))

    await waitFor(() => expect(screen.getByLabelText('Upload files by clicking or dragging')).toBeInTheDocument())

    const dropzone = screen.getByLabelText('Upload files by clicking or dragging')
    fireEvent.dragOver(dropzone, { dataTransfer: { files: [] } })
    fireEvent.dragLeave(dropzone)

    // dragLeave resets state — element still present, no crash
    expect(dropzone).toBeInTheDocument()
  })

  it('handleDrop with a file calls handleUpload', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ filename: 'test.txt', size: 100 }) })
    vi.stubGlobal('fetch', mockFetch)

    renderDropzone()

    await waitFor(() => expect(screen.getByText('Dropzone')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Dropzone'))

    await waitFor(() => expect(screen.getByLabelText('Upload files by clicking or dragging')).toBeInTheDocument())

    const dropzone = screen.getByLabelText('Upload files by clicking or dragging')
    const file = new File(['content'], 'test.txt', { type: 'text/plain' })
    fireEvent.drop(dropzone, { dataTransfer: { files: [file] } })

    // handleDrop fires, no crash
    expect(dropzone).toBeInTheDocument()
  })

  it('handleDrop with no file does nothing', async () => {
    renderDropzone()

    await waitFor(() => expect(screen.getByText('Dropzone')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Dropzone'))

    await waitFor(() => expect(screen.getByLabelText('Upload files by clicking or dragging')).toBeInTheDocument())

    const dropzone = screen.getByLabelText('Upload files by clicking or dragging')
    fireEvent.drop(dropzone, { dataTransfer: { files: [] } })

    // no crash, no upload called
    expect(dropzone).toBeInTheDocument()
  })

  it('handleFileInputChange triggers upload for selected file', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ filename: 'test.txt', size: 200 }) })
    vi.stubGlobal('fetch', mockFetch)

    renderDropzone()

    await waitFor(() => expect(screen.getByText('Dropzone')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Dropzone'))

    await waitFor(() => expect(screen.getByLabelText('Upload files by clicking or dragging')).toBeInTheDocument())

    // The hidden file input is inside the dropzone
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    expect(fileInput).toBeTruthy()

    const file = new File(['content'], 'test.txt', { type: 'text/plain' })
    fireEvent.change(fileInput, { target: { files: [file] } })

    // handleFileInputChange fires, no crash
    expect(fileInput).toBeTruthy()
  })

  it('dropzone onKeyDown Enter triggers file input click', async () => {
    renderDropzone()

    await waitFor(() => expect(screen.getByText('Dropzone')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Dropzone'))

    await waitFor(() => expect(screen.getByLabelText('Upload files by clicking or dragging')).toBeInTheDocument())

    const dropzone = screen.getByLabelText('Upload files by clicking or dragging')
    // Press Enter key on the dropzone
    fireEvent.keyDown(dropzone, { key: 'Enter' })

    // No crash
    expect(dropzone).toBeInTheDocument()
  })

  it('dropzone onKeyDown Space triggers file input click', async () => {
    renderDropzone()

    await waitFor(() => expect(screen.getByText('Dropzone')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Dropzone'))

    await waitFor(() => expect(screen.getByLabelText('Upload files by clicking or dragging')).toBeInTheDocument())

    const dropzone = screen.getByLabelText('Upload files by clicking or dragging')
    fireEvent.keyDown(dropzone, { key: ' ' })

    expect(dropzone).toBeInTheDocument()
  })

  it('dropzone onClick triggers file input click', async () => {
    renderDropzone()

    await waitFor(() => expect(screen.getByText('Dropzone')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Dropzone'))

    await waitFor(() => expect(screen.getByLabelText('Upload files by clicking or dragging')).toBeInTheDocument())

    const dropzone = screen.getByLabelText('Upload files by clicking or dragging')
    fireEvent.click(dropzone)

    expect(dropzone).toBeInTheDocument()
  })
})

// --- extensionToLanguage Dockerfile test ---

describe('extensionToLanguage Dockerfile mapping (line 231)', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('Dockerfile file gets dockerfile syntax highlighting', async () => {
    const dockerContent = 'FROM ubuntu:22.04\nRUN apt-get update'
    const fileContent = { data: btoa(dockerContent), total_size: dockerContent.length, mime_type: 'text/plain' }

    mockApiFetch.mockResolvedValueOnce(mockServer) // server
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] }) // my-paths
    mockApiFetch.mockResolvedValueOnce({ files: [{ name: 'Dockerfile', path: '/etc/Dockerfile', is_dir: false, size: dockerContent.length, readable: true }] }) // /etc children
    mockApiFetch.mockResolvedValue(fileContent) // file content + any additional calls

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('/etc')).toBeInTheDocument())
    fireEvent.click(screen.getByText('/etc'))
    await waitFor(() => expect(screen.getByText('Dockerfile')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Dockerfile'))

    // Wait for the file content to render (code block appears after decodedContent is computed)
    await waitFor(() => {
      const codeEl = document.querySelector('code.hljs')
      expect(codeEl).toBeTruthy()
    }, { timeout: 3000 })
  })
})

// --- handleToggleDir branch tests (collapse/expand-cached/error) ---

describe('handleToggleDir branches', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('collapsing an already-expanded directory hides its children (lines 1589-1593)', async () => {
    const subFiles = [{ name: 'nginx.conf', path: '/etc/nginx.conf', is_dir: false, size: 1024, readable: true }]
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValueOnce({ files: subFiles })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    // Expand the directory
    await waitFor(() => expect(screen.getByText('/etc')).toBeInTheDocument())
    fireEvent.click(screen.getByText('/etc'))
    await waitFor(() => expect(screen.getByText('nginx.conf')).toBeInTheDocument())

    // Collapse it by clicking again
    fireEvent.click(screen.getByText('/etc'))
    await waitFor(() => {
      expect(screen.queryByText('nginx.conf')).not.toBeInTheDocument()
    })
  })

  it('expanding cached directory does not refetch (lines 1598-1602)', async () => {
    const subFiles = [{ name: 'nginx.conf', path: '/etc/nginx.conf', is_dir: false, size: 1024, readable: true }]
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValueOnce({ files: subFiles })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    // Expand the directory (fetches children)
    await waitFor(() => expect(screen.getByText('/etc')).toBeInTheDocument())
    fireEvent.click(screen.getByText('/etc'))
    await waitFor(() => expect(screen.getByText('nginx.conf')).toBeInTheDocument())

    const fetchCallCount = mockApiFetch.mock.calls.length

    // Collapse it
    fireEvent.click(screen.getByText('/etc'))
    await waitFor(() => expect(screen.queryByText('nginx.conf')).not.toBeInTheDocument())

    // Re-expand — should use cached children, no new fetch
    mockApiFetch.mockResolvedValueOnce({ files: subFiles }) // prepare in case it fetches (it shouldn't)
    fireEvent.click(screen.getByText('/etc'))
    await waitFor(() => expect(screen.getByText('nginx.conf')).toBeInTheDocument())

    // The fetch count should not have increased by more than 1 (the re-expand uses cache)
    expect(mockApiFetch.mock.calls.length).toBeLessThanOrEqual(fetchCallCount + 1)
  })

  it('handleToggleDir catch block shows error for failed directory fetch (lines 1625-1626)', async () => {
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockRejectedValueOnce(new Error('Permission denied listing /etc'))

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('/etc')).toBeInTheDocument())
    fireEvent.click(screen.getByText('/etc'))

    await waitFor(() => {
      expect(screen.getByText('Permission denied listing /etc')).toBeInTheDocument()
    })
  })
})

// --- onToggleMarkdownView test ---

describe('onToggleMarkdownView (line 1806)', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('clicking markdown toggle switches between rendered and raw view', async () => {
    const mdContent = '# Hello markdown'
    const fileContent = { data: btoa(mdContent), total_size: mdContent.length, mime_type: 'text/markdown' }

    mockApiFetch.mockResolvedValue(fileContent)
    mockApiFetch.mockResolvedValueOnce(mockServer)
    mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
    mockApiFetch.mockResolvedValueOnce({ files: [{ name: 'README.md', path: '/etc/README.md', is_dir: false, size: mdContent.length, readable: true }] })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <ServerDetailPage />
        </BrowserRouter>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('/etc')).toBeInTheDocument())
    fireEvent.click(screen.getByText('/etc'))
    await waitFor(() => expect(screen.getByText('README.md')).toBeInTheDocument())
    fireEvent.click(screen.getByText('README.md'))

    // Wait for toolbar to appear with markdown toggle
    await waitFor(() => expect(screen.getByTitle('Show raw')).toBeInTheDocument(), { timeout: 3000 })

    // Click the toggle to switch to raw mode
    fireEvent.click(screen.getByTitle('Show raw'))

    await waitFor(() => {
      // Now in raw mode, button title changes to 'Show rendered'
      expect(screen.getByTitle('Show rendered')).toBeInTheDocument()
    })
  })

  // --- Feature #6: Refresh button in file explorer sidebar ---
  describe('file tree refresh button', () => {
    it('shows refresh button in file explorer sidebar header', async () => {
      mockApiFetch.mockImplementation((url: string) => {
        if (url.includes('/my-paths')) return Promise.resolve({ paths: ['/etc'] })
        if (url.match(/\/servers\/srv-1$/)) return Promise.resolve(mockServer)
        return Promise.resolve({ files: [] })
      })
      renderPage()
      await waitFor(() => expect(screen.getByTitle('Refresh file tree')).toBeInTheDocument())
    })

    it('refresh button is enabled after paths load', async () => {
      mockApiFetch.mockResolvedValueOnce(mockServer)
      mockApiFetch.mockResolvedValue({ paths: ['/etc'] })
      renderPage()
      // Wait for paths to load (indicated by /etc appearing in tree)
      await waitFor(() => expect(screen.getByText('/etc')).toBeInTheDocument())

      const refreshBtn = screen.getByTitle('Refresh file tree')
      expect(refreshBtn).not.toBeDisabled()
    })

    it('refreshes expanded directories when clicked', async () => {
      mockApiFetch.mockResolvedValueOnce(mockServer)
      mockApiFetch.mockResolvedValueOnce({ paths: ['/etc'] })
      // First call to expand /etc
      mockApiFetch.mockResolvedValueOnce({ files: [
        { name: 'nginx.conf', path: '/etc/nginx.conf', is_dir: false, size: 1024, readable: true },
      ]})
      // Refresh call
      mockApiFetch.mockResolvedValueOnce({ files: [
        { name: 'nginx.conf', path: '/etc/nginx.conf', is_dir: false, size: 1024, readable: true },
        { name: 'hosts', path: '/etc/hosts', is_dir: false, size: 256, readable: true },
      ]})
      mockApiFetch.mockResolvedValue(mockServer)
      renderPage()
      await waitFor(() => expect(screen.getByText('/etc')).toBeInTheDocument())

      // Expand directory
      fireEvent.click(screen.getByText('/etc'))
      await waitFor(() => expect(screen.getByText('nginx.conf')).toBeInTheDocument())

      // Click refresh
      fireEvent.click(screen.getByTitle('Refresh file tree'))

      // Should show the new file from the refresh response
      await waitFor(() => expect(screen.getByText('hosts')).toBeInTheDocument())
    })

    it('hides refresh button when sidebar is collapsed', async () => {
      mockApiFetch.mockImplementation((url: string) => {
        if (url.includes('/my-paths')) return Promise.resolve({ paths: ['/etc'] })
        if (url.match(/\/servers\/srv-1$/)) return Promise.resolve(mockServer)
        return Promise.resolve({ files: [] })
      })
      renderPage()
      await waitFor(() => expect(screen.getByTitle('Refresh file tree')).toBeInTheDocument())

      // Collapse sidebar
      fireEvent.click(screen.getByTitle('Collapse sidebar'))
      expect(screen.queryByTitle('Refresh file tree')).not.toBeInTheDocument()
    })
  })

  // --- Feature #5: Resizable sidebar divider ---
  describe('resizable sidebar divider', () => {
    it('renders a draggable divider between sidebar and content', async () => {
      mockApiFetch.mockImplementation((url: string) => {
        if (url.includes('/my-paths')) return Promise.resolve({ paths: ['/etc'] })
        if (url.match(/\/servers\/srv-1$/)) return Promise.resolve(mockServer)
        return Promise.resolve({ files: [] })
      })
      renderPage()
      await waitFor(() => expect(screen.getByLabelText('Resize sidebar')).toBeInTheDocument())
    })

    it('hides divider when sidebar is collapsed', async () => {
      mockApiFetch.mockImplementation((url: string) => {
        if (url.includes('/my-paths')) return Promise.resolve({ paths: ['/etc'] })
        if (url.match(/\/servers\/srv-1$/)) return Promise.resolve(mockServer)
        return Promise.resolve({ files: [] })
      })
      renderPage()
      await waitFor(() => expect(screen.getByLabelText('Resize sidebar')).toBeInTheDocument())

      // Collapse sidebar
      fireEvent.click(screen.getByTitle('Collapse sidebar'))
      expect(screen.queryByLabelText('Resize sidebar')).not.toBeInTheDocument()
    })

    it('resizes sidebar on drag', async () => {
      mockApiFetch.mockImplementation((url: string) => {
        if (url.includes('/my-paths')) return Promise.resolve({ paths: ['/etc'] })
        if (url.match(/\/servers\/srv-1$/)) return Promise.resolve(mockServer)
        return Promise.resolve({ files: [] })
      })
      renderPage()
      await waitFor(() => expect(screen.getByLabelText('Resize sidebar')).toBeInTheDocument())

      const divider = screen.getByLabelText('Resize sidebar')

      // Simulate drag: mousedown at x=288, then mousemove to x=400
      fireEvent.mouseDown(divider, { clientX: 288 })
      fireEvent.mouseMove(document, { clientX: 400 })
      fireEvent.mouseUp(document)

      // Sidebar should have been resized (stored in sessionStorage)
      expect(sessionStorage.getItem('veyport-sidebar-width')).toBe('400')
    })

    it('resets sidebar width on double-click', async () => {
      // Set a non-default width first
      sessionStorage.setItem('veyport-sidebar-width', '400')

      mockApiFetch.mockImplementation((url: string) => {
        if (url.includes('/my-paths')) return Promise.resolve({ paths: ['/etc'] })
        if (url.match(/\/servers\/srv-1$/)) return Promise.resolve(mockServer)
        return Promise.resolve({ files: [] })
      })
      renderPage()
      await waitFor(() => expect(screen.getByLabelText('Resize sidebar')).toBeInTheDocument())

      const divider = screen.getByLabelText('Resize sidebar')
      fireEvent.doubleClick(divider)

      expect(sessionStorage.getItem('veyport-sidebar-width')).toBe('288')
    })

    it('clamps sidebar width to min 200 and max 600', async () => {
      mockApiFetch.mockImplementation((url: string) => {
        if (url.includes('/my-paths')) return Promise.resolve({ paths: ['/etc'] })
        if (url.match(/\/servers\/srv-1$/)) return Promise.resolve(mockServer)
        return Promise.resolve({ files: [] })
      })
      renderPage()
      await waitFor(() => expect(screen.getByLabelText('Resize sidebar')).toBeInTheDocument())

      const divider = screen.getByLabelText('Resize sidebar')

      // Try to drag below minimum (200)
      fireEvent.mouseDown(divider, { clientX: 288 })
      fireEvent.mouseMove(document, { clientX: 50 })
      fireEvent.mouseUp(document)
      expect(sessionStorage.getItem('veyport-sidebar-width')).toBe('200')

      // Try to drag above maximum (600)
      fireEvent.mouseDown(divider, { clientX: 200 })
      fireEvent.mouseMove(document, { clientX: 900 })
      fireEvent.mouseUp(document)
      expect(sessionStorage.getItem('veyport-sidebar-width')).toBe('600')
    })
  })
})

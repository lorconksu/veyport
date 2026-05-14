import { useState, useEffect, useMemo, useCallback, useRef, lazy, Suspense, type MouseEvent as ReactMouseEvent, type RefObject } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Folder,
  File,
  RefreshCw,
  Eye,
  Code,
  Loader2,
  Trash2,
  Plus,
  AlertTriangle,
  FolderOpen,
  PanelLeftClose,
  PanelLeftOpen,
  Play,
  Square,
  Search,
  Terminal,
  Upload,
  X,
  CheckCircle,
} from 'lucide-react'
import 'highlight.js/styles/github-dark.css'
// Lazy-load heavy markdown/mermaid viewer (code-split out of main bundle)
const LazyMarkdownViewer = lazy(() => import('@/components/markdown-viewer'))
import { apiFetch } from '@/lib/api'
import { getCSRFToken } from '@/lib/auth'
import { useFileContentViewer } from '@/hooks/use-file-content-viewer'
import { relativeTime } from '@/lib/time'
import { formatFileSize, isMarkdownFile, parseSseChunk, sortFileNodes } from '@/lib/file-viewer'
import { statusDot } from '@/lib/server-utils'
import { useAuth } from '@/hooks/use-auth'
import { OfflineTerminalState, ServerTerminal } from '@/components/server-terminal'
import type {
  Server,
  FileNode,
  FileListResponse,
  FileReadResponse,
  PathPermission,
  PathListResponse,
  CreatePathRequest,
  User,
} from '@/types/api'

// --- Tree Node State ---

interface TreeNodeState {
  loading: boolean
  expanded: boolean
  children: FileNode[] | null
  error: string | null
}

type WorkspaceMode = 'files' | 'terminal'

function workspaceToggleClass(active: boolean): string {
  return active
    ? 'bg-accent text-white shadow-sm'
    : 'text-text-secondary hover:text-text-primary hover:bg-elevated/80'
}

function workspaceDescription(offline: boolean, terminalAvailable: boolean): string {
  if (offline) {
    return 'This node is offline. Terminal access unlocks as soon as the agent reconnects.'
  }
  if (terminalAvailable) {
    return 'Switch between file browsing and terminal access.'
  }
  return 'File browsing is available for this server.'
}

// --- FileTreeNode Component ---

interface FileTreeNodeProps {
  node: FileNode
  depth: number
  selectedPath: string | null
  treeState: Record<string, TreeNodeState>
  onToggleDir: (path: string) => void
  onSelectFile: (node: FileNode) => void
}

function FileTreeNode({
  node,
  depth,
  selectedPath,
  treeState,
  onToggleDir,
  onSelectFile,
}: Readonly<FileTreeNodeProps>) {
  const state = treeState[node.path]
  const isExpanded = state?.expanded ?? false
  const isLoading = state?.loading ?? false
  const children = state?.children ?? null
  const isSelected = selectedPath === node.path

  if (node.is_dir) {
    return (
      <div>
        <button
          onClick={() => onToggleDir(node.path)}
          className={`w-full flex items-center gap-1 px-2 py-1 text-sm hover:bg-elevated/80 transition-colors text-left ${
            isSelected ? 'bg-elevated text-accent' : 'text-text-secondary'
          }`}
          style={{ paddingLeft: `${depth * 16 + 8}px` }}
          disabled={isLoading}
        >
          {isLoading && (
            <Loader2 className="w-3.5 h-3.5 shrink-0 animate-spin text-text-faint" />
          )}
          {!isLoading && isExpanded && (
            <ChevronDown className="w-3.5 h-3.5 shrink-0 text-text-faint" />
          )}
          {!isLoading && !isExpanded && (
            <ChevronRight className="w-3.5 h-3.5 shrink-0 text-text-faint" />
          )}
          {isExpanded ? (
            <FolderOpen className="w-4 h-4 shrink-0 text-status-warning" />
          ) : (
            <Folder className="w-4 h-4 shrink-0 text-status-warning" />
          )}
          <span className="truncate ml-1">{node.name}</span>
        </button>
        {isExpanded && children && (
          <div>
            {children.length === 0 ? (
              <div
                className="text-text-faint text-xs italic px-2 py-1"
                style={{ paddingLeft: `${(depth + 1) * 16 + 28}px` }}
              >
                Empty directory
              </div>
            ) : (
              children.map((child) => (
                <FileTreeNode
                  key={child.path}
                  node={child}
                  depth={depth + 1}
                  selectedPath={selectedPath}
                  treeState={treeState}
                  onToggleDir={onToggleDir}
                  onSelectFile={onSelectFile}
                />
              ))
            )}
          </div>
        )}
        {state?.error && (
          <div
            className="text-status-error text-xs px-2 py-1"
            style={{ paddingLeft: `${(depth + 1) * 16 + 28}px` }}
          >
            {state.error}
          </div>
        )}
      </div>
    )
  }

  function fileNodeClass(): string {
    if (isSelected) return 'bg-accent/15 text-accent'
    if (node.readable) return 'text-text-secondary hover:bg-elevated/80'
    return 'text-text-faint cursor-not-allowed'
  }

  return (
    <button
      onClick={() => node.readable && onSelectFile(node)}
      className={`w-full flex items-center gap-1 px-2 py-1 text-sm transition-colors text-left ${fileNodeClass()}`}
      style={{ paddingLeft: `${depth * 16 + 8}px` }}
      disabled={!node.readable}
      title={node.readable ? undefined : 'File not readable'}
    >
      <span className="w-3.5 shrink-0" />
      <File className="w-4 h-4 shrink-0 text-text-faint" />
      <span className="truncate ml-1">{node.name}</span>
    </button>
  )
}

// --- PathManagement Component (Admin Only) ---

function PathManagement({ serverId }: Readonly<{ serverId: string }>) {
  const queryClient = useQueryClient()
  const [expanded, setExpanded] = useState(false)
  const [newUserId, setNewUserId] = useState('')
  const [newPath, setNewPath] = useState('')

  const { data: pathsData, isLoading: pathsLoading } = useQuery({
    queryKey: ['server-paths', serverId],
    queryFn: () => apiFetch<PathListResponse>(`/servers/${serverId}/paths`),
    enabled: expanded,
  })

  const { data: usersData } = useQuery({
    queryKey: ['users'],
    queryFn: () => apiFetch<{ users: User[] }>('/users'),
    enabled: expanded,
  })

  const addMutation = useMutation({
    mutationFn: (data: CreatePathRequest) =>
      apiFetch<PathPermission>(`/servers/${serverId}/paths`, {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['server-paths', serverId] })
      setNewUserId('')
      setNewPath('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (pathId: string) =>
      apiFetch(`/servers/${serverId}/paths/${pathId}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['server-paths', serverId] })
    },
  })

  const handleAdd = (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (!newUserId || !newPath) return
    addMutation.mutate({ user_id: newUserId, path: newPath })
  }

  const paths = pathsData?.paths ?? []
  const users = usersData?.users ?? []

  return (
    <div className="border border-border rounded">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-text-primary hover:bg-elevated/50 transition-colors"
      >
        <span>Manage File Access</span>
        {expanded ? (
          <ChevronDown className="w-4 h-4 text-text-muted" />
        ) : (
          <ChevronRight className="w-4 h-4 text-text-muted" />
        )}
      </button>

      {expanded && (
        <div className="border-t border-border px-4 py-3 space-y-4">
          {/* Add Path Form */}
          <form onSubmit={handleAdd} className="flex items-end gap-3">
            <div className="flex-1">
              <label htmlFor="path-user" className="block text-xs text-text-muted mb-1">User</label>
              <select
                id="path-user"
                value={newUserId}
                onChange={(e) => setNewUserId(e.target.value)}
                className="w-full bg-elevated border border-border rounded px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent"
              >
                <option value="">Select user...</option>
                {users.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.username}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex-1">
              <label htmlFor="path-input" className="block text-xs text-text-muted mb-1">Path</label>
              <input
                id="path-input"
                type="text"
                placeholder="/var/log"
                value={newPath}
                onChange={(e) => setNewPath(e.target.value)}
                className="w-full bg-elevated border border-border rounded px-3 py-1.5 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent font-mono"
              />
            </div>
            <button
              type="submit"
              disabled={addMutation.isPending || !newUserId || !newPath}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm rounded transition-colors disabled:opacity-50"
            >
              <Plus className="w-3.5 h-3.5" />
              {addMutation.isPending ? 'Adding...' : 'Add Path'}
            </button>
          </form>

          {addMutation.isError && (
            <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2">
              {addMutation.error instanceof Error ? addMutation.error.message : 'Failed to add path'}
            </div>
          )}

          {/* Paths Table */}
          {pathsLoading && (
            <div className="text-text-muted text-sm py-4 text-center">Loading permissions...</div>
          )}
          {!pathsLoading && paths.length === 0 && (
            <div className="text-text-muted text-sm py-4 text-center">
              No path permissions configured yet.
            </div>
          )}
          {!pathsLoading && paths.length > 0 && (
            <div className="border border-border rounded overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-elevated text-text-muted text-xs uppercase tracking-wider">
                    <th className="px-3 py-2 text-left">Username</th>
                    <th className="px-3 py-2 text-left">Path</th>
                    <th className="px-3 py-2 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {paths.map((p) => (
                    <tr key={p.id} className="hover:bg-elevated/50 transition-colors">
                      <td className="px-3 py-2 text-text-primary">{p.username}</td>
                      <td className="px-3 py-2 font-mono text-text-secondary text-xs">{p.path}</td>
                      <td className="px-3 py-2 text-right">
                        <button
                          onClick={() => deleteMutation.mutate(p.id)}
                          disabled={deleteMutation.isPending}
                          className="text-text-muted hover:text-status-offline transition-colors"
                          title="Remove permission"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// --- DropzoneUpload Component (Admin Only) ---

function DropzoneUpload({ serverId }: Readonly<{ serverId: string }>) {
  const [expanded, setExpanded] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadResult, setUploadResult] = useState<{ filename: string; size: number } | null>(null)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const queryClient = useQueryClient()

  const { data: dropzoneData } = useQuery({
    queryKey: ['dropzone', serverId],
    queryFn: () => apiFetch<{ files: FileNode[] }>(`/servers/${serverId}/dropzone`),
    enabled: expanded,
    refetchInterval: expanded ? 30_000 : false,
  })

  const [deleteState, setDeleteState] = useState<'idle' | 'deleting' | 'done' | 'error'>('idle')
  const [deleteError, setDeleteError] = useState('')

  /* c8 ignore start */
  const handleConfirmDelete = async () => {
    if (!confirmDelete) return
    setDeleteState('deleting')
    setDeleteError('')
    try {
      await apiFetch(`/servers/${serverId}/dropzone?filename=${encodeURIComponent(confirmDelete)}`, { method: 'DELETE' })
      queryClient.invalidateQueries({ queryKey: ['dropzone', serverId] })
      setDeleteState('done')
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Delete failed')
      setDeleteState('error')
    }
  }
  /* c8 ignore stop */

  const closeDeleteModal = () => {
    setConfirmDelete(null)
    setDeleteState('idle')
    setDeleteError('')
  }

  /* c8 ignore start */
  const handleUpload = async (file: File) => {
    setUploading(true)
    setUploadResult(null)
    setUploadError(null)

    try {
      const formData = new FormData()
      formData.append('file', file)

      const result = await apiFetch<{ filename: string; size: number }>(`/servers/${serverId}/upload`, {
        method: 'POST',
        body: formData,
      })
      setUploadResult(result)
      queryClient.invalidateQueries({ queryKey: ['dropzone', serverId] })
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Upload failed')
    } finally {
      setUploading(false)
    }
  }
  /* c8 ignore stop */

  const handleDrop = (e: React.DragEvent<HTMLButtonElement>) => {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files[0]
    if (file) handleUpload(file)
  }

  const handleDragOver = (e: React.DragEvent<HTMLButtonElement>) => {
    e.preventDefault()
    setDragOver(true)
  }

  const handleDragLeave = () => {
    setDragOver(false)
  }

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      handleUpload(file)
      // Reset input so the same file can be re-uploaded
      e.target.value = ''
    }
  }

  const files = dropzoneData?.files ?? []

  return (
    <div className="border border-border rounded">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-text-primary hover:bg-elevated/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Upload className="w-4 h-4 text-text-muted" />
          <span>Dropzone</span>
        </div>
        {expanded ? (
          <ChevronDown className="w-4 h-4 text-text-muted" />
        ) : (
          <ChevronRight className="w-4 h-4 text-text-muted" />
        )}
      </button>

      {expanded && (
        <div className="border-t border-border px-4 py-3 space-y-4">
          {/* Drag-and-drop area */}
          <button
            type="button"
            aria-label="Upload files by clicking or dragging"
            disabled={uploading}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onClick={() => !uploading && fileInputRef.current?.click()}
            className={`w-full flex flex-col items-center justify-center gap-2 border-2 border-dashed rounded-lg px-6 py-8 cursor-pointer transition-colors ${
              dragOver
                ? 'border-accent bg-accent/10 text-accent'
                : 'border-border hover:border-accent/50 text-text-muted hover:text-text-secondary'
            } ${uploading ? 'cursor-not-allowed opacity-60' : ''}`}
          >
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              onChange={handleFileInputChange}
              disabled={uploading}
            />
            {uploading ? (
              <>
                <Loader2 className="w-6 h-6 animate-spin" />
                <span className="text-sm">Uploading...</span>
              </>
            ) : (
              <>
                <Upload className="w-6 h-6" />
                <span className="text-sm">Drop files here or click to browse</span>
              </>
            )}
          </button>

          {/* Upload result feedback */}
          {uploadResult && !uploading && (
            <div className="flex items-center gap-2 bg-status-online/10 border border-status-online/20 text-status-online text-xs rounded px-3 py-2">
              <CheckCircle className="w-4 h-4 shrink-0" />
              <span>
                <span className="font-medium">{uploadResult.filename}</span> uploaded successfully
                ({formatFileSize(uploadResult.size)})
              </span>
            </div>
          )}

          {uploadError && (
            <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2">
              {uploadError}
            </div>
          )}

          {/* Dropped files table */}
          <div>
            <div className="text-xs text-text-muted uppercase tracking-wider font-medium mb-2">
              Dropped Files
            </div>
            {files.length === 0 ? (
              <div className="text-text-muted text-sm py-3 text-center">No files in dropzone</div>
            ) : (
              <div className="border border-border rounded overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-elevated text-text-muted text-xs uppercase tracking-wider">
                      <th className="px-3 py-2 text-left">Name</th>
                      <th className="px-3 py-2 text-right">Size</th>
                      <th className="px-3 py-2"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {files.map((f) => (
                      <tr key={f.path} className="hover:bg-elevated/50 transition-colors">
                        <td className="px-3 py-2 font-mono text-text-primary text-xs">{f.name}</td>
                        <td className="px-3 py-2 text-right text-text-secondary text-xs">
                          {formatFileSize(f.size)}
                        </td>
                        <td className="px-3 py-2 text-right">
                          <button
                            onClick={() => { setConfirmDelete(f.name); setDeleteState('idle'); }}
                            className="text-text-muted hover:text-status-error transition-colors"
                            title="Delete file"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
      {/* Delete Confirmation Modal */}
      {confirmDelete && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-surface border border-border rounded-lg w-full max-w-sm mx-4 p-6">
            {deleteState === 'done' && (
              <>
                <div className="flex items-center gap-2 mb-3">
                  <CheckCircle className="w-5 h-5 text-status-online" />
                  <h3 className="text-text-primary font-semibold">File Deleted</h3>
                </div>
                <p className="text-sm text-text-secondary mb-4">
                  <span className="font-mono text-text-primary">{confirmDelete}</span> has been deleted from the dropzone.
                </p>
                <div className="flex justify-end">
                  <button
                    onClick={closeDeleteModal}
                    className="px-4 py-2 bg-accent hover:bg-accent-hover text-white text-sm rounded transition-colors"
                  >
                    Close
                  </button>
                </div>
              </>
            )}
            {deleteState === 'error' && (
              <>
                <div className="flex items-center gap-2 mb-3">
                  <AlertTriangle className="w-5 h-5 text-status-error" />
                  <h3 className="text-text-primary font-semibold">Delete Failed</h3>
                </div>
                <p className="text-sm text-status-error mb-4">{deleteError}</p>
                <div className="flex justify-end gap-2">
                  <button
                    onClick={closeDeleteModal}
                    className="px-4 py-2 bg-elevated hover:bg-border text-text-primary text-sm rounded transition-colors"
                  >
                    Close
                  </button>
                  <button
                    onClick={handleConfirmDelete}
                    className="px-4 py-2 bg-status-error/20 hover:bg-status-error/30 text-status-error text-sm rounded transition-colors"
                  >
                    Retry
                  </button>
                </div>
              </>
            )}
            {deleteState === 'deleting' && (
              <>
                <div className="flex items-center gap-2 mb-3">
                  <Loader2 className="w-5 h-5 text-text-muted animate-spin" />
                  <h3 className="text-text-primary font-semibold">Deleting File...</h3>
                </div>
                <p className="text-sm text-text-muted mb-4">
                  Removing <span className="font-mono text-text-primary">{confirmDelete}</span> from the dropzone...
                </p>
                <div className="flex justify-end">
                  <button disabled className="px-4 py-2 bg-elevated text-text-faint text-sm rounded opacity-50 cursor-not-allowed">
                    Close
                  </button>
                </div>
              </>
            )}
            {deleteState === 'idle' && (
              <>
                <h3 className="text-text-primary font-semibold mb-3">Delete File?</h3>
                <p className="text-sm text-text-secondary mb-4">
                  Are you sure you want to delete <span className="font-mono text-text-primary">{confirmDelete}</span> from the dropzone? This cannot be undone.
                </p>
                <div className="flex justify-end gap-2">
                  <button
                    onClick={closeDeleteModal}
                    className="px-4 py-2 bg-elevated hover:bg-border text-text-primary text-sm rounded transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleConfirmDelete}
                    className="px-4 py-2 bg-status-error/20 hover:bg-status-error/30 text-status-error text-sm rounded transition-colors"
                  >
                    Delete
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// --- LiveTail Component ---
/* c8 ignore start */

type LiveTailStatus = 'connecting' | 'streaming' | 'disconnected'

const STATUS_COLORS: Record<LiveTailStatus, string> = {
  connecting: 'text-status-warning',
  streaming: 'text-status-online',
  disconnected: 'text-status-offline',
}

const STATUS_LABELS: Record<LiveTailStatus, string> = {
  connecting: 'Connecting',
  streaming: 'Streaming',
  disconnected: 'Disconnected',
}

const MAX_LINES = 2_000

interface LiveTailProps {
  serverId: string
  filePath: string
  onStop: () => void
}

function LiveTail({
  serverId,
  filePath,
  onStop,
}: Readonly<LiveTailProps>) {
  const lineCounterRef = useRef(0)
  const [lines, setLines] = useState<{ id: number; text: string }[]>([])
  const [grep, setGrep] = useState('')
  const [grepInput, setGrepInput] = useState('')
  const [status, setStatus] = useState<LiveTailStatus>('connecting')
  const [paused, setPaused] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)
  const scrollContainerRef = useRef<HTMLDivElement>(null)
  const abortRef = useRef<AbortController | null>(null)
  const grepTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const pendingLinesRef = useRef<string[]>([])
  const rafIdRef = useRef<number | null>(null)
  const shouldStickToBottomRef = useRef(true)

  // Auto-scroll effect
  useEffect(() => {
    if (!paused && shouldStickToBottomRef.current && bottomRef.current) {
      bottomRef.current.scrollIntoView({ block: 'end' })
    }
  }, [lines, paused])

  const handleScroll = useCallback(() => {
    const container = scrollContainerRef.current
    if (!container) return
    const distanceFromBottom = container.scrollHeight - container.scrollTop - container.clientHeight
    shouldStickToBottomRef.current = distanceFromBottom < 24
  }, [])

  // Debounced grep filter
  const handleGrepChange = useCallback((value: string) => {
    setGrepInput(value)
    if (grepTimerRef.current) clearTimeout(grepTimerRef.current)
    grepTimerRef.current = setTimeout(() => {
      setGrep(value)
    }, 500)
  }, [])

  // Cleanup grep timer and RAF
  useEffect(() => {
    return () => {
      if (grepTimerRef.current) clearTimeout(grepTimerRef.current)
      if (rafIdRef.current !== null) cancelAnimationFrame(rafIdRef.current)
    }
  }, [])

  // Flush pending lines into state (called via requestAnimationFrame).
  const flushPendingLines = useCallback(() => {
    rafIdRef.current = null
    const batch = pendingLinesRef.current
    if (batch.length === 0) return
    pendingLinesRef.current = []
    setLines((prev) => {
      const newEntries = batch.map((text) => ({ id: lineCounterRef.current++, text }))
      const combined = [...prev, ...newEntries]
      return combined.length > MAX_LINES ? combined.slice(-MAX_LINES) : combined
    })
  }, [])

  // Appends new log lines into a pending buffer, flushed at most once per frame.
  const appendLogLines = useCallback((newLogLines: string[]) => {
    pendingLinesRef.current.push(...newLogLines)
    rafIdRef.current ??= requestAnimationFrame(flushPendingLines)
  }, [flushPendingLines])

  // Reads an SSE stream and forwards parsed log lines via appendLogLines.
  const readStream = useCallback(async (reader: ReadableStreamDefaultReader<Uint8Array>) => {
    const decoder = new TextDecoder()
    let sseBuffer = ''

    while (true) {
      const { done, value } = await reader.read()
      if (done) break

      sseBuffer += decoder.decode(value, { stream: true })
      const sseLines = sseBuffer.split('\n')
      sseBuffer = sseLines.pop() || ''

      const newLogLines = parseSseChunk(sseLines)
      if (newLogLines.length > 0) {
        appendLogLines(newLogLines)
      }
    }
  }, [appendLogLines])

  // SSE connection effect
  useEffect(() => {
    const controller = new AbortController()
    abortRef.current = controller

    setStatus('connecting')
    setError(null)
    setLines([])

    async function startStream(signal: AbortSignal) {
      try {
        const params = new URLSearchParams({ path: filePath })
        if (grep) params.set('grep', grep)

        const csrfToken = getCSRFToken()
        const response = await fetch(`/api/servers/${serverId}/logs/tail?${params.toString()}`, {
          headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : undefined,
          credentials: 'same-origin',
          signal,
        })

        if (!response.ok) {
          const errBody = await response.json().catch(() => ({ error: `HTTP ${response.status}` }))
          throw new Error((errBody as { error?: string }).error || `HTTP ${response.status}`)
        }

        setStatus('streaming')

        const reader = response.body?.getReader()
        if (!reader) throw new Error('Response body is not readable')

        await readStream(reader)

        // Stream ended normally
        setStatus('disconnected')
      } catch (err) {
        if (signal.aborted) return
        const msg = err instanceof Error ? err.message : 'Connection failed'
        setError(msg)
        setStatus('disconnected')
      }
    }

    startStream(controller.signal)

    return () => {
      controller.abort()
    }
  }, [serverId, filePath, grep, readStream])

  const handleStop = useCallback(() => {
    abortRef.current?.abort()
    onStop()
  }, [onStop])

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-border bg-surface/50 shrink-0">
        {/* Status indicator */}
        <div className="flex items-center gap-1.5">
          <span className={`${STATUS_COLORS[status]}`}>&#x25CF;</span>
          <span className="text-xs text-text-muted">{STATUS_LABELS[status]}</span>
        </div>

        {/* Grep filter */}
        <div className="flex items-center gap-1 bg-elevated border border-border rounded px-2 py-0.5 flex-1 max-w-xs">
          <Search className="w-3 h-3 text-text-faint shrink-0" />
          <input
            type="text"
            placeholder="Filter (grep)..."
            value={grepInput}
            onChange={(e) => handleGrepChange(e.target.value)}
            className="bg-transparent text-xs text-text-primary placeholder:text-text-faint focus:outline-none w-full font-mono"
          />
        </div>

        {/* Line count */}
        <span className="text-xs text-text-faint">
          {lines.length.toLocaleString()} line{lines.length === 1 ? '' : 's'}
        </span>

        {/* Pause/Resume toggle */}
        <button
          onClick={() => setPaused((p) => !p)}
          className={`px-2 py-0.5 text-xs rounded border transition-colors ${
            paused
              ? 'bg-status-warning/15 border-status-warning/30 text-status-warning'
              : 'bg-elevated border-border text-text-secondary hover:text-text-primary'
          }`}
          title={paused ? 'Resume auto-scroll' : 'Pause auto-scroll'}
        >
          {paused ? 'Paused' : 'Auto-scroll'}
        </button>

        {/* Stop button */}
        <button
          onClick={handleStop}
          className="flex items-center gap-1 px-2 py-0.5 text-xs bg-status-error/15 border border-status-error/30 text-status-error rounded hover:bg-status-error/25 transition-colors"
        >
          <Square className="w-3 h-3" />
          Stop
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <div className="bg-status-error/10 border-b border-status-error/20 px-4 py-1.5 text-xs text-status-error shrink-0">
          {error}
        </div>
      )}

      {/* Log output */}
      <div
        ref={scrollContainerRef}
        className="flex-1 overflow-auto bg-base"
        onScroll={handleScroll}
      >
        {lines.length === 0 && status === 'connecting' && (
          <div className="flex items-center justify-center py-16">
            <Loader2 className="w-5 h-5 animate-spin text-text-muted" />
            <span className="ml-2 text-text-muted text-sm">Connecting to log stream...</span>
          </div>
        )}
        {lines.length === 0 && status === 'streaming' && (
          <div className="flex items-center justify-center py-16 text-text-muted text-sm">
            Waiting for log data...
          </div>
        )}
        {lines.length > 0 && (
          <pre className="p-3 text-xs font-mono leading-5 whitespace-pre-wrap break-all">
            {lines.map((line) => (
              <div key={line.id} className="text-emerald-400/90 hover:bg-white/5">
                {line.text}
              </div>
            ))}
            <div ref={bottomRef} />
          </pre>
        )}
      </div>
    </div>
  )
}
/* c8 ignore stop */

// --- FileViewerContent Component ---

interface FileViewerContentProps {
  fileLoading: boolean
  fileError: Error | null
  decodedContent: string | null
  selectedFile: FileNode
  markdownView: 'raw' | 'rendered'
  searchTerm: string
  searchHighlightedHtml: string
  highlightedHtml: string
  fileContent: FileReadResponse | undefined
  onRefetch: () => void
}

function FileViewerContent({
  fileLoading,
  fileError,
  decodedContent,
  selectedFile,
  markdownView,
  searchTerm,
  searchHighlightedHtml,
  highlightedHtml,
  fileContent,
  onRefetch,
}: Readonly<FileViewerContentProps>) {
  const isPartialFile = fileContent && decodedContent && fileContent.total_size > decodedContent.length
  const htmlToRender = searchTerm ? searchHighlightedHtml : highlightedHtml

  if (fileLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="w-5 h-5 animate-spin text-text-muted" />
        <span className="ml-2 text-text-muted text-sm">Loading file...</span>
      </div>
    )
  }

  if (fileError) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <AlertTriangle className="w-6 h-6 text-status-error mb-2" />
        <p className="text-text-primary text-sm mb-1">Failed to load file</p>
        <p className="text-text-muted text-xs mb-3">
          {fileError instanceof Error ? fileError.message : 'Unknown error'}
        </p>
        <button
          onClick={onRefetch}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-elevated border border-border rounded text-sm text-text-secondary hover:text-text-primary transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Retry
        </button>
      </div>
    )
  }

  if (decodedContent === null) return null

  return (
    <>
      {isPartialFile && (
        <div className="bg-status-warning/10 border-b border-status-warning/20 px-4 py-1.5 text-xs text-status-warning shrink-0">
          Showing last 1 MB of {formatFileSize(fileContent?.total_size ?? 0)}
        </div>
      )}
      <div className="flex-1 overflow-auto">
        {isMarkdownFile(selectedFile.path) && markdownView === 'rendered' ? (
          <Suspense fallback={<div className="flex items-center justify-center py-16"><Loader2 className="w-5 h-5 animate-spin text-text-muted" /><span className="ml-2 text-text-muted text-sm">Loading viewer...</span></div>}>
            <LazyMarkdownViewer content={decodedContent} />
          </Suspense>
        ) : (
          <HighlightedCodeBlock html={htmlToRender} />
        )}
      </div>
    </>
  )
}

// HighlightedCodeBlock renders pre-sanitized hljs HTML.
// highlight.js escapes all user text and only produces <span class="hljs-..."> wrappers.
// sanitizeHljsHtml() strips any non-span tags as a defense-in-depth measure.
function HighlightedCodeBlock({ html }: Readonly<{ html: string }>) {
  // NOTE: html here is sanitized output from sanitizeHljsHtml() — safe to render.
  return (
    <pre className="p-4 text-sm font-mono leading-relaxed overflow-x-auto">
      <code className="hljs" dangerouslySetInnerHTML={{ __html: html }} />
    </pre>
  )
}

// --- FileViewerToolbar Component ---

interface FileViewerToolbarProps {
  selectedFile: FileNode
  fileContent: FileReadResponse | undefined
  fileLoading: boolean
  liveTailing: boolean
  searchOpen: boolean
  markdownView: 'raw' | 'rendered'
  onRefetch: () => void
  onToggleSearch: () => void
  onToggleLiveTail: () => void
  onToggleMarkdownView: () => void
  breadcrumbs: { name: string; path: string }[]
}

function FileViewerToolbar({
  selectedFile,
  fileContent,
  fileLoading,
  liveTailing,
  searchOpen,
  markdownView,
  onRefetch,
  onToggleSearch,
  onToggleLiveTail,
  onToggleMarkdownView,
  breadcrumbs,
}: Readonly<FileViewerToolbarProps>) {
  return (
    <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-surface/50 shrink-0">
      <div className="flex items-center gap-1 text-xs text-text-muted overflow-x-auto min-w-0">
        {breadcrumbs.map((crumb, i) => (
          <span key={crumb.path} className="flex items-center gap-1 shrink-0">
            {i > 0 && <span className="text-text-faint">/</span>}
            <span
              className={
                i === breadcrumbs.length - 1
                  ? 'text-text-primary font-medium'
                  : 'text-text-muted'
              }
            >
              {crumb.name}
            </span>
          </span>
        ))}
      </div>
      <div className="flex items-center gap-2 shrink-0 ml-2">
        {fileContent && (
          <span className="text-xs text-text-faint">
            {formatFileSize(fileContent.total_size)}
            {fileContent.mime_type && ` \u00B7 ${fileContent.mime_type}`}
          </span>
        )}
        {isMarkdownFile(selectedFile.path) && (
          <button
            onClick={onToggleMarkdownView}
            className="flex items-center gap-1 px-2 py-0.5 text-xs bg-elevated border border-border rounded text-text-secondary hover:text-text-primary transition-colors"
            title={markdownView === 'raw' ? 'Show rendered' : 'Show raw'}
          >
            {markdownView === 'raw' && (
              <>
                <Eye className="w-3 h-3" />
                Rendered
              </>
            )}
            {markdownView !== 'raw' && (
              <>
                <Code className="w-3 h-3" />
                Raw
              </>
            )}
          </button>
        )}
        <button
          onClick={onRefetch}
          disabled={fileLoading || liveTailing}
          className="p-1 text-text-muted hover:text-text-primary transition-colors disabled:opacity-50"
          title="Refresh file"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${fileLoading ? 'animate-spin' : ''}`} />
        </button>
        <button
          onClick={onToggleSearch}
          disabled={liveTailing}
          className={`p-1 transition-colors disabled:opacity-50 ${searchOpen ? 'text-accent' : 'text-text-muted hover:text-text-primary'}`}
          title="Search in file (Ctrl+F)"
        >
          <Search className="w-3.5 h-3.5" />
        </button>
        {!selectedFile.is_dir && (
          <button
            onClick={onToggleLiveTail}
            className={`flex items-center gap-1 px-2 py-0.5 text-xs rounded border transition-colors ${
              liveTailing
                ? 'bg-status-error/15 border-status-error/30 text-status-error'
                : 'bg-elevated border-border text-text-secondary hover:text-text-primary'
            }`}
            title={liveTailing ? 'Stop live tail' : 'Start live tail'}
          >
            {liveTailing ? <Square className="w-3 h-3" /> : <Play className="w-3 h-3" />}
            {liveTailing ? 'Stop' : 'Live Tail'}
          </button>
        )}
      </div>
    </div>
  )
}

// --- FileSearchBar Component ---

interface FileSearchBarProps {
  searchInput: string
  matchCount: number
  currentMatch: number
  onSearchChange: (value: string) => void
  onNavigatePrev: () => void
  onNavigateNext: () => void
  onClose: () => void
  inputRef: RefObject<HTMLInputElement | null>
}

function FileSearchBar({
  searchInput,
  matchCount,
  currentMatch,
  onSearchChange,
  onNavigatePrev,
  onNavigateNext,
  onClose,
  inputRef,
}: Readonly<FileSearchBarProps>) {
  return (
    <div className="flex items-center gap-2 px-4 py-1.5 border-b border-border bg-elevated/50 shrink-0">
      <Search className="w-3.5 h-3.5 text-text-muted" />
      <input
        ref={inputRef}
        type="text"
        value={searchInput}
        onChange={(e) => onSearchChange(e.target.value)}
        placeholder="Search in file..."
        className="flex-1 bg-transparent text-sm text-text-primary placeholder:text-text-faint focus:outline-none"
        autoFocus
        onKeyDown={(e) => {
          if (e.key === 'Escape') onClose()
          if (e.key === 'Enter' && !e.shiftKey) onNavigateNext()
          if (e.key === 'Enter' && e.shiftKey) onNavigatePrev()
        }}
      />
      {searchInput && (
        <span className="text-xs text-text-muted whitespace-nowrap">
          {matchCount > 0 ? `${currentMatch + 1} of ${matchCount}` : 'No matches'}
        </span>
      )}
      <button onClick={onNavigatePrev} disabled={matchCount === 0} className="p-0.5 text-text-muted hover:text-text-primary disabled:opacity-30">
        <ChevronUp className="w-3.5 h-3.5" />
      </button>
      <button onClick={onNavigateNext} disabled={matchCount === 0} className="p-0.5 text-text-muted hover:text-text-primary disabled:opacity-30">
        <ChevronDown className="w-3.5 h-3.5" />
      </button>
      <button onClick={onClose} className="p-0.5 text-text-muted hover:text-text-primary">
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}

// --- FileExplorerSidebar Component ---

interface FileExplorerSidebarProps {
  sidebarCollapsed: boolean
  sidebarWidth: number
  onToggleCollapse: () => void
  onRefreshTree: () => void
  treeRefreshing: boolean
  pathsLoading: boolean
  rootPaths: string[]
  rootNodes: FileNode[]
  selectedFile: FileNode | null
  treeState: Record<string, TreeNodeState>
  onToggleDir: (path: string) => void
  onSelectFile: (node: FileNode) => void
}

function FileExplorerSidebar({
  sidebarCollapsed,
  sidebarWidth,
  onToggleCollapse,
  onRefreshTree,
  treeRefreshing,
  pathsLoading,
  rootPaths,
  rootNodes,
  selectedFile,
  treeState,
  onToggleDir,
  onSelectFile,
}: Readonly<FileExplorerSidebarProps>) {
  return (
    <div
      className="border-r border-border flex flex-col bg-surface/30 shrink-0 transition-all duration-200"
      style={{ width: sidebarCollapsed ? 40 : sidebarWidth }}
    >
      <div className="flex items-center justify-between px-2 py-2 border-b border-border shrink-0">
        {!sidebarCollapsed && (
          <span className="text-xs text-text-muted uppercase tracking-wider font-medium pl-1">File Explorer</span>
        )}
        <div className="flex items-center gap-0.5">
          {!sidebarCollapsed && (
            <button
              onClick={onRefreshTree}
              disabled={treeRefreshing || pathsLoading}
              className="p-1 text-text-muted hover:text-text-primary transition-colors disabled:opacity-50"
              title="Refresh file tree"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${treeRefreshing ? 'animate-spin' : ''}`} />
            </button>
          )}
          <button
            onClick={onToggleCollapse}
            className="p-1 text-text-muted hover:text-text-primary transition-colors"
            title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {sidebarCollapsed ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
          </button>
        </div>
      </div>
      <div className={`flex-1 overflow-y-auto ${sidebarCollapsed ? 'hidden' : ''}`}>
        {pathsLoading && (
          <div className="flex items-center gap-2 px-3 py-4 text-text-muted text-sm">
            <Loader2 className="w-4 h-4 animate-spin" />
            Loading paths...
          </div>
        )}
        {!pathsLoading && rootPaths.length === 0 && (
          <div className="px-3 py-4 text-text-muted text-sm">
            No paths configured. Ask an admin to grant access.
          </div>
        )}
        {!pathsLoading && rootPaths.length > 0 && (
          <div className="py-1">
	            {rootNodes.map((node) => (
	              <FileTreeNode
	                key={node.path}
	                node={node}
	                depth={0}
	                selectedPath={selectedFile?.path ?? null}
	                treeState={treeState}
	                onToggleDir={onToggleDir}
                onSelectFile={onSelectFile}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// --- ServerDetailHeader Component ---

function ServerDetailHeader({ server }: Readonly<{ server: Server }>) {
  return (
    <div className="flex items-center justify-between px-4 py-3 bg-surface border-b border-border shrink-0">
      <div className="flex items-center gap-4">
        <Link
          to="/"
          className="text-text-muted hover:text-text-secondary transition-colors"
          title="Back to dashboard"
        >
          <ArrowLeft className="w-4 h-4" />
        </Link>
        <div>
          <div className="flex items-center gap-2">
            <span className={statusDot[server.status]}>&#x25CF;</span>
            <h1 className="text-lg font-semibold text-text-primary">{server.name}</h1>
          </div>
          <div className="flex items-center gap-3 text-xs text-text-muted mt-0.5">
            {(server.hostname || server.ip_address) && (
              <span className="font-mono">
                {server.hostname ?? '--'} / {server.ip_address ?? '--'}
              </span>
            )}
            {server.os && <span>{server.os}</span>}
            {server.agent_version && <span>v{server.agent_version}</span>}
            <span>Last seen: {relativeTime(server.last_seen_at)}</span>
          </div>
        </div>
      </div>
    </div>
  )
}

function WorkspaceModeBar({
  workspaceMode,
  onChange,
  offline,
  terminalAvailable,
}: Readonly<{
  workspaceMode: WorkspaceMode
  onChange: (mode: WorkspaceMode) => void
  offline: boolean
  terminalAvailable: boolean
}>) {
  return (
    <div className="flex items-center justify-between px-4 py-2.5 bg-surface/60 border-b border-border shrink-0">
      <div>
        <p className="text-sm font-medium text-text-primary">Workspace</p>
        <p className="text-xs text-text-muted">{workspaceDescription(offline, terminalAvailable)}</p>
      </div>
      <div className="inline-flex items-center gap-1 rounded-lg border border-border bg-elevated/40 p-1">
        <button
          type="button"
          onClick={() => onChange('files')}
          aria-pressed={workspaceMode === 'files'}
          className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition-colors ${workspaceToggleClass(workspaceMode === 'files')}`}
        >
          <Folder className="w-4 h-4" />
          Files
        </button>
        {terminalAvailable && (
          <button
            type="button"
            onClick={() => onChange('terminal')}
            aria-pressed={workspaceMode === 'terminal'}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition-colors ${workspaceToggleClass(workspaceMode === 'terminal')}`}
          >
            <Terminal className="w-4 h-4" />
            Terminal
          </button>
        )}
      </div>
    </div>
  )
}

function OfflineFilesState() {
  return (
    <div className="flex-1 flex items-center justify-center px-6">
      <div className="max-w-md rounded-2xl border border-border bg-surface/50 px-6 py-8 text-center shadow-sm">
        <File className="w-10 h-10 text-text-faint mx-auto mb-3" />
        <p className="text-text-primary text-sm font-medium">File browsing is waiting on the agent</p>
        <p className="mt-2 text-sm text-text-muted">
          This node is not online yet, so the explorer stays read-only. When it reconnects, the terminal tab opens a live shell over the agent stream.
        </p>
      </div>
    </div>
  )
}

interface ServerWorkspacePanelProps {
  workspaceMode: WorkspaceMode
  isOffline: boolean
  isDragging: boolean
  server: Server
  serverId: string
  sidebarCollapsed: boolean
  sidebarWidth: number
  treeRefreshing: boolean
  pathsLoading: boolean
  rootPaths: string[]
  rootNodes: FileNode[]
  selectedFile: FileNode | null
  treeState: Record<string, TreeNodeState>
  fileContent: FileReadResponse | undefined
  fileLoading: boolean
  fileError: Error | null
  liveTailing: boolean
  searchOpen: boolean
  markdownView: 'raw' | 'rendered'
  searchInput: string
  matchCount: number
  currentMatch: number
  breadcrumbs: Array<{ name: string; path: string }>
  decodedContent: string | null
  effectiveSearchTerm: string
  searchHighlightedHtml: string
  highlightedHtml: string
  searchInputRef: RefObject<HTMLInputElement | null>
  onToggleSidebar: () => void
  onRefreshTree: () => void
  onToggleDir: (path: string) => void
  onSelectFile: (node: FileNode) => void
  onDragStart: (event: ReactMouseEvent) => void
  onResetWidth: () => void
  onRefetchFile: () => void
  onToggleSearch: () => void
  onToggleLiveTail: () => void
  onToggleMarkdownView: () => void
  onSearchChange: (value: string) => void
  onNavigatePrev: () => void
  onNavigateNext: () => void
  onCloseSearch: () => void
  onStopLiveTail: () => void
}

function ServerWorkspacePanel(props: Readonly<ServerWorkspacePanelProps>) {
  const className = `flex flex-1${props.isDragging ? ' select-none' : ''}`

  if (props.workspaceMode === 'terminal') {
    return (
      <div className={className} style={{ minHeight: 0 }}>
        {props.isOffline ? (
          <OfflineTerminalState server={props.server} />
        ) : (
          <ServerTerminal serverId={props.serverId} server={props.server} />
        )}
      </div>
    )
  }

  return (
    <div className={className} style={{ minHeight: 0 }}>
      {props.isOffline ? <OfflineFilesState /> : <FilesWorkspace {...props} />}
    </div>
  )
}

function FilesWorkspace(props: Readonly<ServerWorkspacePanelProps>) {
  return (
    <>
      <FileExplorerSidebar
        sidebarCollapsed={props.sidebarCollapsed}
        sidebarWidth={props.sidebarWidth}
        onToggleCollapse={props.onToggleSidebar}
        onRefreshTree={props.onRefreshTree}
        treeRefreshing={props.treeRefreshing}
        pathsLoading={props.pathsLoading}
        rootPaths={props.rootPaths}
        rootNodes={props.rootNodes}
        selectedFile={props.selectedFile}
        treeState={props.treeState}
        onToggleDir={props.onToggleDir}
        onSelectFile={props.onSelectFile}
      />

      {!props.sidebarCollapsed && (
        <button
          type="button"
          className="w-1 hover:w-1.5 bg-border hover:bg-accent/50 cursor-col-resize transition-colors shrink-0 p-0 border-0 rounded-none"
          onMouseDown={props.onDragStart}
          onDoubleClick={props.onResetWidth}
          aria-label="Resize sidebar"
          title="Drag to resize sidebar, double-click to reset"
        />
      )}

      <FileWorkspaceContent {...props} />
    </>
  )
}

function FileWorkspaceContent(props: Readonly<ServerWorkspacePanelProps>) {
  if (!props.selectedFile) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-center">
          <File className="w-10 h-10 text-text-faint mx-auto mb-3" />
          <p className="text-text-muted text-sm">Select a file to view its contents</p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex-1 flex flex-col min-w-0">
      <FileViewerToolbar
        selectedFile={props.selectedFile}
        fileContent={props.fileContent}
        fileLoading={props.fileLoading}
        liveTailing={props.liveTailing}
        searchOpen={props.searchOpen}
        markdownView={props.markdownView}
        onRefetch={props.onRefetchFile}
        onToggleSearch={props.onToggleSearch}
        onToggleLiveTail={props.onToggleLiveTail}
        onToggleMarkdownView={props.onToggleMarkdownView}
        breadcrumbs={props.breadcrumbs}
      />

      {props.searchOpen && !props.liveTailing && (
        <FileSearchBar
          searchInput={props.searchInput}
          matchCount={props.matchCount}
          currentMatch={props.currentMatch}
          onSearchChange={props.onSearchChange}
          onNavigatePrev={props.onNavigatePrev}
          onNavigateNext={props.onNavigateNext}
          onClose={props.onCloseSearch}
          inputRef={props.searchInputRef}
        />
      )}

      {props.liveTailing ? (
        <LiveTail
          serverId={props.serverId}
          filePath={props.selectedFile.path}
          onStop={props.onStopLiveTail}
        />
      ) : (
        <FileViewerContent
          fileLoading={props.fileLoading}
          fileError={props.fileError}
          decodedContent={props.decodedContent}
          selectedFile={props.selectedFile}
          markdownView={props.markdownView}
          searchTerm={props.effectiveSearchTerm}
          searchHighlightedHtml={props.searchHighlightedHtml}
          highlightedHtml={props.highlightedHtml}
          fileContent={props.fileContent}
          onRefetch={props.onRefetchFile}
        />
      )}
    </div>
  )
}

// --- Main Page Component ---

export function ServerDetailPage() {
  const { id: serverId } = useParams<{ id: string }>()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const canUseTerminal = isAdmin || user?.terminal_access === true

  // File tree state
  const [treeState, setTreeState] = useState<Record<string, TreeNodeState>>({})
  const treeStateRef = useRef(treeState)
  treeStateRef.current = treeState
  const [selectedFile, setSelectedFile] = useState<FileNode | null>(null)
  const [markdownView, setMarkdownView] = useState<'raw' | 'rendered'>('rendered')
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    const saved = sessionStorage.getItem('aerodocs-sidebar-width')
    return saved ? Number(saved) : 288
  })
  const [isDragging, setIsDragging] = useState(false)
  const [treeRefreshing, setTreeRefreshing] = useState(false)
  const [liveTailing, setLiveTailing] = useState(false)
  const [workspaceMode, setWorkspaceMode] = useState<WorkspaceMode>('files')

  // In-file search state. Expensive matching/highlighting is deferred in useFileContentViewer.
  const [searchOpen, setSearchOpen] = useState(false)
  const [searchInput, setSearchInput] = useState('')
  const [currentMatch, setCurrentMatch] = useState(0)
  const searchInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    setCurrentMatch(0)
  }, [searchInput])

  // Server info query
  const {
    data: server,
    isLoading: serverLoading,
    error: serverError,
  } = useQuery({
    queryKey: ['server', serverId],
    queryFn: () => apiFetch<Server>(`/servers/${serverId}`),
    refetchInterval: 10_000,
    enabled: !!serverId,
  })

  // User's allowed root paths
  const {
    data: myPathsData,
    isLoading: pathsLoading,
  } = useQuery({
    queryKey: ['my-paths', serverId],
    queryFn: () => apiFetch<{ paths: string[] }>(`/servers/${serverId}/my-paths`),
    enabled: !!serverId && server?.status === 'online',
  })

  const rootPaths = useMemo(() => myPathsData?.paths ?? [], [myPathsData])

  // Build root nodes from paths
  const rootNodes: FileNode[] = useMemo(
    () =>
      rootPaths.map((p) => ({
        name: p,
        path: p,
        is_dir: true,
        size: 0,
        readable: true,
      })),
    [rootPaths],
  )

  // File content query
  const {
    data: fileContent,
    isLoading: fileLoading,
    error: fileError,
    refetch: refetchFile,
  } = useQuery({
    queryKey: ['file-content', serverId, selectedFile?.path],
    queryFn: () =>
      apiFetch<FileReadResponse>(
        `/servers/${serverId}/files/read?path=${encodeURIComponent(selectedFile!.path)}`,
      ),
    enabled: !!serverId && !!selectedFile && !selectedFile.is_dir,
  })

  const {
    decodedContent,
    effectiveSearchTerm,
    highlightedHtml,
    searchHighlightedHtml,
    matchCount,
  } = useFileContentViewer(fileContent, selectedFile, searchInput, currentMatch)

  // Toggle directory expansion — reads current state from ref to avoid treeState dependency
  const handleToggleDir = useCallback(
    async (dirPath: string) => {
      const current = treeStateRef.current[dirPath]
      if (current?.expanded) {
        // Collapse
        setTreeState((prev) => ({
          ...prev,
          [dirPath]: { ...prev[dirPath], expanded: false },
        }))
        return
      }

      // If already loaded, just expand
      if (current?.children !== null && current?.children !== undefined) {
        setTreeState((prev) => ({
          ...prev,
          [dirPath]: { ...prev[dirPath], expanded: true },
        }))
        return
      }

      // Fetch children
      setTreeState((prev) => ({
        ...prev,
        [dirPath]: { loading: true, expanded: true, children: null, error: null },
      }))

      try {
        const data = await apiFetch<FileListResponse>(
          `/servers/${serverId}/files?path=${encodeURIComponent(dirPath)}`,
        )
        const sorted = sortFileNodes(data.files)
        setTreeState((prev) => ({
          ...prev,
          [dirPath]: { loading: false, expanded: true, children: sorted, error: null },
        }))
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Failed to list directory'
        setTreeState((prev) => ({
          ...prev,
          [dirPath]: { loading: false, expanded: true, children: null, error: msg },
        }))
      }
    },
    [serverId],
  )

  const handleSelectFile = useCallback((node: FileNode) => {
    setSelectedFile(node)
    setMarkdownView('rendered')
    setLiveTailing(false)
    setSearchOpen(false)
    setSearchInput('')
    setCurrentMatch(0)
  }, [])

  // Refresh all expanded directories in the file tree
  const handleRefreshTree = useCallback(async () => {
    setTreeRefreshing(true)
    try {
      const expandedPaths = Object.entries(treeStateRef.current)
        .filter(([, state]) => state.expanded && state.children !== null)
        .map(([path]) => path)

      const results = await Promise.allSettled(
        expandedPaths.map(async (dirPath) => {
          const data = await apiFetch<FileListResponse>(
            `/servers/${serverId}/files?path=${encodeURIComponent(dirPath)}`,
          )
          const sorted = sortFileNodes(data.files)
          return { dirPath, children: sorted }
        }),
      )

      setTreeState((prev) => {
        const next = { ...prev }
        for (const result of results) {
          if (result.status === 'fulfilled') {
            const { dirPath, children } = result.value
            next[dirPath] = { loading: false, expanded: true, children, error: null }
          }
        }
        return next
      })
    } finally {
      setTreeRefreshing(false)
    }
  }, [serverId])

  // Resizable sidebar drag handlers
  const handleDragStart = useCallback(
    (e: ReactMouseEvent) => {
      e.preventDefault()
      const startX = e.clientX
      const startWidth = sidebarWidth
      setIsDragging(true)

      const handleMouseMove = (ev: MouseEvent) => {
        const delta = ev.clientX - startX
        const newWidth = Math.min(600, Math.max(200, startWidth + delta))
        setSidebarWidth(newWidth)
        sessionStorage.setItem('aerodocs-sidebar-width', String(newWidth))
      }

      const handleMouseUp = () => {
        setIsDragging(false)
        document.removeEventListener('mousemove', handleMouseMove)
        document.removeEventListener('mouseup', handleMouseUp)
      }

      document.addEventListener('mousemove', handleMouseMove)
      document.addEventListener('mouseup', handleMouseUp)
    },
    [sidebarWidth],
  )

  const handleResetWidth = useCallback(() => {
    setSidebarWidth(288)
    sessionStorage.setItem('aerodocs-sidebar-width', '288')
  }, [])

  // Reset tree state when server changes
  useEffect(() => {
    setTreeState({})
    setSelectedFile(null)
  }, [serverId])

  // Breadcrumb segments
  const breadcrumbs = useMemo(() => {
    if (!selectedFile) return []
    const parts = selectedFile.path.split('/').filter(Boolean)
    return parts.map((part, i) => ({
      name: part,
      path: '/' + parts.slice(0, i + 1).join('/'),
    }))
  }, [selectedFile])

  // Ctrl+F handler — open search bar
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault()
        setSearchOpen(true)
      }
    }
    globalThis.addEventListener('keydown', handler)
    return () => globalThis.removeEventListener('keydown', handler)
  }, [])

  // Scroll current match into view when it changes
  /* c8 ignore next 6 */
  useEffect(() => {
    if (effectiveSearchTerm && matchCount > 0) {
      const el = document.getElementById('current-search-match')
      if (el && 'scrollIntoView' in el && typeof el.scrollIntoView === 'function') {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' })
      }
    }
  }, [currentMatch, effectiveSearchTerm, matchCount])

  const handleRefetchFile = useCallback(() => {
    refetchFile().catch(() => undefined)
  }, [refetchFile])

  const handleToggleMarkdownView = useCallback(() => {
    setMarkdownView((v) => (v === 'raw' ? 'rendered' : 'raw'))
  }, [])

  const handleNavigatePrev = useCallback(() => {
    setCurrentMatch((i) => (matchCount > 0 ? (i - 1 + matchCount) % matchCount : 0))
  }, [matchCount])

  const handleNavigateNext = useCallback(() => {
    setCurrentMatch((i) => (matchCount > 0 ? (i + 1) % matchCount : 0))
  }, [matchCount])

  const handleCloseSearch = useCallback(() => {
    setSearchOpen(false)
    setSearchInput('')
    setCurrentMatch(0)
  }, [])

  const handleStopLiveTail = useCallback(() => {
    setLiveTailing(false)
  }, [])

  // --- Render ---

  if (serverLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="w-5 h-5 animate-spin text-text-muted" />
        <span className="ml-2 text-text-muted text-sm">Loading server...</span>
      </div>
    )
  }

  if (serverError || !server) {
    return (
      <div className="text-center py-16">
        <AlertTriangle className="w-8 h-8 text-status-error mx-auto mb-3" />
        <p className="text-text-primary text-sm mb-1">Failed to load server</p>
        <p className="text-text-muted text-xs mb-4">
          {serverError instanceof Error ? serverError.message : 'Server not found'}
        </p>
        <Link to="/" className="text-accent text-sm hover:underline">
          Back to dashboard
        </Link>
      </div>
    )
  }

  const isOffline = server.status !== 'online'
  const canUseTerminalForServer = canUseTerminal && (isAdmin || rootPaths.includes('/'))
  const effectiveWorkspaceMode = canUseTerminalForServer ? workspaceMode : 'files'

  return (
    <div className="flex flex-col h-[calc(100vh-92px)] overflow-hidden">
      <ServerDetailHeader server={server} />

      {isOffline && (
        <div className="bg-status-error/10 border-b border-status-error/20 px-4 py-2.5 flex items-center gap-2 shrink-0">
          <AlertTriangle className="w-4 h-4 text-status-error" />
          <span className="text-status-error text-sm">
            Server is offline. File browsing is unavailable until the agent reconnects.
          </span>
        </div>
      )}

      <WorkspaceModeBar
        workspaceMode={effectiveWorkspaceMode}
        onChange={setWorkspaceMode}
        offline={isOffline}
        terminalAvailable={canUseTerminalForServer}
      />

      <ServerWorkspacePanel
        workspaceMode={effectiveWorkspaceMode}
        isOffline={isOffline}
        isDragging={isDragging}
        server={server}
        serverId={serverId ?? ''}
        sidebarCollapsed={sidebarCollapsed}
        sidebarWidth={sidebarWidth}
        treeRefreshing={treeRefreshing}
        pathsLoading={pathsLoading}
        rootPaths={rootPaths}
        rootNodes={rootNodes}
        selectedFile={selectedFile}
        treeState={treeState}
        fileContent={fileContent}
        fileLoading={fileLoading}
        fileError={fileError}
        liveTailing={liveTailing}
        searchOpen={searchOpen}
        markdownView={markdownView}
        searchInput={searchInput}
        matchCount={matchCount}
        currentMatch={currentMatch}
        breadcrumbs={breadcrumbs}
        decodedContent={decodedContent}
        effectiveSearchTerm={effectiveSearchTerm}
        searchHighlightedHtml={searchHighlightedHtml}
        highlightedHtml={highlightedHtml}
        searchInputRef={searchInputRef}
        onToggleSidebar={() => setSidebarCollapsed((v) => !v)}
        onRefreshTree={handleRefreshTree}
        onToggleDir={handleToggleDir}
        onSelectFile={handleSelectFile}
        onDragStart={handleDragStart}
        onResetWidth={handleResetWidth}
        onRefetchFile={handleRefetchFile}
        onToggleSearch={() => setSearchOpen((v) => !v)}
        onToggleLiveTail={() => setLiveTailing((v) => !v)}
        onToggleMarkdownView={handleToggleMarkdownView}
        onSearchChange={setSearchInput}
        onNavigatePrev={handleNavigatePrev}
        onNavigateNext={handleNavigateNext}
        onCloseSearch={handleCloseSearch}
        onStopLiveTail={handleStopLiveTail}
      />

      {isAdmin && (
        <div className="shrink-0 border-t border-border p-4 bg-surface/30 space-y-3">
          <PathManagement serverId={serverId ?? ''} />
          <DropzoneUpload serverId={serverId ?? ''} />
        </div>
      )}
    </div>
  )
}

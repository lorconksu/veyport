import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, Download, Loader2, X } from 'lucide-react'
import { useAuth } from '@/hooks/use-auth'
import { formatFileSize } from '@/lib/file-viewer'
import { fetchImagePreview } from '@/lib/image-preview'
import type { FileNode } from '@/types/api'

const toolbarControl = 'inline-flex items-center gap-1 rounded border border-border bg-elevated px-2 py-1 text-xs text-text-secondary hover:text-text-primary aria-pressed:border-accent aria-pressed:text-accent'

interface ImagePreviewProps {
  serverId: string
  file: FileNode
  onClose: () => void
}

export function ImagePreview({ serverId, file, onClose }: Readonly<ImagePreviewProps>) {
  const { user } = useAuth()
  const [fit, setFit] = useState(true)
  const [decodeFailed, setDecodeFailed] = useState(false)
  const [loaded, setLoaded] = useState<{ blob: Blob; url: string } | null>(null)
  const imageRef = useRef<HTMLImageElement>(null)
  const { data, error, isFetching, refetch } = useQuery({
    queryKey: ['file-image', user?.id, serverId, file.path],
    queryFn: ({ signal }) => fetchImagePreview(serverId, file.path, signal),
    gcTime: 0,
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
  const source = isFetching || error || decodeFailed ? undefined : data
  const downloadURL = loaded?.blob === source ? loaded?.url : undefined

  useEffect(() => {
    const image = imageRef.current
    if (!source || !image) return
    const url = URL.createObjectURL(source)
    image.src = url
    return () => {
      image.removeAttribute('src')
      URL.revokeObjectURL(url)
    }
  }, [source])

  useEffect(() => {
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === 'Escape' && !event.defaultPrevented) onClose()
    }
    globalThis.addEventListener('keydown', closeOnEscape)
    return () => globalThis.removeEventListener('keydown', closeOnEscape)
  }, [onClose])

  function retry() {
    setDecodeFailed(false)
    setLoaded(null)
    void refetch()
  }

  return (
    <section aria-label="Image preview" className="flex min-h-0 min-w-0 flex-1 flex-col bg-surface/30">
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-border bg-surface/50 px-4 py-2">
        <div className="min-w-0">
          <p className="truncate text-sm font-medium text-text-primary" title={file.path}>{file.name}</p>
          {downloadURL && source && (
            <p className="text-xs text-text-muted">{formatFileSize(source.size)}</p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {downloadURL && (
            <>
              <button type="button" className={toolbarControl} aria-pressed={fit} onClick={() => setFit(true)}>
                Fit to window
              </button>
              <button type="button" className={toolbarControl} aria-pressed={!fit} onClick={() => setFit(false)}>
                Actual size
              </button>
              <a className={toolbarControl} href={downloadURL} download={file.name}>
                <Download className="size-3.5" aria-hidden="true" />
                Download
              </a>
            </>
          )}
          <button type="button" className={toolbarControl} onClick={onClose}>
            <X className="size-3.5" aria-hidden="true" />
            Close
          </button>
        </div>
      </div>

      {error || decodeFailed ? (
        <div role="alert" className="flex flex-col items-center px-4 py-16 text-center">
          <AlertTriangle className="mb-2 size-6 text-status-error" aria-hidden="true" />
          <p className="mb-1 text-sm text-text-primary">Failed to load image</p>
          <p className="mb-3 text-xs text-text-muted">{error?.message ?? 'The image could not be decoded'}</p>
          <button type="button" className={toolbarControl} onClick={retry}>Retry</button>
        </div>
      ) : (
        <div className="relative min-h-0 flex-1 overflow-auto">
          {!downloadURL && (
            <div role="status" className="absolute inset-x-0 top-16 flex items-center justify-center gap-2 text-sm text-text-muted">
              <Loader2 className="size-5 animate-spin" aria-hidden="true" />
              Loading image...
            </div>
          )}
          {source && (
            <div className={fit ? 'flex h-full items-center justify-center p-4' : 'min-w-max p-4'}>
              <img
                ref={imageRef}
                alt={file.name}
                aria-hidden={!downloadURL}
                className={`${downloadURL ? '' : 'invisible '}${fit ? 'h-auto max-h-full w-auto max-w-full object-contain' : 'h-auto w-auto max-w-none'}`}
                onLoad={event => setLoaded({ blob: source, url: event.currentTarget.src })}
                onError={() => { setLoaded(null); setDecodeFailed(true) }}
              />
            </div>
          )}
        </div>
      )}
    </section>
  )
}

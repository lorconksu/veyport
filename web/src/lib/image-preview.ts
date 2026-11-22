import { apiFetchResponse } from './api'

const MAX_IMAGE_BYTES = 10 * 1024 * 1024

export function imagePreviewType(path: string): string | null {
  if (/\.png$/i.test(path)) return 'image/png'
  if (/\.jpe?g$/i.test(path)) return 'image/jpeg'
  if (/\.webp$/i.test(path)) return 'image/webp'
  return null
}

export async function fetchImagePreview(serverId: string, path: string, signal: AbortSignal): Promise<Blob> {
  const type = imagePreviewType(path)
  if (!type) throw new Error('Unsupported image format')

  const response = await apiFetchResponse(
    `/servers/${encodeURIComponent(serverId)}/files/image?path=${encodeURIComponent(path)}`,
    { headers: { Accept: type }, signal },
  )
  const size = Number(response.headers.get('Content-Length'))
  if (response.status !== 200 || response.headers.get('Content-Type') !== type ||
      !Number.isSafeInteger(size) || size < 1 || size > MAX_IMAGE_BYTES || !response.body) {
    await response.body?.cancel().catch(() => undefined)
    throw new Error('Invalid image response')
  }

  const reader = response.body.getReader()
  const bytes = new Uint8Array(size)
  let offset = 0
  try {
    while (true) {
      signal.throwIfAborted()
      const { done, value } = await reader.read()
      if (done) break
      if (value.byteLength > size - offset) throw new Error('Invalid image response')
      bytes.set(value, offset)
      offset += value.byteLength
    }
    signal.throwIfAborted()
    if (offset !== size) throw new Error('Incomplete image response')
    return new Blob([bytes], { type })
  } catch (error) {
    await reader.cancel().catch(() => undefined)
    throw error
  } finally {
    reader.releaseLock()
  }
}

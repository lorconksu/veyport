/**
 * Reassembly of log lines from a log-tail SSE stream.
 *
 * The hub emits `data:` frames holding base64-encoded chunks of the tailed
 * file. Those chunks are whatever a single agent-side read returned, so they
 * are NOT line-aligned: one log line can straddle two frames. A consumer that
 * decodes and splits each frame independently renders such a line as two
 * broken lines.
 *
 * The assembler below carries the trailing partial line across frames (and
 * carries partial UTF-8 sequences across frames too, via a streaming decoder),
 * emitting only complete lines until the stream ends.
 */

/**
 * Maximum number of characters retained for a partial (not yet newline
 * terminated) line. Mirrors the 1 MiB cap used by the CLI log tail writer. A
 * partial line that grows past this is emitted as-is rather than buffered
 * without bound.
 */
export const MAX_PARTIAL_LINE_LENGTH = 1 << 20

export interface LogLineAssembler {
  /**
   * Consumes raw SSE protocol lines (without trailing newlines) and returns
   * the log lines that became complete as a result.
   */
  push(sseLines: string[]): string[]
  /**
   * Ends the stream, returning any buffered partial line as a final log line.
   */
  flush(): string[]
}

function decodeBase64(data: string): Uint8Array | null {
  try {
    return Uint8Array.from(atob(data), (c) => c.codePointAt(0)!)
  } catch {
    // Skip malformed base64 chunks
    return null
  }
}

export function createLogLineAssembler(): LogLineAssembler {
  const decoder = new TextDecoder('utf-8')
  // Trailing partial line carried across frames.
  let partial = ''
  // Event name of the SSE frame currently being parsed ('' means the default
  // `message` event, i.e. a log data frame).
  let pendingEvent = ''

  // Appends decoded text to the carry buffer and drains complete lines into
  // `out`. Empty lines are dropped, matching how the log viewer has always
  // rendered blank log output.
  function absorb(text: string, out: string[]): void {
    if (text === '') return
    partial += text

    if (partial.includes('\n')) {
      const segments = partial.split('\n')
      partial = segments.pop() ?? ''
      for (const segment of segments) {
        if (segment !== '') out.push(segment)
      }
    }

    if (partial.length > MAX_PARTIAL_LINE_LENGTH) {
      out.push(partial)
      partial = ''
    }
  }

  return {
    push(sseLines: string[]): string[] {
      const out: string[] = []

      for (const sseLine of sseLines) {
        // Blank line terminates the current SSE frame.
        if (sseLine === '') {
          pendingEvent = ''
          continue
        }
        if (sseLine.startsWith('event:')) {
          pendingEvent = sseLine.slice(6).trim()
          continue
        }
        if (!sseLine.startsWith('data: ')) continue
        // Named events (e.g. `overflow`) carry JSON notices, not log bytes,
        // and must never enter the carry buffer.
        if (pendingEvent !== '' && pendingEvent !== 'message') continue

        const base64Data = sseLine.slice(6)
        if (!base64Data) continue

        const bytes = decodeBase64(base64Data)
        if (bytes === null) continue

        absorb(decoder.decode(bytes, { stream: true }), out)
      }

      return out
    },

    flush(): string[] {
      const out: string[] = []
      // Flush any incomplete trailing UTF-8 sequence.
      absorb(decoder.decode(), out)
      if (partial !== '') {
        out.push(partial)
        partial = ''
      }
      pendingEvent = ''
      return out
    },
  }
}

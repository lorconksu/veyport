import { MAX_PARTIAL_LINE_LENGTH, createLogLineAssembler } from '../log-stream'

// Encodes raw bytes the way the hub does: base64 of the chunk read from the file.
function dataFrame(chunk: string | Uint8Array): string {
  const bytes = typeof chunk === 'string' ? new TextEncoder().encode(chunk) : chunk
  let binary = ''
  for (const byte of bytes) binary += String.fromCodePoint(byte)
  return `data: ${btoa(binary)}`
}

describe('createLogLineAssembler', () => {
  it('reassembles a log line straddling two frames', () => {
    const assembler = createLogLineAssembler()

    expect(assembler.push([dataFrame('alpha\nbeta par'), ''])).toEqual(['alpha'])
    expect(assembler.push([dataFrame('tial\ngamma\n'), ''])).toEqual(['beta partial', 'gamma'])
    expect(assembler.flush()).toEqual([])
  })

  it('emits every complete line contained in a single frame', () => {
    const assembler = createLogLineAssembler()

    expect(assembler.push([dataFrame('line 1\nline 2\nline 3\n'), ''])).toEqual([
      'line 1',
      'line 2',
      'line 3',
    ])
  })

  it('holds back a line until its newline arrives', () => {
    const assembler = createLogLineAssembler()

    expect(assembler.push([dataFrame('no newline yet'), ''])).toEqual([])
    expect(assembler.push([dataFrame(' still going'), ''])).toEqual([])
    expect(assembler.push([dataFrame('\n'), ''])).toEqual(['no newline yet still going'])
  })

  it('flushes the trailing partial line when the stream closes', () => {
    const assembler = createLogLineAssembler()

    expect(assembler.push([dataFrame('done\nunterminated tail'), ''])).toEqual(['done'])
    expect(assembler.flush()).toEqual(['unterminated tail'])
    // Flushing twice must not repeat the line.
    expect(assembler.flush()).toEqual([])
  })

  it('returns nothing for empty frames, empty data and non-data lines', () => {
    const assembler = createLogLineAssembler()

    expect(assembler.push([])).toEqual([])
    expect(assembler.push([''])).toEqual([])
    expect(assembler.push(['data: '])).toEqual([])
    expect(assembler.push([dataFrame(''), ''])).toEqual([])
    expect(assembler.push([': keep-alive comment', 'id: 7'])).toEqual([])
    expect(assembler.flush()).toEqual([])
  })

  it('drops blank log lines', () => {
    const assembler = createLogLineAssembler()

    expect(assembler.push([dataFrame('first\n\n\nsecond\n'), ''])).toEqual(['first', 'second'])
  })

  it('skips malformed base64 without breaking reassembly', () => {
    const assembler = createLogLineAssembler()

    expect(assembler.push([dataFrame('good pre'), '', 'data: !!!not-base64!!!', ''])).toEqual([])
    expect(assembler.push([dataFrame('fix\n'), ''])).toEqual(['good prefix'])
  })

  it('ignores overflow notice frames and keeps the carry buffer intact', () => {
    const assembler = createLogLineAssembler()

    expect(assembler.push([dataFrame('split '), ''])).toEqual([])
    expect(assembler.push(['event: overflow', 'data: {"dropped":12}', ''])).toEqual([])
    expect(assembler.push([dataFrame('line\n'), ''])).toEqual(['split line'])
  })

  it('resumes normal data frames after a named event frame', () => {
    const assembler = createLogLineAssembler()

    expect(
      assembler.push(['event: overflow', 'data: {"dropped":1}', '', dataFrame('after\n'), '']),
    ).toEqual(['after'])
  })

  it('reassembles multi-byte UTF-8 characters split across frames', () => {
    const assembler = createLogLineAssembler()
    const encoded = new TextEncoder().encode('héllo → wörld\n')
    const cut = 2 // splits the two-byte "é"

    expect(assembler.push([dataFrame(encoded.slice(0, cut)), ''])).toEqual([])
    expect(assembler.push([dataFrame(encoded.slice(cut)), ''])).toEqual(['héllo → wörld'])
  })

  it('flushes an oversized partial line instead of buffering without bound', () => {
    const assembler = createLogLineAssembler()
    const huge = 'x'.repeat(MAX_PARTIAL_LINE_LENGTH + 1)

    const emitted = assembler.push([dataFrame(huge), ''])
    expect(emitted).toHaveLength(1)
    expect(emitted[0]).toHaveLength(MAX_PARTIAL_LINE_LENGTH + 1)

    // The buffer was reset, so the next chunk starts a fresh line.
    expect(assembler.push([dataFrame('tail\n'), ''])).toEqual(['tail'])
    expect(assembler.flush()).toEqual([])
  })

  it('does not flush a partial line that is exactly at the cap', () => {
    const assembler = createLogLineAssembler()
    const atCap = 'y'.repeat(MAX_PARTIAL_LINE_LENGTH)

    expect(assembler.push([dataFrame(atCap), ''])).toEqual([])
    expect(assembler.flush()).toEqual([atCap])
  })
})

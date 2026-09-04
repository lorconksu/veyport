import { render, screen, fireEvent, act } from '@testing-library/react'
import { vi } from 'vitest'
import { InstallCliModal } from '../install-cli-modal'

// Mock clipboard
Object.assign(navigator, {
  clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
})

function renderModal(onClose = vi.fn()) {
  return render(<InstallCliModal onClose={onClose} />)
}

describe('InstallCliModal', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('renders Install CLI heading', () => {
    renderModal()
    expect(screen.getByText('Install CLI')).toBeInTheDocument()
  })

  it('renders the curl install command with the current origin', () => {
    renderModal()
    const expected = `curl -fsSL ${window.location.origin}/install/cli.sh | sh`
    expect(screen.getByText(expected)).toBeInTheDocument()
  })

  it('renders the sign-in command with the current origin', () => {
    renderModal()
    const expected = `vey --hub ${window.location.origin} login`
    expect(screen.getByText(expected)).toBeInTheDocument()
  })

  it('renders a footnote about hub-served binaries and no Windows support', () => {
    renderModal()
    expect(screen.getByText(/binaries and checksums are served by this hub/i)).toBeInTheDocument()
    expect(screen.getByText(/windows/i)).toBeInTheDocument()
  })

  it('copy button copies the full install command to the clipboard', async () => {
    renderModal()
    const expected = `curl -fsSL ${window.location.origin}/install/cli.sh | sh`

    const copyBtn = screen.getByTitle('Copy install command')
    fireEvent.click(copyBtn)

    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expected)
  })

  it('copy button flips to the Check icon after copying and reverts after timeout', async () => {
    vi.useFakeTimers()
    try {
      renderModal()
      const copyBtn = screen.getByTitle('Copy install command')

      await act(async () => {
        fireEvent.click(copyBtn)
        await Promise.resolve()
        await Promise.resolve()
      })
      expect(copyBtn.querySelector('.lucide-check')).toBeInTheDocument()

      await act(async () => {
        vi.advanceTimersByTime(2100)
      })

      expect(copyBtn.querySelector('.lucide-copy')).toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })

  it('sign-in copy button copies the login command and flips to the Check icon', async () => {
    vi.useFakeTimers()
    try {
      renderModal()
      const expected = `vey --hub ${window.location.origin} login`
      const copyBtn = screen.getByTitle('Copy sign-in command')

      await act(async () => {
        fireEvent.click(copyBtn)
        await Promise.resolve()
        await Promise.resolve()
      })

      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expected)
      expect(copyBtn.querySelector('.lucide-check')).toBeInTheDocument()

      await act(async () => {
        vi.advanceTimersByTime(2100)
      })

      expect(copyBtn.querySelector('.lucide-copy')).toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })

  it('close (X) button calls onClose and is always enabled', () => {
    const onClose = vi.fn()
    renderModal(onClose)

    const closeBtn = screen.getByTitle('Close')
    expect(closeBtn).not.toBeDisabled()
    fireEvent.click(closeBtn)
    expect(onClose).toHaveBeenCalled()
  })
})

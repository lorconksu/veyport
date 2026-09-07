import { render, screen, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { TOTPDigitInput, useTOTPDigits } from '../totp-digit-input'

// Helper to create a complete digit array
const SIX_DIGITS = ['1', '2', '3', '4', '5', '6']

// ---- useTOTPDigits hook tests ----

describe('useTOTPDigits hook', () => {
  it('initializes with 6 empty digits', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    expect(result.current.digits).toEqual(['', '', '', '', '', ''])
  })

  it('handleDigitChange updates a digit at index', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    act(() => result.current.handleDigitChange(0, '5'))
    expect(result.current.digits[0]).toBe('5')
  })

  it('handleDigitChange ignores non-digit characters', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    act(() => result.current.handleDigitChange(0, 'a'))
    expect(result.current.digits[0]).toBe('')
  })

  it('handleDigitChange distributes a full autofilled code across all boxes from index 0', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    const mockFocus5 = vi.fn()
    act(() => {
      result.current.inputRefs.current[5] = { focus: mockFocus5 } as unknown as HTMLInputElement
      result.current.handleDigitChange(0, '123456')
    })
    expect(result.current.digits).toEqual(['1', '2', '3', '4', '5', '6'])
    expect(mockFocus5).toHaveBeenCalled()
    expect(onComplete).toHaveBeenCalledTimes(1)
    expect(onComplete).toHaveBeenCalledWith('123456')
  })

  it('handleDigitChange distributes a partial multi-digit value from a middle index', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    const mockFocus4 = vi.fn()
    act(() => {
      result.current.inputRefs.current[4] = { focus: mockFocus4 } as unknown as HTMLInputElement
      result.current.handleDigitChange(2, '34')
    })
    expect(result.current.digits[2]).toBe('3')
    expect(result.current.digits[3]).toBe('4')
    expect(mockFocus4).toHaveBeenCalled()
    expect(onComplete).not.toHaveBeenCalled()
  })

  it('handleDigitChange ignores a multi-char value that contains non-digits', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    act(() => result.current.handleDigitChange(0, '12ab3'))
    expect(result.current.digits).toEqual(['', '', '', '', '', ''])
    expect(onComplete).not.toHaveBeenCalled()
  })

  it('handleDigitChange still handles a single typed character normally', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    const mockFocus1 = vi.fn()
    act(() => {
      result.current.inputRefs.current[1] = { focus: mockFocus1 } as unknown as HTMLInputElement
      result.current.handleDigitChange(0, '7')
    })
    expect(result.current.digits[0]).toBe('7')
    expect(mockFocus1).toHaveBeenCalled()
  })

  it('calls onComplete when all digits are filled via paste', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    // Paste fills all 6 digits in one shot — this is the reliable way to trigger onComplete
    const pasteEvent = {
      preventDefault: vi.fn(),
      clipboardData: { getData: () => '123456' },
    } as unknown as React.ClipboardEvent
    act(() => result.current.handlePaste(pasteEvent))
    expect(onComplete).toHaveBeenCalledWith('123456')
  })

  it('does not call onComplete if digits are incomplete', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    act(() => result.current.handleDigitChange(0, '1'))
    expect(onComplete).not.toHaveBeenCalled()
  })

  it('handlePaste fills digits from pasted text', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    const pasteEvent = {
      preventDefault: vi.fn(),
      clipboardData: { getData: () => '123456' },
    } as unknown as React.ClipboardEvent
    act(() => result.current.handlePaste(pasteEvent))
    expect(result.current.digits).toEqual(['1', '2', '3', '4', '5', '6'])
    expect(onComplete).toHaveBeenCalledWith('123456')
  })

  it('handlePaste strips non-digit characters', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    const pasteEvent = {
      preventDefault: vi.fn(),
      clipboardData: { getData: () => 'abc123def456' },
    } as unknown as React.ClipboardEvent
    act(() => result.current.handlePaste(pasteEvent))
    expect(result.current.digits).toEqual(['1', '2', '3', '4', '5', '6'])
  })

  it('handlePaste handles partial paste (fewer than 6 digits)', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    const pasteEvent = {
      preventDefault: vi.fn(),
      clipboardData: { getData: () => '123' },
    } as unknown as React.ClipboardEvent
    act(() => result.current.handlePaste(pasteEvent))
    expect(result.current.digits[0]).toBe('1')
    expect(result.current.digits[1]).toBe('2')
    expect(result.current.digits[2]).toBe('3')
    expect(result.current.digits[3]).toBe('')
    expect(onComplete).not.toHaveBeenCalled()
  })

  it('handlePaste does nothing for empty paste', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    const pasteEvent = {
      preventDefault: vi.fn(),
      clipboardData: { getData: () => 'abc' }, // no digits
    } as unknown as React.ClipboardEvent
    act(() => result.current.handlePaste(pasteEvent))
    expect(result.current.digits).toEqual(['', '', '', '', '', ''])
  })

  it('handleKeyDown on Backspace at index 0 does not navigate', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    // Should not throw
    act(() => {
      result.current.handleKeyDown(0, { key: 'Backspace' } as React.KeyboardEvent)
    })
    expect(result.current.digits).toEqual(['', '', '', '', '', ''])
  })

  it('handleKeyDown on Backspace focuses previous input when current is empty and index > 0', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    const mockFocus = vi.fn()
    // Simulate refs set
    act(() => {
      result.current.inputRefs.current[0] = { focus: mockFocus } as unknown as HTMLInputElement
      result.current.handleKeyDown(1, { key: 'Backspace' } as React.KeyboardEvent)
    })
    expect(mockFocus).toHaveBeenCalled()
  })

  it('handleKeyDown on other keys does nothing special', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    act(() => {
      result.current.handleKeyDown(2, { key: 'ArrowLeft' } as React.KeyboardEvent)
    })
    expect(result.current.digits).toEqual(['', '', '', '', '', ''])
  })

  it('reset clears all digits', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    act(() => {
      for (let i = 0; i < 5; i++) result.current.handleDigitChange(i, String(i + 1))
    })
    act(() => result.current.reset())
    expect(result.current.digits).toEqual(['', '', '', '', '', ''])
  })

  it('reset focuses the first input', () => {
    const onComplete = vi.fn()
    const { result } = renderHook(() => useTOTPDigits(onComplete))
    const mockFocus = vi.fn()
    act(() => {
      result.current.inputRefs.current[0] = { focus: mockFocus } as unknown as HTMLInputElement
      result.current.reset()
    })
    expect(mockFocus).toHaveBeenCalled()
  })
})

// ---- TOTPDigitInput component tests ----

describe('TOTPDigitInput component', () => {
  const defaultProps = {
    digits: ['', '', '', '', '', ''],
    inputRefs: { current: [] } as React.MutableRefObject<(HTMLInputElement | null)[]>,
    handleDigitChange: vi.fn(),
    handlePaste: vi.fn(),
    handleKeyDown: vi.fn(),
  }

  it('renders 6 input elements', () => {
    render(<TOTPDigitInput {...defaultProps} />)
    const inputs = screen.getAllByRole('textbox')
    expect(inputs).toHaveLength(6)
  })

  it('renders with provided digit values', () => {
    render(<TOTPDigitInput {...defaultProps} digits={SIX_DIGITS} />)
    const inputs = screen.getAllByRole('textbox')
    SIX_DIGITS.forEach((digit, i) => {
      expect((inputs[i] as HTMLInputElement).value).toBe(digit)
    })
  })

  it('disables all inputs when disabled=true', () => {
    render(<TOTPDigitInput {...defaultProps} disabled={true} />)
    const inputs = screen.getAllByRole('textbox')
    inputs.forEach((input) => {
      expect(input).toBeDisabled()
    })
  })

  it('enables inputs when disabled=false', () => {
    render(<TOTPDigitInput {...defaultProps} disabled={false} />)
    const inputs = screen.getAllByRole('textbox')
    inputs.forEach((input) => {
      expect(input).not.toBeDisabled()
    })
  })

  it('calls handleDigitChange on input change', async () => {
    const handleDigitChange = vi.fn()
    render(<TOTPDigitInput {...defaultProps} handleDigitChange={handleDigitChange} />)
    const inputs = screen.getAllByRole('textbox')
    fireEvent.change(inputs[0], { target: { value: '7' } })
    expect(handleDigitChange).toHaveBeenCalledWith(0, '7')
  })

  it('calls handleKeyDown on key press', () => {
    const handleKeyDown = vi.fn()
    render(<TOTPDigitInput {...defaultProps} handleKeyDown={handleKeyDown} />)
    const inputs = screen.getAllByRole('textbox')
    fireEvent.keyDown(inputs[2], { key: 'Backspace' })
    expect(handleKeyDown).toHaveBeenCalledWith(2, expect.objectContaining({ key: 'Backspace' }))
  })

  it('calls handlePaste on paste event', () => {
    const handlePaste = vi.fn()
    render(<TOTPDigitInput {...defaultProps} handlePaste={handlePaste} />)
    const inputs = screen.getAllByRole('textbox')
    fireEvent.paste(inputs[0], {
      clipboardData: { getData: () => '123456' },
    })
    expect(handlePaste).toHaveBeenCalled()
  })

  it('marks the first box as autocomplete one-time-code and the rest as off', () => {
    render(<TOTPDigitInput {...defaultProps} />)
    const inputs = screen.getAllByRole('textbox')
    expect(inputs[0]).toHaveAttribute('autocomplete', 'one-time-code')
    for (let i = 1; i < 6; i++) {
      expect(inputs[i]).toHaveAttribute('autocomplete', 'off')
    }
  })

  it('allows up to 6 characters in the first box (for autofill) but only 1 in the rest', () => {
    render(<TOTPDigitInput {...defaultProps} />)
    const inputs = screen.getAllByRole('textbox')
    expect(inputs[0]).toHaveAttribute('maxlength', '6')
    for (let i = 1; i < 6; i++) {
      expect(inputs[i]).toHaveAttribute('maxlength', '1')
    }
  })
})

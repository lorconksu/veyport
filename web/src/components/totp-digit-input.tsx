import { useState, useRef } from 'react'

export function useTOTPDigits(onComplete: (code: string) => void) {
  const [digits, setDigits] = useState(['', '', '', '', '', ''])
  const inputRefs = useRef<(HTMLInputElement | null)[]>([])

  const handleDigitChange = (index: number, value: string) => {
    if (!/^\d*$/.test(value)) return

    // Password managers (e.g. 1Password) can autofill a full one-time code into
    // whichever box currently has focus as a single change event. Distribute it
    // across the remaining boxes the same way a paste is distributed.
    if (value.length > 1) {
      const distributed = value.slice(0, 6 - index)
      const newDigits = [...digits]
      for (let i = 0; i < distributed.length; i++) {
        newDigits[index + i] = distributed[i]
      }
      setDigits(newDigits)

      const lastFilledIndex = index + distributed.length - 1
      const nextIndex = lastFilledIndex < 5 ? lastFilledIndex + 1 : 5
      inputRefs.current[nextIndex]?.focus()

      if (newDigits.every(Boolean)) onComplete(newDigits.join(''))
      return
    }

    const newDigits = [...digits]
    newDigits[index] = value.slice(-1)
    setDigits(newDigits)

    if (value && index < 5) {
      inputRefs.current[index + 1]?.focus()
    }

    if (newDigits.every(Boolean) && index === 5) {
      onComplete(newDigits.join(''))
    }
  }

  const handlePaste = (e: React.ClipboardEvent) => {
    e.preventDefault()
    const pasted = e.clipboardData.getData('text').replaceAll(/\D/g, '').slice(0, 6)
    if (!pasted) return
    const newDigits = [...digits]
    for (let i = 0; i < pasted.length; i++) {
      newDigits[i] = pasted[i]
    }
    setDigits(newDigits)
    const nextEmpty = pasted.length < 6 ? pasted.length : 5
    inputRefs.current[nextEmpty]?.focus()
    if (newDigits.every(Boolean)) onComplete(newDigits.join(''))
  }

  const handleKeyDown = (index: number, e: React.KeyboardEvent) => {
    if (e.key === 'Backspace' && !digits[index] && index > 0) {
      inputRefs.current[index - 1]?.focus()
    }
  }

  const reset = () => {
    setDigits(['', '', '', '', '', ''])
    inputRefs.current[0]?.focus()
  }

  return { digits, inputRefs, handleDigitChange, handlePaste, handleKeyDown, reset }
}

type TOTPDigitInputProps = Readonly<{
  digits: string[]
  inputRefs: { current: (HTMLInputElement | null)[] }
  handleDigitChange: (index: number, value: string) => void
  handlePaste: (e: React.ClipboardEvent) => void
  handleKeyDown: (index: number, e: React.KeyboardEvent) => void
  disabled?: boolean
}>

const DIGIT_POSITIONS = [0, 1, 2, 3, 4, 5] as const

export function TOTPDigitInput({
  digits,
  inputRefs,
  handleDigitChange,
  handlePaste,
  handleKeyDown,
  disabled = false,
}: TOTPDigitInputProps) {
  return (
    <div className="flex gap-2 justify-center mb-4">
      {DIGIT_POSITIONS.map((position) => (
        <input
          key={position}
          ref={el => { inputRefs.current[position] = el }}
          type="text"
          inputMode="numeric"
          maxLength={position === 0 ? 6 : 1}
          autoComplete={position === 0 ? 'one-time-code' : 'off'}
          value={digits[position]}
          onChange={(e) => handleDigitChange(position, e.target.value)}
          onKeyDown={(e) => handleKeyDown(position, e)}
          onPaste={handlePaste}
          className="w-10 h-12 bg-elevated border border-border rounded text-center text-lg font-mono text-text-primary focus:outline-none focus:border-accent"
          autoFocus={position === 0}
          disabled={disabled}
        />
      ))}
    </div>
  )
}

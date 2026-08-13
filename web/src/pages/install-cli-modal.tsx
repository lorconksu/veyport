import { useState } from 'react'
import { X, Copy, Check } from 'lucide-react'

interface InstallCliModalProps {
  onClose: () => void
}

const COPY_RESET_MS = 2000

export function InstallCliModal({ onClose }: Readonly<InstallCliModalProps>) {
  const [copied, setCopied] = useState(false)
  const [loginCopied, setLoginCopied] = useState(false)

  const installCommand = `curl -fsSL ${window.location.origin}/install/cli.sh | sh`
  const loginCommand = `vey --hub ${window.location.origin} login`

  const handleCopy = async () => {
    await navigator.clipboard.writeText(installCommand)
    setCopied(true)
    setTimeout(() => setCopied(false), COPY_RESET_MS)
  }

  const handleCopyLogin = async () => {
    await navigator.clipboard.writeText(loginCommand)
    setLoginCopied(true)
    setTimeout(() => setLoginCopied(false), COPY_RESET_MS)
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-surface border border-border rounded-lg w-full max-w-lg mx-4 p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-text-primary font-semibold">Install CLI</h3>
          <button
            type="button"
            onClick={onClose}
            title="Close"
            className="text-text-muted hover:text-text-primary"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-sm text-text-secondary mb-3">
          Installs the <span className="text-text-primary font-medium">vey</span> CLI. One
          command for Linux and macOS — it auto-detects your platform.
        </p>

        <div className="relative">
          <pre className="bg-base border border-border rounded p-3 text-xs font-mono text-text-secondary overflow-x-auto whitespace-pre-wrap break-all">
            {installCommand}
          </pre>
          <button
            type="button"
            onClick={handleCopy}
            className="absolute top-2 right-2 p-1 bg-elevated border border-border rounded text-text-muted hover:text-text-primary transition-colors"
            title="Copy install command"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-status-online" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        </div>

        <p className="text-xs text-text-muted mt-4 mb-2">then sign in:</p>
        <div className="relative">
          <pre className="bg-base border border-border rounded p-3 text-xs font-mono text-text-secondary overflow-x-auto whitespace-pre-wrap break-all">
            {loginCommand}
          </pre>
          <button
            type="button"
            onClick={handleCopyLogin}
            className="absolute top-2 right-2 p-1 bg-elevated border border-border rounded text-text-muted hover:text-text-primary transition-colors"
            title="Copy sign-in command"
          >
            {loginCopied ? <Check className="w-3.5 h-3.5 text-status-online" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        </div>

        <p className="text-xs text-text-faint mt-4">
          Binaries and checksums are served by this hub. Windows is not yet supported.
        </p>

        <div className="flex justify-end mt-4">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 bg-elevated hover:bg-border text-text-primary text-sm rounded transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}

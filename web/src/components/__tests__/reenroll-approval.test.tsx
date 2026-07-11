import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ReEnrollApproval } from '../reenroll-approval'
import type { ReEnrollRequest } from '@/types/api'

vi.mock('@/lib/api', () => ({
  approveReEnroll: vi.fn(),
  denyReEnroll: vi.fn(),
}))

import { approveReEnroll, denyReEnroll } from '@/lib/api'
const mockApprove = approveReEnroll as ReturnType<typeof vi.fn>
const mockDeny = denyReEnroll as ReturnType<typeof vi.fn>

function makeRequest(overrides?: Partial<ReEnrollRequest>): ReEnrollRequest {
  return {
    id: 're-1',
    server_id: 'srv',
    requested_at: '2026-07-11T00:00:00Z',
    ip_address: '10.0.0.1',
    fingerprint: 'fp2',
    status: 'pending',
    anomaly_flags: '{}',
    decided_by: null,
    ...overrides,
  }
}

function renderApproval(request: ReEnrollRequest) {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })
  return render(
    <QueryClientProvider client={qc}>
      <ReEnrollApproval request={request} />
    </QueryClientProvider>,
  )
}

describe('ReEnrollApproval', () => {
  beforeEach(() => {
    mockApprove.mockReset()
    mockDeny.mockReset()
  })

  // Task 9 brief test (intent preserved; wrapped in QueryClientProvider per project pattern)
  it('shows a clone warning and requires a TOTP code to approve', async () => {
    renderApproval({ id: 're-1', server_id: 'srv', fingerprint: 'fp2',
      status: 'pending', anomaly_flags: '{"fingerprint_changed":true,"original_online":true}' } as any)
    expect(screen.getByText(/possible clone/i)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /approve/i }))
    expect(screen.getByText(/enter.*totp|authenticator code/i)).toBeInTheDocument()
  })

  it('does not show clone warning when no anomaly flags are set', () => {
    renderApproval(makeRequest({ anomaly_flags: '{"fingerprint_changed":false,"original_online":false}' }))
    expect(screen.queryByText(/possible clone/i)).not.toBeInTheDocument()
  })

  it('shows clone warning when only fingerprint_changed is true', () => {
    renderApproval(makeRequest({ anomaly_flags: '{"fingerprint_changed":true,"original_online":false}' }))
    expect(screen.getByText(/possible clone/i)).toBeInTheDocument()
  })

  it('shows clone warning when only original_online is true', () => {
    renderApproval(makeRequest({ anomaly_flags: '{"fingerprint_changed":false,"original_online":true}' }))
    expect(screen.getByText(/possible clone/i)).toBeInTheDocument()
  })

  it('renders Approve and Deny buttons', () => {
    renderApproval(makeRequest())
    expect(screen.getByRole('button', { name: /approve/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /deny/i })).toBeInTheDocument()
  })

  it('clicking Approve reveals TOTP prompt', async () => {
    renderApproval(makeRequest())
    await userEvent.click(screen.getByRole('button', { name: /approve/i }))
    expect(screen.getByText(/enter.*totp|authenticator code/i)).toBeInTheDocument()
    // TOTP digit inputs should now be visible (6 inputs)
    const inputs = screen.getAllByRole('textbox')
    expect(inputs.length).toBe(6)
  })

  it('calls denyReEnroll when Deny is clicked', async () => {
    mockDeny.mockResolvedValue(undefined)
    renderApproval(makeRequest())
    await userEvent.click(screen.getByRole('button', { name: /deny/i }))
    await waitFor(() => {
      expect(mockDeny).toHaveBeenCalledWith('srv', 're-1')
    })
  })
})

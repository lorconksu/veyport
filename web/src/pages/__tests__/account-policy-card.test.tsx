import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AccountPolicyCard } from '../account-policy-card'

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

import { apiFetch } from '@/lib/api'
const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>

const defaultHubConfig = {
  grpc_external_addr: '',
  lockout_threshold: 5,
  lockout_window_minutes: 15,
  lockout_duration_minutes: 30,
  dormant_days: 35,
  session_idle_minutes: 15,
  session_max_hours: 12,
}

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AccountPolicyCard />
    </QueryClientProvider>,
  )
}

describe('AccountPolicyCard', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
  })

  it('shows a loading state while fetching', async () => {
    mockApiFetch.mockReturnValue(new Promise(() => {}))
    renderCard()
    expect(screen.getByText('Loading...')).toBeInTheDocument()
  })

  it('renders the title and effective values from /settings/hub', async () => {
    mockApiFetch.mockResolvedValueOnce(defaultHubConfig)
    renderCard()

    await screen.findByLabelText('Lockout threshold (failures)')
    expect(screen.getByText('Account policy')).toBeInTheDocument()
    expect(screen.getByLabelText('Lockout threshold (failures)')).toHaveValue(5)
    expect(screen.getByLabelText('Lockout window (minutes)')).toHaveValue(15)
    expect(screen.getByLabelText('Lock duration (minutes)')).toHaveValue(30)
    expect(screen.getByLabelText('Dormant after (days)')).toHaveValue(35)
    expect(screen.getByLabelText('Idle timeout (minutes)')).toHaveValue(15)
    expect(screen.getByLabelText('Maximum session (hours)')).toHaveValue(12)
  })

  it('shows helper text under each field', async () => {
    mockApiFetch.mockResolvedValueOnce(defaultHubConfig)
    renderCard()

    await screen.findByLabelText('Lockout threshold (failures)')
    expect(screen.getByText('0 disables locking')).toBeInTheDocument()
    expect(screen.getByText('0 = no auto-unlock')).toBeInTheDocument()
    expect(screen.getByText('0 disables dormancy')).toBeInTheDocument()
    expect(screen.getByText('0 disables the idle limit')).toBeInTheDocument()
    expect(screen.getByText('0 disables the absolute limit')).toBeInTheDocument()
  })

  it('shows a field error and does not PUT when a value is negative', async () => {
    mockApiFetch.mockResolvedValueOnce(defaultHubConfig)
    renderCard()

    await screen.findByLabelText('Lockout threshold (failures)')
    fireEvent.change(screen.getByLabelText('Lockout threshold (failures)'), { target: { value: '-1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => {
      expect(screen.getByText('Must be a non-negative integer')).toBeInTheDocument()
    })
    expect(mockApiFetch).not.toHaveBeenCalledWith('/settings/hub', expect.objectContaining({ method: 'PUT' }))
  })

  it('shows a field error and does not PUT when a value is non-integer', async () => {
    mockApiFetch.mockResolvedValueOnce(defaultHubConfig)
    renderCard()

    await screen.findByLabelText('Dormant after (days)')
    fireEvent.change(screen.getByLabelText('Dormant after (days)'), { target: { value: '1.5' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => {
      expect(screen.getByText('Must be a non-negative integer')).toBeInTheDocument()
    })
    expect(mockApiFetch).not.toHaveBeenCalledWith('/settings/hub', expect.objectContaining({ method: 'PUT' }))
  })

  it('saves with exactly the six fields as integers and shows a success message', async () => {
    mockApiFetch.mockResolvedValueOnce(defaultHubConfig) // GET
    mockApiFetch.mockResolvedValueOnce({ ...defaultHubConfig, dormant_days: 1 }) // PUT response
    renderCard()

    await screen.findByLabelText('Dormant after (days)')
    fireEvent.change(screen.getByLabelText('Dormant after (days)'), { target: { value: '1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/settings/hub', {
        method: 'PUT',
        body: JSON.stringify({
          lockout_threshold: 5,
          lockout_window_minutes: 15,
          lockout_duration_minutes: 30,
          dormant_days: 1,
          session_idle_minutes: 15,
          session_max_hours: 12,
        }),
      })
    })

    await waitFor(() => {
      expect(screen.getByText('Account policy saved.')).toBeInTheDocument()
    })
  })

  it('shows a field error and does not PUT when the idle-timeout value is negative', async () => {
    mockApiFetch.mockResolvedValueOnce(defaultHubConfig)
    renderCard()

    await screen.findByLabelText('Idle timeout (minutes)')
    fireEvent.change(screen.getByLabelText('Idle timeout (minutes)'), { target: { value: '-5' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => {
      expect(screen.getByText('Must be a non-negative integer')).toBeInTheDocument()
    })
    expect(mockApiFetch).not.toHaveBeenCalledWith('/settings/hub', expect.objectContaining({ method: 'PUT' }))
  })

  it('shows an error banner when the API rejects the save', async () => {
    mockApiFetch.mockResolvedValueOnce(defaultHubConfig) // GET
    mockApiFetch.mockRejectedValueOnce(new Error('dormant_days must be a non-negative integer')) // PUT
    renderCard()

    await screen.findByLabelText('Lockout threshold (failures)')
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => {
      expect(screen.getByText('dormant_days must be a non-negative integer')).toBeInTheDocument()
    })
  })
})

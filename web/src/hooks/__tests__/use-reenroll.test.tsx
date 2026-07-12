import { renderHook, waitFor, act } from '@testing-library/react'
import { vi } from 'vitest'
import React from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  usePendingReEnroll,
  useApproveReEnroll,
  useDenyReEnroll,
  PENDING_REENROLL_KEY,
} from '../use-reenroll'
import { ALL_SERVERS_KEY } from '../use-servers'

vi.mock('@/lib/api', () => ({
  listPendingReEnroll: vi.fn(),
  approveReEnroll: vi.fn(),
  denyReEnroll: vi.fn(),
}))

import { listPendingReEnroll, approveReEnroll, denyReEnroll } from '@/lib/api'
const mockList = listPendingReEnroll as ReturnType<typeof vi.fn>
const mockApprove = approveReEnroll as ReturnType<typeof vi.fn>
const mockDeny = denyReEnroll as ReturnType<typeof vi.fn>

function makeWrapper(qc: QueryClient) {
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  }
}

function makeQC() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchOnWindowFocus: false },
      mutations: { retry: false },
    },
  })
}

describe('usePendingReEnroll', () => {
  beforeEach(() => {
    mockList.mockReset()
  })

  it('returns the list of pending re-enroll requests', async () => {
    const payload = [{ id: 're-1', server_id: 'srv', status: 'pending' }]
    mockList.mockResolvedValue(payload)
    const qc = makeQC()
    const { result } = renderHook(
      () => usePendingReEnroll({ refetchInterval: false }),
      { wrapper: makeWrapper(qc) },
    )
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(payload)
    expect(mockList).toHaveBeenCalledTimes(1)
  })

  it('surfaces errors from the API', async () => {
    mockList.mockRejectedValue(new Error('Network error'))
    const qc = makeQC()
    const { result } = renderHook(
      () => usePendingReEnroll({ refetchInterval: false }),
      { wrapper: makeWrapper(qc) },
    )
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect((result.current.error as Error).message).toBe('Network error')
  })
})

describe('useApproveReEnroll', () => {
  beforeEach(() => {
    mockApprove.mockReset()
    mockList.mockResolvedValue([])
  })

  it('calls approveReEnroll with correct args on mutate', async () => {
    mockApprove.mockResolvedValue(undefined)
    const qc = makeQC()
    // Seed the cache so invalidation has something to work with
    qc.setQueryData(PENDING_REENROLL_KEY, [])
    qc.setQueryData(ALL_SERVERS_KEY, [])

    const { result } = renderHook(() => useApproveReEnroll(), {
      wrapper: makeWrapper(qc),
    })

    act(() => {
      result.current.mutate({ serverId: 'srv-1', requestId: 're-2', totpCode: '654321' })
    })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockApprove).toHaveBeenCalledWith('srv-1', 're-2', '654321')
  })

  it('invalidates PENDING_REENROLL_KEY and ALL_SERVERS_KEY on success', async () => {
    mockApprove.mockResolvedValue(undefined)
    const qc = makeQC()
    const invalidateSpy = vi.spyOn(qc, 'invalidateQueries')
    qc.setQueryData(PENDING_REENROLL_KEY, [])
    qc.setQueryData(ALL_SERVERS_KEY, [])

    const { result } = renderHook(() => useApproveReEnroll(), {
      wrapper: makeWrapper(qc),
    })

    act(() => {
      result.current.mutate({ serverId: 'srv-1', requestId: 're-2', totpCode: '654321' })
    })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PENDING_REENROLL_KEY })
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ALL_SERVERS_KEY })
  })

  it('surfaces error when approveReEnroll fails', async () => {
    mockApprove.mockRejectedValue(new Error('Bad TOTP'))
    const qc = makeQC()

    const { result } = renderHook(() => useApproveReEnroll(), {
      wrapper: makeWrapper(qc),
    })

    act(() => {
      result.current.mutate({ serverId: 'srv-1', requestId: 're-2', totpCode: '000000' })
    })

    await waitFor(() => expect(result.current.isError).toBe(true))
    expect((result.current.error as Error).message).toBe('Bad TOTP')
  })
})

describe('useDenyReEnroll', () => {
  beforeEach(() => {
    mockDeny.mockReset()
    mockList.mockResolvedValue([])
  })

  it('calls denyReEnroll with correct args on mutate', async () => {
    mockDeny.mockResolvedValue(undefined)
    const qc = makeQC()
    qc.setQueryData(PENDING_REENROLL_KEY, [])
    qc.setQueryData(ALL_SERVERS_KEY, [])

    const { result } = renderHook(() => useDenyReEnroll(), {
      wrapper: makeWrapper(qc),
    })

    act(() => {
      result.current.mutate({ serverId: 'srv-2', requestId: 're-3' })
    })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(mockDeny).toHaveBeenCalledWith('srv-2', 're-3')
  })

  it('invalidates PENDING_REENROLL_KEY and ALL_SERVERS_KEY on success', async () => {
    mockDeny.mockResolvedValue(undefined)
    const qc = makeQC()
    const invalidateSpy = vi.spyOn(qc, 'invalidateQueries')
    qc.setQueryData(PENDING_REENROLL_KEY, [])
    qc.setQueryData(ALL_SERVERS_KEY, [])

    const { result } = renderHook(() => useDenyReEnroll(), {
      wrapper: makeWrapper(qc),
    })

    act(() => {
      result.current.mutate({ serverId: 'srv-2', requestId: 're-3' })
    })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PENDING_REENROLL_KEY })
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ALL_SERVERS_KEY })
  })

  it('surfaces error when denyReEnroll fails', async () => {
    mockDeny.mockRejectedValue(new Error('Deny failed'))
    const qc = makeQC()

    const { result } = renderHook(() => useDenyReEnroll(), {
      wrapper: makeWrapper(qc),
    })

    act(() => {
      result.current.mutate({ serverId: 'srv-2', requestId: 're-3' })
    })

    await waitFor(() => expect(result.current.isError).toBe(true))
    expect((result.current.error as Error).message).toBe('Deny failed')
  })
})

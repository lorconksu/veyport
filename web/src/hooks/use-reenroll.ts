import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listPendingReEnroll, approveReEnroll, denyReEnroll } from '@/lib/api'
import { ALL_SERVERS_KEY } from './use-servers'

export const PENDING_REENROLL_KEY = ['reenroll', 'pending'] as const

export function usePendingReEnroll(options?: { refetchInterval?: number | false }) {
  return useQuery({
    queryKey: PENDING_REENROLL_KEY,
    queryFn: listPendingReEnroll,
    refetchInterval: options?.refetchInterval ?? 15_000,
  })
}

export function useApproveReEnroll() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ serverId, requestId, totpCode }: { serverId: string; requestId: string; totpCode: string }) =>
      approveReEnroll(serverId, requestId, totpCode),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: PENDING_REENROLL_KEY })
      queryClient.invalidateQueries({ queryKey: ALL_SERVERS_KEY })
    },
  })
}

export function useDenyReEnroll() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ serverId, requestId }: { serverId: string; requestId: string }) =>
      denyReEnroll(serverId, requestId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: PENDING_REENROLL_KEY })
      queryClient.invalidateQueries({ queryKey: ALL_SERVERS_KEY })
    },
  })
}

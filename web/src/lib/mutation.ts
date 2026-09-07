/** The subset of a TanStack mutation result the error helpers need. */
export interface MutationErrorState {
  isError: boolean
  error: unknown
}

/**
 * The message to show for a failed mutation: the Error's message when the
 * rejection was an Error, `fallback` for anything else, null when it has not
 * failed.
 */
export function mutationErrorMessage(mutation: MutationErrorState, fallback: string): string | null {
  if (!mutation.isError) return null
  return mutation.error instanceof Error ? mutation.error.message : fallback
}

/** The first failed mutation's message, or null when none has failed. */
export function firstMutationError(...muts: MutationErrorState[]): string | null {
  for (const m of muts) {
    const msg = mutationErrorMessage(m, 'Request failed')
    if (msg !== null) return msg
  }
  return null
}

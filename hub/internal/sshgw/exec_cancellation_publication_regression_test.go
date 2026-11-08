package sshgw

import (
	"context"
	"testing"
)

func TestExecutionFailureDispositionCancellationPublicationGap(t *testing.T) {
	// ExecutionSession.Cancel publishes its reason and closes Done before the
	// watchdog calls its context cancel function. Freeze that exact ordering:
	// Done is closed but ctx is still live. No sleeps or scheduler luck needed.
	ctx := context.Background()
	done := make(chan struct{})
	close(done)
	if ctx.Err() != nil {
		t.Fatal("fixture context must remain live during cancellation publication")
	}
	for _, reason := range []string{"SSH output consumer stalled", "execution access revoked", "SSH client disconnected"} {
		if got := executionFailureDisposition(ctx, done, reason, "outcome_unknown"); got != "cancelled" {
			t.Errorf("published cancellation %q classified as %q with live context", reason, got)
		}
	}
}

func TestExecutionFailureDispositionPreservesOtherFailureBoundaries(t *testing.T) {
	for _, state := range []string{"admission_failed", "launch_failed", "outcome_unknown"} {
		t.Run(state, func(t *testing.T) {
			open := make(chan struct{})
			closed := make(chan struct{})
			close(closed)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if got := executionFailureDisposition(ctx, open, "ordinary failure", state); got != state {
				t.Fatalf("uncancelled failure changed from %q to %q", state, got)
			}
			if got := executionFailureDisposition(ctx, closed, "execution transport lost", state); got != state {
				t.Fatalf("transport loss with closed Done changed from %q to %q", state, got)
			}
			cancel()
			if got := executionFailureDisposition(ctx, open, "local cancellation", state); got != "cancelled" {
				t.Fatalf("context-only cancellation classified as %q", got)
			}
			if got := executionFailureDisposition(ctx, closed, "execution transport lost", state); got != state {
				t.Fatalf("transport loss with both signals changed from %q to %q", state, got)
			}
		})
	}
}

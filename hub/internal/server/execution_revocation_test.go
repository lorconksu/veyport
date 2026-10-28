package server

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/grpcserver"
)

func executionForCredentialRevocationTest(t *testing.T, s *Server, actor string) <-chan grpcserver.TerminalEvent {
	t.Helper()
	if s.terminalSessions == nil {
		s.terminalSessions = grpcserver.NewTerminalSessions()
	}
	user, err := s.store.GetUserByID(actor)
	if err != nil {
		t.Fatal(err)
	}
	events, ok := s.terminalSessions.Register("node", "execution", actor, "", grpcserver.WithKind(grpcserver.TerminalKindExec), grpcserver.WithCredentialGeneration(user.TokenGeneration, false))
	if !ok {
		t.Fatal("register execution")
	}
	if _, _, ok := s.terminalSessions.AttachStream("node", "execution", actor); !ok {
		t.Fatal("attach execution")
	}
	return events
}

func requireCredentialRevokedExecution(t *testing.T, events <-chan grpcserver.TerminalEvent) {
	t.Helper()
	select {
	case event := <-events:
		if event.Type != grpcserver.TerminalEventExit || !event.Forced {
			t.Fatalf("credential mutation did not force execution cancellation: %+v", event)
		}
	default:
		t.Fatal("credential mutation returned before cancelling existing executions")
	}
}

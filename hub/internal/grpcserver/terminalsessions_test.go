package grpcserver

import "testing"

func TestTerminalSessions_RegisterGetAndRemove(t *testing.T) {
	ts := NewTerminalSessions()
	ch, ok := ts.Register("srv-1", "sess-1", "user-1", "alice")
	if !ok || ch == nil {
		t.Fatal("expected terminal session registration to succeed")
	}

	info, ok := ts.Get("srv-1", "sess-1")
	if !ok {
		t.Fatal("expected terminal session lookup to succeed")
	}
	if info.UserID != "user-1" {
		t.Fatalf("expected user-1, got %s", info.UserID)
	}
	if info.ExecutionUser != "alice" {
		t.Fatalf("expected execution user alice, got %s", info.ExecutionUser)
	}
	if info.Closed {
		t.Fatal("new session should not be closed")
	}

	if !ts.Remove("srv-1", "sess-1") {
		t.Fatal("expected remove to report success")
	}
	if _, ok := ts.Get("srv-1", "sess-1"); ok {
		t.Fatal("expected session to be gone after remove")
	}
}

func TestTerminalSessions_DeliverAndEnd(t *testing.T) {
	ts := NewTerminalSessions()
	ch, ok := ts.Register("srv-1", "sess-1", "user-1", "")
	if !ok {
		t.Fatal("expected registration to succeed")
	}

	if !ts.DeliverData("srv-1", "sess-1", []byte("pwd\r\n")) {
		t.Fatal("expected terminal data delivery to succeed")
	}
	event := <-ch
	if event.Type != TerminalEventData || string(event.Data) != "pwd\r\n" {
		t.Fatalf("unexpected data event: %+v", event)
	}

	if !ts.End("srv-1", "sess-1", 0, "") {
		t.Fatal("expected terminal end to succeed")
	}
	exit := <-ch
	if exit.Type != TerminalEventExit || exit.ExitCode != 0 {
		t.Fatalf("unexpected exit event: %+v", exit)
	}

	info, ok := ts.Get("srv-1", "sess-1")
	if !ok {
		t.Fatal("expected closed session to remain readable until removal")
	}
	if !info.Closed {
		t.Fatal("expected session to be marked closed")
	}
}

func TestTerminalSessions_EndEvictsBufferedDataToDeliverExit(t *testing.T) {
	ts := NewTerminalSessions()
	ch, ok := ts.Register("srv-1", "sess-1", "user-1", "")
	if !ok {
		t.Fatal("expected registration to succeed")
	}

	// Fill the per-session channel with data events without draining it,
	// simulating an SSE consumer that has not yet attached (or is slow).
	for i := 0; i < cap(ch); i++ {
		if !ts.DeliverData("srv-1", "sess-1", []byte("x")) {
			t.Fatalf("expected DeliverData #%d to succeed before End", i)
		}
	}

	// End must still enqueue the exit event by evicting the oldest data,
	// so the SSE client surfaces the real exit code, not a generic close.
	if !ts.End("srv-1", "sess-1", 7, "boom") {
		t.Fatal("expected terminal end to succeed")
	}

	var exit TerminalEvent
	foundExit := false
	for event := range ch {
		if event.Type == TerminalEventExit {
			exit = event
			foundExit = true
		}
	}
	if !foundExit {
		t.Fatal("expected exit event to be delivered even when channel was full")
	}
	if exit.ExitCode != 7 || exit.Error != "boom" {
		t.Fatalf("unexpected exit payload: %+v", exit)
	}
}

func TestTerminalSessions_AttachStreamOnlyOnce(t *testing.T) {
	ts := NewTerminalSessions()
	if _, ok := ts.Register("srv-1", "sess-1", "user-1", "alice"); !ok {
		t.Fatal("expected registration to succeed")
	}

	info, exists, attached := ts.AttachStream("srv-1", "sess-1", "user-1")
	if !exists || !attached {
		t.Fatalf("expected first attach to succeed: exists=%v attached=%v", exists, attached)
	}
	if info.ExecutionUser != "alice" {
		t.Fatalf("expected execution user alice, got %s", info.ExecutionUser)
	}

	_, exists, attached = ts.AttachStream("srv-1", "sess-1", "user-1")
	if !exists || attached {
		t.Fatalf("expected duplicate attach to be rejected as conflict: exists=%v attached=%v", exists, attached)
	}

	_, exists, attached = ts.AttachStream("srv-1", "sess-1", "other-user")
	if exists || attached {
		t.Fatalf("expected wrong user to be hidden as not found: exists=%v attached=%v", exists, attached)
	}
}

func TestTerminalSessions_RemoveUnattached(t *testing.T) {
	ts := NewTerminalSessions()
	ch, ok := ts.Register("srv-1", "sess-1", "user-1", "")
	if !ok {
		t.Fatal("expected registration to succeed")
	}

	if !ts.RemoveUnattached("srv-1", "sess-1") {
		t.Fatal("expected unattached session to be removed")
	}
	if _, ok := <-ch; ok {
		t.Fatal("expected removed session channel to close")
	}
	if _, ok := ts.Get("srv-1", "sess-1"); ok {
		t.Fatal("expected session to be gone after unattached removal")
	}

	if _, ok := ts.Register("srv-1", "sess-2", "user-1", ""); !ok {
		t.Fatal("expected second registration to succeed")
	}
	if _, exists, attached := ts.AttachStream("srv-1", "sess-2", "user-1"); !exists || !attached {
		t.Fatal("expected stream attach to succeed")
	}
	if ts.RemoveUnattached("srv-1", "sess-2") {
		t.Fatal("attached session must not be removed by unattached cleanup")
	}
}

func TestTerminalSessions_EndAll(t *testing.T) {
	ts := NewTerminalSessions()
	ch1, _ := ts.Register("srv-1", "sess-1", "user-1", "")
	ch2, _ := ts.Register("srv-1", "sess-2", "user-1", "")
	_, _ = ts.Register("srv-2", "sess-1", "user-2", "")

	ts.EndAll("srv-1", -1, "agent disconnected")

	ev1 := <-ch1
	ev2 := <-ch2
	if ev1.Type != TerminalEventExit || ev1.Error != "agent disconnected" {
		t.Fatalf("unexpected first exit event: %+v", ev1)
	}
	if ev2.Type != TerminalEventExit || ev2.Error != "agent disconnected" {
		t.Fatalf("unexpected second exit event: %+v", ev2)
	}

	info, ok := ts.Get("srv-2", "sess-1")
	if !ok || info.Closed {
		t.Fatal("expected sessions for other servers to stay open")
	}
}

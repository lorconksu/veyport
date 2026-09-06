package grpcserver

import (
	"testing"
	"time"
)

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

func TestTerminalSessions_RemoveIfHubInitiated(t *testing.T) {
	t.Run("returns_false_when_missing", func(t *testing.T) {
		ts := NewTerminalSessions()
		alreadyClosed, removed := ts.RemoveIfHubInitiated("srv-x", "sess-x")
		if removed {
			t.Fatal("expected removed=false for missing session")
		}
		if alreadyClosed {
			t.Fatal("expected alreadyClosed=false for missing session")
		}
	})

	t.Run("hub_initiated_close_returns_alreadyClosed_false", func(t *testing.T) {
		ts := NewTerminalSessions()
		ch, _ := ts.Register("srv-1", "sess-1", "user-1", "")
		alreadyClosed, removed := ts.RemoveIfHubInitiated("srv-1", "sess-1")
		if !removed {
			t.Fatal("expected removed=true")
		}
		if alreadyClosed {
			t.Fatal("hub-initiated close should report alreadyClosed=false")
		}
		if _, ok := <-ch; ok {
			t.Fatal("expected channel to be closed by RemoveIfHubInitiated")
		}
		if _, ok := ts.Get("srv-1", "sess-1"); ok {
			t.Fatal("expected session entry to be removed from map")
		}
	})

	t.Run("agent_initiated_then_remove_returns_alreadyClosed_true", func(t *testing.T) {
		ts := NewTerminalSessions()
		ts.Register("srv-1", "sess-2", "user-1", "")
		if !ts.End("srv-1", "sess-2", 0, "") {
			t.Fatal("expected End to succeed")
		}
		alreadyClosed, removed := ts.RemoveIfHubInitiated("srv-1", "sess-2")
		if !removed {
			t.Fatal("expected removed=true even when already closed")
		}
		if !alreadyClosed {
			t.Fatal("expected alreadyClosed=true after agent-initiated End")
		}
		if _, ok := ts.Get("srv-1", "sess-2"); ok {
			t.Fatal("expected session entry to be removed from map")
		}
	})
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

// --- Feature 009: registry metadata, per-user/per-session listing and close ---

func TestTerminalSessions_RegisterRecordsMetadata(t *testing.T) {
	start := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	ts := NewTerminalSessions()
	ts.nowFunc = (&fakeClock{now: start}).Now

	if _, ok := ts.Register("srv-1", "sess-1", "user-1", "alice"); !ok {
		t.Fatal("expected registration to succeed")
	}
	info, ok := ts.Get("srv-1", "sess-1")
	if !ok {
		t.Fatal("expected lookup to succeed")
	}
	if info.ServerID != "srv-1" || info.SessionID != "sess-1" {
		t.Fatalf("expected srv-1/sess-1, got %s/%s", info.ServerID, info.SessionID)
	}
	if info.Kind != TerminalKindWeb {
		t.Fatalf("expected default kind %q, got %q", TerminalKindWeb, info.Kind)
	}
	if info.SID != "" {
		t.Fatalf("expected empty sid by default, got %q", info.SID)
	}
	if !info.StartedAt.Equal(start) || !info.LastActivity.Equal(start) {
		t.Fatalf("expected startedAt/lastActivity %v, got %v/%v", start, info.StartedAt, info.LastActivity)
	}

	if _, ok := ts.Register("srv-2", "sess-2", "user-1", "bob",
		WithKind(TerminalKindSSH), WithSessionID("web-sid-1")); !ok {
		t.Fatal("expected registration with options to succeed")
	}
	info, _ = ts.Get("srv-2", "sess-2")
	if info.Kind != TerminalKindSSH {
		t.Fatalf("expected kind ssh, got %q", info.Kind)
	}
	if info.SID != "web-sid-1" {
		t.Fatalf("expected sid web-sid-1, got %q", info.SID)
	}
	if info.ExecutionUser != "bob" {
		t.Fatalf("expected execution user bob, got %q", info.ExecutionUser)
	}
}

func TestTerminalSessions_AttachStreamCarriesMetadata(t *testing.T) {
	ts := NewTerminalSessions()
	if _, ok := ts.Register("srv-1", "sess-1", "user-1", "alice", WithKind(TerminalKindSSH)); !ok {
		t.Fatal("expected registration to succeed")
	}
	info, exists, attached := ts.AttachStream("srv-1", "sess-1", "user-1")
	if !exists || !attached {
		t.Fatal("expected attach to succeed")
	}
	if info.Kind != TerminalKindSSH || info.ServerID != "srv-1" || info.SessionID != "sess-1" {
		t.Fatalf("expected metadata on the attached info, got %+v", info)
	}
}

func TestTerminalSessions_DeliverDataBumpsLastActivityAtMostOncePerSecond(t *testing.T) {
	start := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: start}
	ts := NewTerminalSessions()
	ts.nowFunc = clock.Now

	ch, _ := ts.Register("srv-1", "sess-1", "user-1", "")

	clock.Advance(500 * time.Millisecond)
	if !ts.DeliverData("srv-1", "sess-1", []byte("a")) {
		t.Fatal("expected delivery to succeed")
	}
	info, _ := ts.Get("srv-1", "sess-1")
	if !info.LastActivity.Equal(start) {
		t.Fatalf("expected lastActivity unchanged within 1s, got %v", info.LastActivity)
	}

	clock.Advance(600 * time.Millisecond) // now start+1.1s
	if !ts.DeliverData("srv-1", "sess-1", []byte("b")) {
		t.Fatal("expected delivery to succeed")
	}
	info, _ = ts.Get("srv-1", "sess-1")
	if !info.LastActivity.Equal(start.Add(1100 * time.Millisecond)) {
		t.Fatalf("expected lastActivity bumped to start+1.1s, got %v", info.LastActivity)
	}

	// Both payloads still made it through untouched.
	for _, want := range []string{"a", "b"} {
		event := <-ch
		if event.Type != TerminalEventData || string(event.Data) != want {
			t.Fatalf("unexpected event: %+v", event)
		}
	}
}

func TestTerminalSessions_ListByUser(t *testing.T) {
	start := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: start}
	ts := NewTerminalSessions()
	ts.nowFunc = clock.Now

	ts.Register("srv-2", "sess-2", "user-1", "alice", WithKind(TerminalKindSSH))
	clock.Advance(time.Minute)
	ts.Register("srv-1", "sess-1", "user-1", "alice", WithKind(TerminalKindWeb), WithSessionID("sid-1"))
	clock.Advance(time.Minute)
	ts.Register("srv-3", "sess-3", "user-2", "bob")
	ts.Register("srv-4", "sess-4", "user-1", "alice")
	if !ts.End("srv-4", "sess-4", 0, "") {
		t.Fatal("expected End to succeed")
	}

	list := ts.ListByUser("user-1")
	if len(list) != 2 {
		t.Fatalf("expected 2 live entries for user-1, got %d (%+v)", len(list), list)
	}
	if list[0].SessionID != "sess-2" || list[1].SessionID != "sess-1" {
		t.Fatalf("expected startedAt ordering sess-2, sess-1, got %s, %s", list[0].SessionID, list[1].SessionID)
	}
	if list[0].Kind != TerminalKindSSH || list[0].ServerID != "srv-2" {
		t.Fatalf("unexpected first entry: %+v", list[0])
	}
	if !list[0].StartedAt.Equal(start) || !list[1].StartedAt.Equal(start.Add(time.Minute)) {
		t.Fatalf("unexpected startedAt values: %v, %v", list[0].StartedAt, list[1].StartedAt)
	}
	if list[1].SID != "sid-1" || list[1].UserID != "user-1" {
		t.Fatalf("unexpected second entry: %+v", list[1])
	}
	if got := ts.ListByUser("nobody"); len(got) != 0 {
		t.Fatalf("expected no entries for an unknown user, got %d", len(got))
	}
}

func TestTerminalSessions_EndByUser(t *testing.T) {
	ts := NewTerminalSessions()
	ch1, _ := ts.Register("srv-1", "sess-1", "user-1", "")
	ch2, _ := ts.Register("srv-2", "sess-2", "user-1", "")
	other, _ := ts.Register("srv-3", "sess-3", "user-2", "")

	const msg = "veyport: session ended by an administrator"
	if got := ts.EndByUser("user-1", 1, msg); got != 2 {
		t.Fatalf("expected 2 shells closed, got %d", got)
	}
	for _, ch := range []chan TerminalEvent{ch1, ch2} {
		event := <-ch
		if event.Type != TerminalEventExit || event.ExitCode != 1 || event.Error != msg {
			t.Fatalf("unexpected exit event: %+v", event)
		}
		if _, open := <-ch; open {
			t.Fatal("expected the channel to be closed after EndByUser")
		}
	}

	if got := ts.EndByUser("user-1", 1, msg); got != 0 {
		t.Fatalf("expected EndByUser to be idempotent, got %d", got)
	}

	info, ok := ts.Get("srv-3", "sess-3")
	if !ok || info.Closed {
		t.Fatal("expected another user's shell to stay open")
	}
	select {
	case event := <-other:
		t.Fatalf("expected no event for another user, got %+v", event)
	default:
	}
}

func TestTerminalSessions_EndBySession(t *testing.T) {
	ts := NewTerminalSessions()
	ch1, _ := ts.Register("srv-1", "sess-1", "user-1", "", WithSessionID("sid-1"))
	ch2, _ := ts.Register("srv-2", "sess-2", "user-1", "", WithSessionID("sid-1"))
	untied, _ := ts.Register("srv-3", "sess-3", "user-1", "")

	const msg = "veyport: session ended"
	if got := ts.EndBySession("sid-1", 1, msg); got != 2 {
		t.Fatalf("expected 2 shells closed for sid-1, got %d", got)
	}
	for _, ch := range []chan TerminalEvent{ch1, ch2} {
		event := <-ch
		if event.Type != TerminalEventExit || event.Error != msg {
			t.Fatalf("unexpected exit event: %+v", event)
		}
	}
	if got := ts.EndBySession("sid-1", 1, msg); got != 0 {
		t.Fatalf("expected EndBySession to be idempotent, got %d", got)
	}
	if got := ts.EndBySession("", 1, msg); got != 0 {
		t.Fatalf("expected an empty sid to match nothing, got %d", got)
	}
	if info, ok := ts.Get("srv-3", "sess-3"); !ok || info.Closed {
		t.Fatal("expected a shell with no owning session to stay open")
	}
	select {
	case event := <-untied:
		t.Fatalf("expected no event on the untied shell, got %+v", event)
	default:
	}
}

func TestTerminalSessions_EndOne(t *testing.T) {
	ts := NewTerminalSessions()
	ch, _ := ts.Register("srv-1", "sess-1", "user-1", "")

	const msg = "veyport: shell ended by an administrator"
	if !ts.EndOne("srv-1", "sess-1", 1, msg) {
		t.Fatal("expected EndOne to report success")
	}
	event := <-ch
	if event.Type != TerminalEventExit || event.ExitCode != 1 || event.Error != msg {
		t.Fatalf("unexpected exit event: %+v", event)
	}
	if _, open := <-ch; open {
		t.Fatal("expected the channel to be closed by EndOne")
	}
	if ts.EndOne("srv-1", "sess-1", 1, msg) {
		t.Fatal("expected EndOne to be idempotent on an already-closed session")
	}
	if ts.EndOne("srv-1", "missing", 1, msg) {
		t.Fatal("expected EndOne to report false for an unknown session")
	}
	if info, ok := ts.Get("srv-1", "sess-1"); !ok || !info.Closed {
		t.Fatal("expected the entry to remain readable and marked closed")
	}
}

func TestTerminalSessions_EndByUserDeliversExitOnFullChannel(t *testing.T) {
	ts := NewTerminalSessions()
	ch, _ := ts.Register("srv-1", "sess-1", "user-1", "")
	for i := 0; i < cap(ch); i++ {
		if !ts.DeliverData("srv-1", "sess-1", []byte("x")) {
			t.Fatalf("expected DeliverData #%d to succeed", i)
		}
	}

	if got := ts.EndByUser("user-1", 1, "forced"); got != 1 {
		t.Fatalf("expected 1 shell closed, got %d", got)
	}
	found := false
	for event := range ch {
		if event.Type == TerminalEventExit && event.Error == "forced" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the exit event to be delivered even on a full channel")
	}
}

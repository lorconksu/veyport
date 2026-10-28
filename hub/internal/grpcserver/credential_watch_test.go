package grpcserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestCredentialWatcherExternalResetAndCleanup(t *testing.T) {
	for _, output := range []bool{false, true} {
		t.Run(map[bool]string{false: "silent", true: "output"}[output], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hub.db")
			st, err := store.New(path)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			cli, err := store.New(path)
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			if err := st.CreateUser(&model.User{ID: "actor", Username: "actor", Email: "actor@test", PasswordHash: "old", Role: model.RoleAdmin}); err != nil {
				t.Fatal(err)
			}
			ts := NewTerminalSessions()
			cm := connmgr.New()
			stream := &orderedTerminalStream{messages: make(chan *pb.HubMessage, 10)}
			cm.Register("node", stream)
			defer cm.Unregister("node")
			_, _, err = ts.RegisterInteractive(st, cm, "node", "shell", "actor", func() (string, error) { return "", nil }, WithCredentialGeneration(0, false))
			if err != nil {
				t.Fatal(err)
			}
			ts.mu.Lock()
			registered := ts.sessions[makeKey("node", "shell")]
			ts.mu.Unlock()
			if err := cli.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: "actor", ExpectedGeneration: 0}, "temporary", time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-registered.credentialWatchDone:
					if ts.DeliverData("node", "shell", []byte("late")) {
						t.Fatal("output accepted after revoke")
					}
					if m := waitTerminalMessage(t, stream); m.GetTerminalClose() == nil {
						t.Fatal("agent not closed")
					}
					ts.mu.Lock()
					count := ts.credentialWatchers
					ts.mu.Unlock()
					if count != 0 {
						t.Fatal("watcher leaked")
					}
					return
				case <-ctx.Done():
					t.Fatal("idle terminal not revoked")
				case <-ticker.C:
					if output {
						ts.DeliverData("node", "shell", []byte("output"))
					}
				}
			}
		})
	}
}

func TestCredentialRevocationAfterNaturalExitDiscardsRetainedOutput(t *testing.T) {
	st, cm, ts, _ := interactiveFixture(t)
	secret := "enrolled"
	if err := st.CreateUser(&model.User{ID: "actor", Username: "actor", Email: "actor@test", PasswordHash: "old", Role: model.RoleAdmin, TOTPEnabled: true, TOTPSecret: &secret}); err != nil {
		t.Fatal(err)
	}
	events, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", func() (string, error) { return "", nil }, WithKind(TerminalKindSSH), WithCredentialGeneration(0, true))
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Remove("node", "shell")
	ts.mu.Lock()
	registered := ts.sessions[makeKey("node", "shell")]
	watchDone := registered.credentialWatchDone
	ts.mu.Unlock()
	info, ok := ts.Get("node", "shell")
	if !ok {
		t.Fatal("registered terminal missing")
	}
	if !ts.DeliverData("node", "shell", []byte("private buffered output")) {
		t.Fatal("failed to buffer terminal output")
	}
	if !ts.End("node", "shell", 0, "") {
		t.Fatal("agent-reported exit was not accepted")
	}
	select {
	case <-watchDone:
		t.Fatal("agent-reported exit stopped credential revalidation before transport teardown")
	case <-time.After(100 * time.Millisecond):
	}
	if err := st.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: "actor", ExpectedGeneration: 0}, "temporary", time.Now()); err != nil {
		t.Fatal(err)
	}
	ts.EndStaleCredentials(st, "actor")
	if _, forwarded := info.ForcedExit(); !forwarded {
		t.Fatal("credential revocation did not seal the retained output gate")
	}
	if forwarded, err := info.ForwardData(func() error { return nil }); err != nil || forwarded {
		t.Fatalf("retained output forwarded after credential revocation: forwarded=%t err=%v", forwarded, err)
	}
	for event := range events {
		if event.Type == TerminalEventData {
			t.Fatal("buffered private output survived credential revocation")
		}
	}
	select {
	case <-watchDone:
	case <-time.After(2 * time.Second):
		t.Fatal("credential watcher did not finish revoked-session cleanup")
	}
}

func TestCredentialWatchersBoundedAndRemovalStopsWork(t *testing.T) {
	st, cm, ts, _ := interactiveFixture(t)
	if err := st.CreateUser(&model.User{ID: "actor", Username: "actor", Email: "actor@test", Role: model.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	var sessions []*terminalSession
	for i := 0; i < 256; i++ {
		node := fmt.Sprintf("node-%d", i/8)
		if i%8 == 0 {
			if err := st.CreateServer(&model.Server{ID: node, Name: node, Status: "online", Labels: "{}"}); err != nil {
				t.Fatal(err)
			}
			cm.Register(node, &orderedTerminalStream{messages: make(chan *pb.HubMessage, 10)})
			defer cm.Unregister(node)
		}
		id := fmt.Sprint(i)
		if _, _, err := ts.RegisterInteractive(st, cm, node, id, "actor", func() (string, error) { return "", nil }, WithCredentialGeneration(0, false)); err != nil {
			t.Fatal(err)
		}
		ts.mu.Lock()
		sessions = append(sessions, ts.sessions[makeKey(node, id)])
		ts.mu.Unlock()
	}
	if err := st.CreateServer(&model.Server{ID: "extra", Name: "extra", Status: "online", Labels: "{}"}); err != nil {
		t.Fatal(err)
	}
	cm.Register("extra", &orderedTerminalStream{messages: make(chan *pb.HubMessage, 10)})
	defer cm.Unregister("extra")
	if _, _, err := ts.RegisterInteractive(st, cm, "extra", "extra", "actor", func() (string, error) { return "", nil }, WithCredentialGeneration(0, false)); !errors.Is(err, ErrInteractiveRegistration) {
		t.Fatalf("unbounded watcher admission: %v", err)
	}
	for _, s := range sessions {
		ts.Remove(s.serverID, s.sessionID)
	}
	for _, s := range sessions {
		select {
		case <-s.credentialWatchDone:
		case <-time.After(time.Second):
			t.Fatal("removal leaked watcher")
		}
	}
	ts.mu.Lock()
	count := ts.credentialWatchers
	ts.mu.Unlock()
	if count != 0 {
		t.Fatalf("%d watchers retained after removal", count)
	}
}

func TestCredentialWatcherFailsClosedOnQueryBudgetDeadline(t *testing.T) {
	st, cm, ts, stream := interactiveFixture(t)
	if _, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", func() (string, error) { return "", nil }, WithCredentialGeneration(0, false)); err != nil {
		t.Fatal(err)
	}
	ts.mu.Lock()
	registered := ts.sessions[makeKey("node", "shell")]
	ts.mu.Unlock()
	// Waiting for a query slot shares the same deadline as the database read.
	for i := 0; i < cap(ts.credentialChecks); i++ {
		ts.credentialChecks <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(ts.credentialChecks); i++ {
			<-ts.credentialChecks
		}
	}()
	select {
	case <-registered.credentialWatchDone:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked storage left stale terminal live")
	}
	if m := waitTerminalMessage(t, stream); m.GetTerminalClose() == nil {
		t.Fatal("storage outage did not close remote shell")
	}
}

func TestCredentialWatcherFailsClosedUnderSQLiteExclusiveLock(t *testing.T) {
	for _, journal := range []string{"WAL", "DELETE"} {
		for _, ssh := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ssh=%t", journal, ssh), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "hub.db")
				st, err := store.New(path)
				if err != nil {
					t.Fatal(err)
				}
				defer st.Close()
				cli, err := store.New(path)
				if err != nil {
					t.Fatal(err)
				}
				defer cli.Close()
				secret := "enrolled"
				if err := st.CreateUser(&model.User{ID: "actor", Username: "actor", Email: "actor@test", PasswordHash: "old", Role: model.RoleViewer, TOTPEnabled: true, TOTPSecret: &secret}); err != nil {
					t.Fatal(err)
				}
				// Drop idle readers so the independent connection can take a real
				// exclusive WAL lock as well as a rollback-journal lock.
				st.DB().SetMaxIdleConns(0)
				cli.DB().SetMaxIdleConns(0)
				ts, cm := NewTerminalSessions(), connmgr.New()
				stream := &orderedTerminalStream{messages: make(chan *pb.HubMessage, 10)}
				cm.Register("node", stream)
				defer cm.Unregister("node")
				if _, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "actor", func() (string, error) { return "", nil }, WithCredentialGeneration(0, ssh)); err != nil {
					t.Fatal(err)
				}
				ts.mu.Lock()
				registered := ts.sessions[makeKey("node", "shell")]
				ts.mu.Unlock()
				defer ts.Remove("node", "shell")
				if err := cli.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: "actor", ExpectedGeneration: 0}, "temporary", time.Now()); err != nil {
					t.Fatal(err)
				}
				locker, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				defer locker.Close()
				conn, err := locker.Conn(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				for _, query := range []string{"PRAGMA journal_mode=" + journal, "PRAGMA locking_mode=EXCLUSIVE", "BEGIN EXCLUSIVE", "SELECT COUNT(*) FROM users"} {
					if _, err := conn.ExecContext(context.Background(), query); err != nil {
						t.Fatal(err)
					}
				}
				defer conn.ExecContext(context.Background(), "ROLLBACK")
				// The read pool has never been opened: this also exercises driver
				// initialization under the lock, which ignores context cancellation.
				started := time.Now()
				select {
				case <-registered.done:
				case <-time.After(CredentialRevalidationInterval + store.TerminalCredentialTimeout):
					t.Fatal("revoked terminal exceeded 1.25s local revocation bound under SQLite lock")
				}
				if ts.DeliverData("node", "shell", []byte("late output")) {
					t.Fatal("revoked terminal accepted output under SQLite lock")
				}
				select {
				case <-registered.credentialWatchDone:
				case <-time.After(time.Second):
					t.Fatal("query/watcher retained after lock failure")
				}
				if len(ts.credentialChecks) != 0 || waitTerminalMessage(t, stream).GetTerminalClose() == nil {
					t.Fatal("query slot leaked or captured agent was not closed")
				}
				t.Logf("local revocation and captured cleanup under %s lock: %s", journal, time.Since(started))
			})
		}
	}
}

func TestCredentialWatcherMFARemovalAcrossStoreConnections(t *testing.T) {
	for _, separate := range []bool{false, true} {
		for _, output := range []bool{false, true} {
			t.Run(fmt.Sprintf("separate=%t/output=%t", separate, output), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "hub.db")
				st, err := store.New(path)
				if err != nil {
					t.Fatal(err)
				}
				defer st.Close()
				writer := st
				if separate {
					writer, err = store.New(path)
					if err != nil {
						t.Fatal(err)
					}
					defer writer.Close()
				}
				secret := "enrolled"
				if err := st.CreateUser(&model.User{ID: "actor", Username: "actor", Email: "actor@test", PasswordHash: "old", Role: model.RoleAdmin, TOTPEnabled: true, TOTPSecret: &secret}); err != nil {
					t.Fatal(err)
				}
				ts, cm := NewTerminalSessions(), connmgr.New()
				stream := &orderedTerminalStream{messages: make(chan *pb.HubMessage, 10)}
				cm.Register("node", stream)
				defer cm.Unregister("node")
				var registered []*terminalSession
				for _, kind := range []string{TerminalKindWeb, TerminalKindSSH} {
					if _, _, err := ts.RegisterInteractive(st, cm, "node", kind, "actor", func() (string, error) { return "", nil }, WithKind(kind), WithCredentialGeneration(0, kind == TerminalKindSSH)); err != nil {
						t.Fatal(err)
					}
					ts.mu.Lock()
					registered = append(registered, ts.sessions[makeKey("node", kind)])
					ts.mu.Unlock()
					defer ts.Remove("node", kind)
				}
				if err := disableWatcherMFA(t, writer, "actor"); err != nil {
					t.Fatal(err)
				}
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				timeout := time.NewTimer(3 * time.Second)
				defer timeout.Stop()
				for _, s := range registered {
				waiting:
					for {
						select {
						case <-s.credentialWatchDone:
							break waiting
						case <-timeout.C:
							t.Fatal("MFA revocation left browser/SSH shell live")
						case <-ticker.C:
							if output {
								for _, active := range registered {
									ts.DeliverData("node", active.sessionID, []byte("output"))
								}
							}
						}
					}
					if !s.closed {
						t.Fatal("watcher exited without closing revoked shell")
					}
				}
				for range registered {
					if waitTerminalMessage(t, stream).GetTerminalClose() == nil {
						t.Fatal("captured agent shell not closed")
					}
				}
				ts.mu.Lock()
				count := ts.credentialWatchers
				ts.mu.Unlock()
				if count != 0 {
					t.Fatal("watchers leaked after MFA removal")
				}
			})
		}
	}
}

func ptrWatcher(s string) *string { return &s }

func disableWatcherMFA(t *testing.T, st *store.Store, user string) error {
	t.Helper()
	admin := &model.User{ID: "watcher-admin", Username: "watcher-admin", Email: "admin@test", PasswordHash: "h", Role: model.RoleAdmin, TOTPEnabled: true, TOTPSecret: ptrWatcher("enrolled")}
	if err := st.CreateUser(admin); err != nil {
		t.Fatal(err)
	}
	sessionID := admin.ID + "-session"
	if err := st.CreateSession(&model.Session{ID: sessionID, UserID: admin.ID, Kind: model.SessionKindWeb, CreatedAt: time.Now(), LastSeenAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return st.DisableUserTOTP(user, time.Now(), model.AuditEntry{UserID: &admin.ID, Target: &user, Action: model.AuditUserTOTPDisabled}, store.AccountManagementActor{UserID: admin.ID, SessionID: sessionID, Generation: admin.TokenGeneration, SecurityRevision: admin.SecurityRevision})
}

type credentialCloseStream struct {
	orderedTerminalStream
	entered chan struct{}
	release chan struct{}
}

func (s *credentialCloseStream) Send(m *pb.HubMessage) error {
	if m.GetTerminalClose() != nil {
		close(s.entered)
		<-s.release
		return nil
	}
	return s.orderedTerminalStream.Send(m)
}

func TestCredentialCleanupRetainsWatcherBudgetAndCapturedConnection(t *testing.T) {
	st, cm, ts, _ := interactiveFixture(t)
	stream := &credentialCloseStream{orderedTerminalStream: orderedTerminalStream{messages: make(chan *pb.HubMessage, 10)}, entered: make(chan struct{}), release: make(chan struct{})}
	cm.Register("node", stream)
	if _, _, err := ts.RegisterInteractive(st, cm, "node", "shell", "missing-user", func() (string, error) { return "", nil }, WithCredentialGeneration(0, false)); err != nil {
		t.Fatal(err)
	}
	ts.mu.Lock()
	registered := ts.sessions[makeKey("node", "shell")]
	ts.mu.Unlock()
	ts.EndStaleCredentials(st, "missing-user")
	select {
	case <-stream.entered:
	case <-time.After(time.Second):
		t.Fatal("synchronous cleanup did not reach captured connection")
	}
	// A stalled agent close must keep its watcher reservation until cleanup ends.
	ts.mu.Lock()
	count := ts.credentialWatchers
	ts.mu.Unlock()
	if count != 1 {
		t.Fatal("watcher budget released before captured close finished")
	}
	select {
	case <-registered.credentialWatchDone:
		t.Fatal("cleanup detached from bounded watcher")
	default:
	}
	replacement := &orderedTerminalStream{messages: make(chan *pb.HubMessage, 10)}
	replaced := make(chan *connmgr.AgentConn, 1)
	go func() { replaced <- cm.Register("node", replacement) }()
	select {
	case <-replaced:
		t.Fatal("replacement crossed the captured close send")
	case <-time.After(100 * time.Millisecond):
	}
	close(stream.release)
	select {
	case <-replaced:
	case <-time.After(time.Second):
		t.Fatal("replacement did not finish after captured close")
	}
	select {
	case <-registered.credentialWatchDone:
	case <-time.After(time.Second):
		t.Fatal("watcher not released after cleanup")
	}
	select {
	case <-replacement.messages:
		t.Fatal("credential cleanup closed a replacement agent")
	default:
	}
}

func TestCredentialCleanupRevalidatesExecutionEpochWithoutWatchers(t *testing.T) {
	st, _, ts, _ := interactiveFixture(t)
	secret := "enrolled"
	if err := st.CreateUser(&model.User{ID: "actor", Username: "actor", Email: "actor@test", PasswordHash: "h", Role: model.RoleAdmin, TOTPEnabled: true, TOTPSecret: &secret}); err != nil {
		t.Fatal(err)
	}
	if _, ok := ts.Register("node", "old-exec", "actor", "", WithKind(TerminalKindExec), WithCredentialGeneration(0, true)); !ok {
		t.Fatal("execution registration failed")
	}
	ts.EndStaleCredentials(st, "actor")
	if info, _ := ts.Get("node", "old-exec"); info.Closed {
		t.Fatal("live execution cancelled")
	}
	if err := disableWatcherMFA(t, st, "actor"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateUserTOTP("actor", &secret, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := ts.Register("node", "fresh-exec", "actor", "", WithKind(TerminalKindExec), WithCredentialGeneration(1, true)); !ok {
		t.Fatal("fresh execution registration failed")
	}
	ts.EndStaleCredentials(st, "actor")
	old, _ := ts.Get("node", "old-exec")
	fresh, _ := ts.Get("node", "fresh-exec")
	if !old.Closed || fresh.Closed {
		t.Fatal("execution cleanup ignored admission epochs")
	}
	ts.mu.Lock()
	count := ts.credentialWatchers
	ts.mu.Unlock()
	if count != 0 {
		t.Fatal("execution markers consumed interactive watcher budget")
	}
}

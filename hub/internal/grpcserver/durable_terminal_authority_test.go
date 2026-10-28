package grpcserver

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestDurableTerminalSessionAndPolicyRevocation(t *testing.T) {
	for _, mutation := range []string{"ended", "absolute", "idle", "missing", "owner", "malformed expiry", "malformed activity", "malformed creation", "recovery", "coverage", "continuity"} {
		for _, process := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/process=%t", mutation, process), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "hub.db")
				st, err := store.New(path)
				if err != nil {
					t.Fatal(err)
				}
				defer st.Close()
				writer, err := store.New(path)
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Close()
				secret := "enrolled"
				for _, id := range []string{"actor", "other"} {
					if err := st.CreateUser(&model.User{ID: id, Username: id, Email: id + "@test", Role: model.RoleAdmin, TOTPEnabled: true, TOTPSecret: &secret}); err != nil {
						t.Fatal(err)
					}
				}
				if err := st.CreateServer(&model.Server{ID: "node", Name: "node", Status: "online", Labels: "{}"}); err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC()
				if err := st.CreateSession(&model.Session{ID: "owning", UserID: "actor", Kind: model.SessionKindWeb, CreatedAt: now, LastSeenAt: now}); err != nil {
					t.Fatal(err)
				}
				marker := filepath.Join(t.TempDir(), "enrollment.json")
				if mutation == "continuity" {
					if err := os.Chmod(filepath.Dir(marker), 0700); err != nil {
						t.Fatal(err)
					}
					if err := authorization.New(st).ConfigureExecutionPolicy(authorization.TransitionConfig{InstallationID: "test-installation", EnrollmentPath: marker}); err != nil {
						t.Fatal(err)
					}
				}
				ts, cm := NewTerminalSessions(), connmgr.New()
				stream := &orderedTerminalStream{messages: make(chan *pb.HubMessage, 10)}
				cm.Register("node", stream)
				defer cm.Unregister("node")
				kinds := []string{TerminalKindWeb}
				if mutation == "recovery" || mutation == "coverage" || mutation == "continuity" {
					kinds = append(kinds, TerminalKindSSH)
				}
				var shells []*terminalSession
				for _, kind := range kinds {
					_, _, err := ts.RegisterInteractive(st, cm, "node", kind, "actor", func() (string, error) { return "", nil }, WithKind(kind), WithSessionID("owning"), WithCredentialGeneration(0, kind == TerminalKindSSH))
					if err != nil {
						t.Fatal(err)
					}
					ts.mu.Lock()
					shell := ts.sessions[makeKey("node", kind)]
					ts.mu.Unlock()
					shells = append(shells, shell)
					defer ts.Remove("node", kind)
					if !ts.credentialLive(st, shell) {
						state, stateErr := st.GetPolicyState()
						t.Fatalf("healthy fixture denied: state=%+v err=%v validation=%v", state, stateErr, st.ValidateExecutionPolicy(state))
					}
					ts.DeliverData("node", kind, []byte("PRIVATE_QUEUED_OUTPUT"))
				}
				if process {
					cmd := exec.Command(os.Args[0], "-test.run=^TestDurableTerminalMutationProcess$")
					cmd.Env = append(os.Environ(), "PR108_DURABLE_DB="+path, "PR108_DURABLE_MUTATION="+mutation, "PR108_DURABLE_MARKER="+marker)
					if output, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("process: %v %s", err, output)
					}
				} else {
					mutateDurableTerminal(t, writer, mutation, marker)
				}
				for _, shell := range shells {
					select {
					case <-shell.credentialWatchDone:
					case <-time.After(3 * time.Second):
						t.Fatal("shell survived durable revocation")
					}
					for event := range shell.ch {
						if event.Type == TerminalEventData {
							t.Fatal("private queue survived revocation")
						}
					}
					if ts.DeliverData("node", shell.sessionID, []byte("PRIVATE_AFTER_REVOCATION")) {
						t.Fatal("late output admitted")
					}
					if msg := waitTerminalMessage(t, stream); msg.GetTerminalClose() == nil {
						t.Fatal("captured agent was not closed")
					}
				}
			})
		}
	}
}
func TestDurableTerminalMutationProcess(t *testing.T) {
	path := os.Getenv("PR108_DURABLE_DB")
	if path == "" {
		return
	}
	st, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	mutateDurableTerminal(t, st, os.Getenv("PR108_DURABLE_MUTATION"), os.Getenv("PR108_DURABLE_MARKER"))
}
func mutateDurableTerminal(t *testing.T, st *store.Store, mutation, marker string) {
	t.Helper()
	var err error
	switch mutation {
	case "ended":
		_, err = st.EndSession("owning", model.SessionEndLogout, nil, time.Now())
	case "absolute":
		_, err = st.DB().Exec("UPDATE sessions SET expires_at='2000-01-01 00:00:00' WHERE id='owning'")
	case "idle":
		_, err = st.DB().Exec("UPDATE sessions SET last_seen_at='2000-01-01 00:00:00' WHERE id='owning'")
	case "missing":
		_, err = st.DB().Exec("DELETE FROM sessions WHERE id='owning'")
	case "owner":
		_, err = st.DB().Exec("UPDATE sessions SET user_id='other' WHERE id='owning'")
	case "malformed expiry":
		_, err = st.DB().Exec("UPDATE sessions SET expires_at='invalid' WHERE id='owning'")
	case "malformed activity":
		_, err = st.DB().Exec("UPDATE sessions SET last_seen_at='invalid' WHERE id='owning'")
	case "malformed creation":
		_, err = st.DB().Exec("UPDATE sessions SET created_at='invalid' WHERE id='owning'")
	case "recovery":
		err = st.RequirePolicyRecovery()
	case "coverage":
		// A foreign policy rewrite must fail closed even without a local observer;
		// continuity validation refuses it before it can authorize covered access.
		raw := []byte(`{"profile":"enhanced","actors":["actor"],"nodes":[],"runtime_seconds":3600}`)
		_, err = st.DB().Exec("UPDATE audit_policy_versions SET payload=?,digest=? WHERE version=1", raw, store.SecurityDigest(raw))
	case "continuity":
		err = os.WriteFile(marker, []byte(`{"invalid":"continuity"}`), 0600)
	default:
		t.Fatal(mutation)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestTerminalForcedClosureDiscardsDequeuedAndInflightData(t *testing.T) {
	ts := NewTerminalSessions()
	ch, _ := ts.Register("node", "shell", "actor", "")
	info, _ := ts.Get("node", "shell")
	ts.DeliverData("node", "shell", []byte("dequeued"))
	event := <-ch
	entered, abort, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	info.SetOutputAbort(func() { close(abort) })
	go func() {
		defer close(finished)
		info.ForwardData(func() error { close(entered); <-abort; return context.Canceled })
	}()
	<-entered
	if !ts.EndOne("node", "shell", 1, "revoked") {
		t.Fatal("not closed")
	}
	<-finished
	called := false
	if forwarded, _ := info.ForwardData(func() error { called = true; _ = event; return nil }); forwarded || called {
		t.Fatal("dequeued private data forwarded")
	}
	if e := <-ch; e.Type != TerminalEventExit || !e.Forced {
		t.Fatal("exit did not take precedence")
	}
	ts.Remove("node", "shell")
	ts.Register("node", "shell", "actor", "")
	if forwarded, _ := info.ForwardData(func() error { called = true; return nil }); forwarded {
		t.Fatal("old info adopted replacement registration")
	}
	ts.Remove("node", "shell")
}

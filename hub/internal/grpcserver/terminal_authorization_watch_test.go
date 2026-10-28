package grpcserver

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestIdleTerminalAuthorizationRevocationAcrossStoresAndProcesses(t *testing.T) {
	for _, mutation := range []string{"role", "permission", "terminal grant", "execution user", "server"} {
		for _, process := range []bool{false, true} {
			if process && mutation != "role" && mutation != "permission" {
				continue
			}
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
				u := &model.User{ID: "actor", Username: "actor", Email: "actor@test", PasswordHash: "h", Role: model.RoleAdmin, TOTPEnabled: true, TOTPSecret: ptrWatcher("enrolled")}
				executionUser := ""
				if mutation != "role" {
					u.Role, u.AuthProvider, u.TerminalAccess, u.LDAPUsername = model.RoleViewer, model.AuthProviderLDAP, true, "operator"
					executionUser = "operator"
				}
				if err := st.CreateUser(u); err != nil {
					t.Fatal(err)
				}
				if err := st.CreateServer(&model.Server{ID: "node", Name: "node", Status: "online", Labels: "{}"}); err != nil {
					t.Fatal(err)
				}
				if _, err := st.CreatePermission(u.ID, "node", "/"); err != nil {
					t.Fatal(err)
				}
				// A subtree path must not retain terminal authority when root is removed.
				if _, err := st.CreatePermission(u.ID, "node", "/var/log"); err != nil {
					t.Fatal(err)
				}
				for _, ssh := range []bool{false, true} {
					if !st.TerminalAuthorizationLive(context.Background(), u.ID, "node", executionUser, 0, ssh) {
						t.Fatal("fixture did not establish terminal authorization")
					}
				}
				ts, cm := NewTerminalSessions(), connmgr.New()
				stream := &orderedTerminalStream{messages: make(chan *pb.HubMessage, 10)}
				cm.Register("node", stream)
				defer cm.Unregister("node")
				var shells []*terminalSession
				for _, kind := range []string{TerminalKindWeb, TerminalKindSSH} {
					if _, _, err := ts.RegisterInteractive(st, cm, "node", kind, u.ID, func() (string, error) { return executionUser, nil }, WithKind(kind), WithCredentialGeneration(0, kind == TerminalKindSSH)); err != nil {
						t.Fatal(err)
					}
					ts.mu.Lock()
					shells = append(shells, ts.sessions[makeKey("node", kind)])
					ts.mu.Unlock()
					defer ts.Remove("node", kind)
				}
				if process {
					cmd := exec.Command(os.Args[0], "-test.run=^TestTerminalAuthorizationMutationProcess$")
					cmd.Env = append(os.Environ(), "PR108_TERMINAL_MUTATION_DB="+path, "PR108_TERMINAL_MUTATION="+mutation)
					if output, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("separate process mutation: %v %s", err, output)
					}
				} else {
					mutateTerminalAuthorization(t, writer, mutation)
				}
				live, err := writer.GetUserByID(u.ID)
				if err != nil || live.TokenGeneration != 0 || live.SSHCredentialGeneration != 0 {
					t.Fatalf("fixture accidentally relied on credential revocation: %v", err)
				}
				for _, shell := range shells {
					select {
					case <-shell.credentialWatchDone:
					case <-time.After(2 * time.Second):
						t.Fatal("idle shell survived authorization removal")
					}
					if ts.DeliverData("node", shell.sessionID, []byte("late private output")) {
						t.Fatal("revoked terminal accepted late agent output")
					}
					if err := ts.SendInteractive(context.Background(), "node", shell.sessionID, terminalOpen()); err == nil {
						t.Fatal("revoked terminal accepted late input")
					}
				}
				closed := map[string]bool{}
				for range shells {
					m := waitTerminalMessage(t, stream).GetTerminalClose()
					if m == nil {
						t.Fatal("captured agent connection was not closed")
					}
					closed[m.SessionId] = true
				}
				if !closed[TerminalKindWeb] || !closed[TerminalKindSSH] {
					t.Fatal("cleanup missed a captured browser/SSH shell")
				}
				ts.mu.Lock()
				watchers := ts.credentialWatchers
				ts.mu.Unlock()
				if watchers != 0 || len(ts.credentialChecks) != 0 {
					t.Fatal("authorization watcher leaked its bounded resources")
				}
			})
		}
	}
}

func TestTerminalAuthorizationMutationProcess(t *testing.T) {
	path := os.Getenv("PR108_TERMINAL_MUTATION_DB")
	if path == "" {
		return
	}
	st, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	mutateTerminalAuthorization(t, st, os.Getenv("PR108_TERMINAL_MUTATION"))
}

func mutateTerminalAuthorization(t *testing.T, st *store.Store, mutation string) {
	t.Helper()
	var err error
	switch mutation {
	case "role":
		err = st.UpdateUserRole("actor", model.RoleViewer)
	case "permission":
		var id string
		if err = st.DB().QueryRow("SELECT id FROM permissions WHERE user_id='actor' AND server_id='node' AND path='/'").Scan(&id); err == nil {
			err = st.DeletePermission(id)
		}
	case "terminal grant":
		_, err = st.DB().Exec("UPDATE users SET terminal_access=0 WHERE id='actor'")
	case "execution user":
		_, err = st.DB().Exec("UPDATE users SET ldap_username='different' WHERE id='actor'")
	case "server":
		_, err = st.DB().Exec("DELETE FROM servers WHERE id='node'")
	default:
		t.Fatalf("unknown mutation %q", mutation)
	}
	if err != nil {
		t.Fatal(err)
	}
}

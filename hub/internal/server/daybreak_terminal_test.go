package server

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/authorization"
	"github.com/wyiu/veyport/hub/internal/grpcserver"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

type daybreakTerminalAgent struct {
	mockGRPCStream
	close chan struct{}
	once  sync.Once
}

func (a *daybreakTerminalAgent) Send(m *pb.HubMessage) error {
	if m.GetTerminalClose() != nil {
		a.once.Do(func() { close(a.close) })
		return nil
	}
	return a.mockGRPCStream.Send(m)
}

type daybreakStreamRecorder struct {
	*httptest.ResponseRecorder
	ready chan struct{}
	once  sync.Once
}

func (w *daybreakStreamRecorder) Flush() {
	w.ResponseRecorder.Flush()
	w.once.Do(func() { close(w.ready) })
}

func TestDaybreakExternalResetClosesBrowserTerminal(t *testing.T) {
	for _, output := range []bool{false, true} {
		t.Run(map[bool]string{false: "silent", true: "agent-output-only"}[output], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hub.db")
			s, token, node := testServerWithAgentAt(t, path)
			a := &daybreakTerminalAgent{mockGRPCStream: mockGRPCStream{pending: s.pending, serverID: node, terms: s.terminalSessions}, close: make(chan struct{})}
			s.connMgr.Register(node, a)
			id := createTerminalSessionForTest(t, s, token, node)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req := httptest.NewRequest("GET", testServersPrefix+node+testTerminalSessionsSuffix+"/"+id+"/stream", nil).WithContext(ctx)
			req.Header.Set("Authorization", testBearerPrefix+token)
			rec := &daybreakStreamRecorder{ResponseRecorder: httptest.NewRecorder(), ready: make(chan struct{})}
			done := make(chan struct{})
			go func() { defer close(done); s.routes().ServeHTTP(rec, req) }()
			select {
			case <-rec.ready:
			case <-time.After(2 * time.Second):
				t.Fatal("stream not attached")
			}
			cli, err := store.New(path)
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			claims, err := auth.ValidateToken(s.jwtSecret, token)
			if err != nil {
				t.Fatal(err)
			}
			user, err := cli.GetUserByID(claims.Subject)
			if err != nil {
				t.Fatal(err)
			}
			if err := cli.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: user.ID, ExpectedGeneration: user.TokenGeneration}, "temporary", time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			timeout := time.NewTimer(3 * time.Second)
			defer timeout.Stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					if rec.Code != 200 || !strings.Contains(rec.Body.String(), "event: exit") {
						t.Fatalf("stream failed to signal exit: %d %s", rec.Code, rec.Body.String())
					}
					if s.terminalSessions.DeliverData(node, id, []byte("late")) {
						t.Fatal("closed browser stream accepted output")
					}
					select {
					case <-a.close:
					case <-time.After(time.Second):
						t.Fatal("agent shell not closed")
					}
					return
				case <-timeout.C:
					cancel()
					<-done
					t.Fatal("browser stream survived credential reset")
				case <-ticker.C:
					if output {
						s.terminalSessions.DeliverData(node, id, []byte("command output"))
					}
				}
			}
		})
	}
}

func TestDaybreakGovernedResetExplicitlyEndsShells(t *testing.T) {
	for _, operation := range []string{"password-reset", "mfa-reset"} {
		for _, replay := range []string{"apply", "reconcile"} {
			t.Run(operation+"/"+replay, func(t *testing.T) {
				s, target := recoveryServer(t, "recovery-officer")
				s.terminalSessions = grpcserver.NewTerminalSessions()
				ref := ""
				if operation == "password-reset" {
					ref = recoveryPasswordSecret(t, s, "SyntheticTemporary@1234")
				}
				change := prepareRecoveryPayload(t, s, model.SecurityChangePayload{Kind: "recovery", Recovery: &model.SecurityRecovery{UserID: target.ID, Operation: operation, SecretRef: ref}})
				register := func(prefix string, user *model.User) {
					t.Helper()
					for _, kind := range []string{grpcserver.TerminalKindSSH, grpcserver.TerminalKindWeb, grpcserver.TerminalKindExec} {
						generation := user.TokenGeneration
						if kind == grpcserver.TerminalKindSSH {
							generation = user.SSHCredentialGeneration
						}
						if _, ok := s.terminalSessions.Register("synthetic-node", prefix+kind, user.ID, "", grpcserver.WithKind(kind), grpcserver.WithCredentialGeneration(generation, kind == grpcserver.TerminalKindSSH)); !ok {
							t.Fatal("fixture registration failed")
						}
					}
				}
				register("before-", target)
				token, _, sid := sessionTokenPair(t, s, "recovery-officer")
				proof, err := s.store.IssueStepup("recovery-officer", sid, authorization.ActionApply, change.Digest, s.now())
				if err != nil {
					t.Fatal(err)
				}
				response := securityCall(s, "POST", "/api/security/changes/"+change.ID+"/apply", token, mustMarshal(t, map[string]string{"step_up_proof": proof}))
				if response.Code != 200 || len(s.terminalSessions.ListByUser(target.ID)) != 0 {
					t.Fatalf("apply failed to close revoked shells: %d %s", response.Code, response.Body.String())
				}
				// Complete recovery using its real durable grants.
				live, err := s.store.GetUserByID(target.ID)
				if err != nil {
					t.Fatal(err)
				}
				if operation == "password-reset" {
					_, err = s.store.CompleteApprovedPasswordRecoveryAudited(store.PasswordRecoverySnapshot{UserID: live.ID, PasswordHash: live.PasswordHash, SecurityRevision: live.SecurityRevision, TokenGeneration: live.TokenGeneration}, "permanent-hash", s.now(), 1, s.accountManagementAudit(httptest.NewRequest("POST", "/", nil), live.ID, live.ID, model.AuditUserPasswordChanged))
				} else {
					secret := "new-enrolled-factor"
					if err = s.store.UpdateUserTOTP(live.ID, &secret, false, live.TokenGeneration); err == nil {
						live, err = s.store.GetUserByID(target.ID)
						if err == nil {
							err = s.store.CompleteTOTPSetup(live, secret, "", s.now(), 1, model.AuditEntry{}, model.AuditEntry{UserID: &live.ID, Action: model.AuditUserTOTPEnabled})
						}
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				live, err = s.store.GetUserByID(target.ID)
				if err != nil || !live.TOTPEnabled || live.MustChangePassword {
					t.Fatal("recovery incomplete")
				}
				if _, err := AuthorizeTerminalExecution(s.store, live.ID, "synthetic-node"); err != nil {
					t.Fatal(err)
				}
				if err := s.securityService().GuardInteractive(live.ID, "synthetic-node"); err != nil {
					t.Fatal(err)
				}
				register("fresh-", live)
				// Simulate cleanup missed during a crash, alongside newer authority.
				register("missed-", target)
				response = securityCall(s, "POST", "/api/security/changes/"+change.ID+"/"+replay, token, []byte(`{}`))
				if response.Code != 200 {
					t.Fatalf("replay %d %s", response.Code, response.Body.String())
				}
				for _, kind := range []string{grpcserver.TerminalKindSSH, grpcserver.TerminalKindWeb, grpcserver.TerminalKindExec} {
					fresh, _ := s.terminalSessions.Get("synthetic-node", "fresh-"+kind)
					stale, _ := s.terminalSessions.Get("synthetic-node", "missed-"+kind)
					if fresh.Closed || !stale.Closed {
						t.Fatalf("replay failed: kind=%s fresh_closed=%t stale_closed=%t fresh_generation=%d/%d stale_generation=%d/%d", kind, fresh.Closed, stale.Closed, live.TokenGeneration, live.SSHCredentialGeneration, target.TokenGeneration, target.SSHCredentialGeneration)
					}
				}
			})
		}
	}
}

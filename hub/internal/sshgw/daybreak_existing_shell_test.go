package sshgw

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestDaybreakExternalBreakGlassClosesEstablishedSSH(t *testing.T) {
	for _, output := range []bool{false, true} {
		t.Run(map[bool]string{false: "silent", true: "agent-output-only"}[output], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hub.db")
			f := newFixtureAt(t, nil, path)
			f.connectAgent()
			cli, err := store.New(path)
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			ch := newFakeChannel()
			done, _ := f.startBridge(ch, nil)
			sessionID := f.openSessionID()
			waitForShell(t, f, sessionID)
			defer f.disconnect(ch)
			user, err := cli.GetUserByID(testUserID)
			if err != nil {
				t.Fatal(err)
			}
			if err := cli.ResetLocalTOTPBreakGlass(store.PasswordResetTarget{UserID: testUserID, ExpectedGeneration: user.TokenGeneration}, "new-hash", time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			timeout := time.NewTimer(3 * time.Second)
			defer timeout.Stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					if !ch.isClosed() {
						t.Fatal("SSH client left open")
					}
					if f.terminals.DeliverData(testServerID, sessionID, []byte("after-close")) {
						t.Fatal("closed shell accepted output")
					}
					f.agent.waitForMessage(t, "revocation close", func(m *pb.HubMessage) bool {
						return m.GetTerminalClose() != nil && m.GetTerminalClose().SessionId == sessionID
					})
					return
				case <-timeout.C:
					t.Fatal("credential reset left SSH shell live without client input")
				case <-ticker.C:
					if output {
						f.terminals.DeliverData(testServerID, sessionID, []byte("command output\n"))
					}
				}
			}
		})
	}
}

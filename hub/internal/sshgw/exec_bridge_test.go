package sshgw

import (
	"golang.org/x/crypto/ssh"
	"strings"
	"testing"
)

func TestExecSyntaxAndPTYRefusal(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()
	for _, test := range []struct {
		name    string
		payload []byte
		pty     bool
	}{
		{"malformed", []byte{1, 2, 3}, false},
		{"empty", ssh.Marshal(struct{ Command string }{""}), false},
		{"nul", ssh.Marshal(struct{ Command string }{"id\x00whoami"}), false},
		{"oversized", ssh.Marshal(struct{ Command string }{strings.Repeat("x", 32769)}), false},
		{"pty", ssh.Marshal(struct{ Command string }{"id"}), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ch := openRawSession(t, f.mustDial(testUsername+"+"+testServerName))
			if test.pty && !sendChannelRequest(t, ch, reqPTY, ssh.Marshal(ptyRequest{Term: "xterm"})) {
				t.Fatal("PTY was refused")
			}
			if sendChannelRequest(t, ch, reqExec, test.payload) {
				t.Fatal("invalid execution accepted")
			}
		})
	}
}

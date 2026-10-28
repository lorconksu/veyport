package sshgw

import (
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	"golang.org/x/crypto/ssh"
)

// Buffer transport writes so the SSH version exchange works over net.Pipe.
// All cryptography, authentication, retained connections and channel dispatch
// still run through the production gateway. No listener privilege is needed.
type sshBufferedPipe struct {
	net.Conn
	writes chan []byte
	done   chan struct{}
	stop   chan struct{}
	once   sync.Once
}

func bufferedSSHPipe(conn net.Conn) *sshBufferedPipe {
	p := &sshBufferedPipe{Conn: conn, writes: make(chan []byte, 64), done: make(chan struct{}), stop: make(chan struct{})}
	go func() {
		defer close(p.done)
		for {
			select {
			case b := <-p.writes:
				if _, err := conn.Write(b); err != nil {
					return
				}
			case <-p.stop:
				return
			}
		}
	}()
	return p
}
func (p *sshBufferedPipe) Write(b []byte) (int, error) {
	select {
	case <-p.done:
		return 0, io.ErrClosedPipe
	case p.writes <- append([]byte(nil), b...):
		return len(b), nil
	}
}
func dialPipeGateway(t *testing.T, f *fixture, method ssh.AuthMethod) *ssh.Client {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	a, b := bufferedSSHPipe(serverConn), bufferedSSHPipe(clientConn)
	finished := make(chan struct{})
	go func() { defer close(finished); f.srv.handleConn(a) }()
	conn, chans, reqs, err := ssh.NewClientConn(b, "pipe-gateway", &ssh.ClientConfig{User: testUsername + "+" + testServerName, Auth: []ssh.AuthMethod{method}, HostKeyCallback: ssh.FixedHostKey(f.hostKey.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		a.Close()
		b.Close()
		t.Fatal(err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() {
		client.Close()
		a.Close()
		b.Close()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("gateway connection did not terminate")
		}
	})
	return client
}
func TestGatewayCertificateCannotReviveAfterAccountRecreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	f := newFixtureAt(t, nil, path)
	f.connectAgent()
	original := certAuth(t, f.ca, testUsername, time.Hour)
	key := newClientKey(t)
	legacy, err := f.ca.SignUserCert(key.PublicKey(), testUsername, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewCertSigner(legacy, key)
	if err != nil {
		t.Fatal(err)
	}
	legacyAuth := ssh.PublicKeys(signer)
	retained := dialPipeGateway(t, f, original)
	retainedLegacy := dialPipeGateway(t, f, legacyAuth)
	writer, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.CreateUser(&model.User{ID: "other-admin", Username: "other-admin", Email: "other@test", Role: model.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.DisableUser(testUserID, "other-admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	stderr, status := refusedShellBounded(t, retained)
	if status == 0 || !strings.Contains(stderr, "credential revoked") {
		t.Fatalf("disable did not revoke: %d %s", status, stderr)
	}
	if err := writer.DeleteUser(testUserID); err != nil {
		t.Fatal(err)
	}
	secret := "synthetic-enrolled-mfa"
	replacement := &model.User{ID: "replacement-account", Username: testUsername, Email: "replacement@test", Role: model.RoleAdmin, TOTPEnabled: true, TOTPSecret: &secret}
	if err := writer.CreateUser(replacement); err != nil {
		t.Fatal(err)
	}
	for _, client := range []*ssh.Client{retained, retainedLegacy, dialPipeGateway(t, f, original), dialPipeGateway(t, f, legacyAuth)} {
		stderr, status := refusedShellBounded(t, client)
		if status == 0 || !strings.Contains(stderr, "credential revoked") {
			t.Fatalf("certificate revived: %d %s", status, stderr)
		}
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		output, err := session.CombinedOutput("printf PRIVATE_REPLAY")
		session.Close()
		if err == nil || !strings.Contains(string(output), "credential revoked") {
			t.Fatalf("exec replay accepted: %v %s", err, output)
		}
	}
	if countOpenRequests(f.agent.messages()) != 0 {
		t.Fatal("replayed certificate reached agent")
	}
	freshKey := newClientKey(t)
	freshCert, err := f.ca.SignUserCertForAccount(freshKey.PublicKey(), testUsername, replacement.ID, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	freshSigner, err := ssh.NewCertSigner(freshCert, freshKey)
	if err != nil {
		t.Fatal(err)
	}
	fresh := dialPipeGateway(t, f, ssh.PublicKeys(freshSigner))
	shell, _, _ := startPTYShell(t, fresh)
	defer shell.Close()
	f.assertOpenRequestGeometry(t, 80, 24)
}

func TestSSHRelayForcedClosureDiscardsQueuedOutput(t *testing.T) {
	f := newFixture(t, nil)
	events, ok := f.terminals.Register(testServerID, "queued", testUserID, "")
	if !ok {
		t.Fatal("registration")
	}
	defer f.terminals.Remove(testServerID, "queued")
	f.terminals.DeliverData(testServerID, "queued", []byte("PRIVATE_BUFFERED_OUTPUT"))
	f.terminals.EndOne(testServerID, "queued", 1, "revoked")
	ch := newFakeChannel()
	defer ch.Close()
	exit := f.srv.relay(ch, events, "queued", bridgeParams{serverID: testServerID})
	if !exit.forced || ch.out.String() != "" {
		t.Fatalf("queued private output forwarded: %q", ch.out.String())
	}
}

func (p *sshBufferedPipe) Close() error { p.once.Do(func() { close(p.stop) }); return p.Conn.Close() }

func TestSSHRelayForcedClosureAbortsInflightPrivateWrite(t *testing.T) {
	f := newFixture(t, nil)
	events, ok := f.terminals.Register(testServerID, "inflight", testUserID, "")
	if !ok {
		t.Fatal("registration")
	}
	defer f.terminals.Remove(testServerID, "inflight")
	ch := &blockingSSHOutput{fakeChannel: newFakeChannel(), entered: make(chan struct{}), abort: make(chan struct{})}
	defer ch.Close()
	f.terminals.DeliverData(testServerID, "inflight", []byte("PRIVATE_INFLIGHT_OUTPUT"))
	done := make(chan exitInfo, 1)
	go func() { done <- f.srv.relay(ch, events, "inflight", bridgeParams{serverID: testServerID}) }()
	select {
	case <-ch.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not dequeue output")
	}
	closed := make(chan struct{})
	go func() { f.terminals.EndOne(testServerID, "inflight", 1, "revoked"); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("revocation did not abort blocked SSH write")
	}
	select {
	case exit := <-done:
		if !exit.forced || ch.out.String() != "" {
			t.Fatal("inflight output bypassed forced exit")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not exit")
	}
}

type blockingSSHOutput struct {
	*fakeChannel
	entered, abort chan struct{}
	once           sync.Once
}

func (ch *blockingSSHOutput) Write(b []byte) (int, error) {
	close(ch.entered)
	<-ch.abort
	return 0, io.ErrClosedPipe
}
func (ch *blockingSSHOutput) Close() error {
	ch.once.Do(func() { close(ch.abort) })
	return ch.fakeChannel.Close()
}

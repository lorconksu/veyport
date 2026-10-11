package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/proto/protectedinput"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

type memorySpoolStore struct {
	files               []*memorySpool
	failWrite, failSeal bool
}

func (s *memorySpoolStore) Ready() error { return nil }
func (s *memorySpoolStore) Create() (protectedinput.File, error) {
	f := &memorySpool{store: s}
	s.files = append(s.files, f)
	return f, nil
}

type memorySpool struct {
	store *memorySpoolStore
	bytes.Buffer
	sealed, closed bool
	openDelay      time.Duration
}

func (f *memorySpool) Write(p []byte) (int, error) {
	if f.store.failWrite {
		return 0, io.ErrShortWrite
	}
	return f.Buffer.Write(p)
}
func (f *memorySpool) Seal() error {
	if f.store.failSeal {
		return io.ErrShortWrite
	}
	f.sealed = true
	return nil
}
func (f *memorySpool) Open() (io.ReadCloser, error) {
	if f.openDelay != 0 {
		time.Sleep(f.openDelay)
	}
	if !f.sealed || f.closed {
		return nil, io.ErrClosedPipe
	}
	return io.NopCloser(bytes.NewReader(f.Bytes())), nil
}
func (f *memorySpool) Close() error { f.closed = true; return nil }

func protectedManager(t *testing.T) (*Manager, *memorySpoolStore) {
	t.Helper()
	m := testManager(t)
	spool := &memorySpoolStore{}
	m.spool = spool
	return m, spool
}
func protectedPrepare(t *testing.T, m *Manager, command string, script []byte) *pb.ExecutionPrepared {
	t.Helper()
	var hash []byte
	if ScriptInterpreter(command) != "" {
		digest := sha256.Sum256(script)
		hash = digest[:]
	}
	p := m.Prepare(&pb.ExecutionPrepare{ExecutionId: "protected", NodeId: "node", Command: command, Enhanced: true, ScriptSha256: hash, ScriptLength: uint64(len(script))})
	if p.Error != "" {
		t.Fatal(p.Error)
	}
	if err := m.Attach(p.Binding); err != nil {
		t.Fatal(err)
	}
	return p
}
func protectedStart(m *Manager, p *pb.ExecutionPrepared, receipt string) (*Run, error) {
	return m.Start(context.Background(), &pb.ExecutionStart{Binding: p.Binding, CommandSha256: p.CommandSha256, IdentitySha256: p.Identity.IdentitySha256, Limits: p.Limits, PolicyVersion: "2", AdmissionReceipt: []byte(receipt), AdmissionExpiresUnixMilli: p.Binding.ExpiresUnixMilli})
}

func TestProtectedReceiptExpiryPreventsEffectsAtEveryLaunchBoundary(t *testing.T) {
	for _, phase := range []string{"missing", "negative", "expired", "past-preparation", "delayed-delivery", "durable-claim", "spool-open"} {
		t.Run(phase, func(t *testing.T) {
			m, spool := protectedManager(t)
			marker := filepath.Join(t.TempDir(), "must-not-start")
			script := []byte("touch '" + marker + "'\n")
			p := protectedPrepare(t, m, "sh -s", script)
			uploadScript(t, m, p, script)
			expiry := p.Binding.ExpiresUnixMilli
			switch phase {
			case "missing":
				expiry = 0
			case "negative":
				expiry = -1
			case "expired":
				expiry = time.Now().Add(-time.Millisecond).UnixMilli()
			case "past-preparation":
				expiry++
			case "delayed-delivery":
				expiry = time.Now().Add(20 * time.Millisecond).UnixMilli()
				time.Sleep(30 * time.Millisecond)
			case "durable-claim":
				expiry = time.Now().Add(200 * time.Millisecond).UnixMilli()
				m.journal.syncFile = func(f *os.File) error { time.Sleep(250 * time.Millisecond); return f.Sync() }
			case "spool-open":
				expiry = time.Now().Add(200 * time.Millisecond).UnixMilli()
				spool.files[0].openDelay = 250 * time.Millisecond
			}
			_, err := m.Start(context.Background(), &pb.ExecutionStart{Binding: p.Binding, CommandSha256: p.CommandSha256, IdentitySha256: p.Identity.IdentitySha256, Limits: p.Limits, PolicyVersion: "2", AdmissionReceipt: []byte("hub-verified-receipt-fixture"), AdmissionExpiresUnixMilli: expiry})
			if err == nil {
				t.Fatal("expired or missing admission authority launched")
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("expired admission had a process effect")
			}
			if phase == "durable-claim" || phase == "spool-open" {
				status := m.Status(p.Binding.ExecutionId)
				if status.State != "launch_failed" || !spool.files[0].closed {
					t.Fatal("expired consumed claim lost explicit failure or raw cleanup")
				}
				if _, err := protectedStart(m, p, "new-receipt"); !errors.Is(err, ErrAlreadyClaimed) {
					t.Fatal("expired consumed claim was retryable")
				}
			}
		})
	}
}
func uploadScript(t *testing.T, m *Manager, p *pb.ExecutionPrepared, script []byte) {
	t.Helper()
	for offset := 0; offset < len(script); {
		end := offset + MaxFrameBytes
		if end > len(script) {
			end = len(script)
		}
		if err := m.ScriptChunk(p.Binding, &pb.ExecutionScriptChunk{Offset: uint64(offset), Data: script[offset:end]}); err != nil {
			t.Fatal(err)
		}
		offset = end
	}
	hash := sha256.Sum256(script)
	if err := m.ScriptEOF(p.Binding, &pb.ExecutionScriptEOF{Length: uint64(len(script)), Sha256: hash[:]}); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedScriptStartsOnlyAfterCompleteValidatedInput(t *testing.T) {
	t.Setenv("SHELL", "/bin/false")
	m, spool := protectedManager(t)
	marker := filepath.Join(t.TempDir(), "once")
	script := []byte("printf x >> '" + marker + "'\nprintf '\\000\\377tail'\nprintf err >&2\nexit 42\n")
	p := protectedPrepare(t, m, "sh -s", script)
	if p.Identity.Shell != "/bin/sh" {
		t.Fatal("actual prepared interpreter was not fixed")
	}
	if _, err := protectedStart(m, p, "authenticated-hub-fixture"); err == nil {
		t.Fatal("executed before script EOF")
	}
	if err := m.ScriptChunk(p.Binding, &pb.ExecutionScriptChunk{Offset: 0, Data: script[:len(script)/2]}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("executed prefix")
	}
	if _, err := protectedStart(m, p, "authenticated-hub-fixture"); err == nil {
		t.Fatal("started partial script")
	}
	if err := m.ScriptChunk(p.Binding, &pb.ExecutionScriptChunk{Offset: uint64(len(script) / 2), Data: script[len(script)/2:]}); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(script)
	if err := m.ScriptEOF(p.Binding, &pb.ExecutionScriptEOF{Length: uint64(len(script)), Sha256: hash[:]}); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedStart(m, p, ""); err == nil {
		t.Fatal("missing hub admission accepted")
	}
	r, err := protectedStart(m, p, "authenticated-hub-fixture")
	if err != nil {
		t.Fatal(err)
	}
	out, stderr, result := collect(t, r)
	if !bytes.Equal(out, []byte{0, 255, 't', 'a', 'i', 'l'}) || string(stderr) != "err" || result.ExitCode != 42 {
		t.Fatalf("bad protected result:%q/%q/%+v", out, stderr, result)
	}
	if _, err := protectedStart(m, p, "authenticated-hub-fixture"); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatal("duplicate start did not preserve single launch")
	}
	data, _ := os.ReadFile(marker)
	if string(data) != "x" {
		t.Fatal("marker was not executed exactly once")
	}
	<-r.Done()
	if !spool.files[0].closed {
		t.Fatal("raw agent spool retained")
	}
}
func TestProtectedScriptInvalidFramesAndStorageNeverExecutePrefix(t *testing.T) {
	for _, test := range []string{"offset", "oversize-frame", "wrong-hash", "premature-eof", "excess-bytes", "duplicate-eof", "write-failure", "seal-failure", "cancelled", "expired"} {
		t.Run(test, func(t *testing.T) {
			m, spool := protectedManager(t)
			marker := filepath.Join(t.TempDir(), "forbidden")
			script := []byte("touch '" + marker + "'\n")
			p := protectedPrepare(t, m, "/bin/bash -s", script)
			var err error
			switch test {
			case "offset":
				err = m.ScriptChunk(p.Binding, &pb.ExecutionScriptChunk{Offset: 1, Data: script})
			case "oversize-frame":
				err = m.ScriptChunk(p.Binding, &pb.ExecutionScriptChunk{Data: make([]byte, MaxFrameBytes+1)})
			case "wrong-hash":
				_ = m.ScriptChunk(p.Binding, &pb.ExecutionScriptChunk{Data: script})
				err = m.ScriptEOF(p.Binding, &pb.ExecutionScriptEOF{Length: uint64(len(script)), Sha256: make([]byte, 32)})
			case "premature-eof":
				hash := sha256.Sum256(script)
				err = m.ScriptEOF(p.Binding, &pb.ExecutionScriptEOF{Length: uint64(len(script)), Sha256: hash[:]})
			case "excess-bytes":
				err = m.ScriptChunk(p.Binding, &pb.ExecutionScriptChunk{Data: append(script, 'x')})
			case "duplicate-eof":
				uploadScript(t, m, p, script)
				hash := sha256.Sum256(script)
				err = m.ScriptEOF(p.Binding, &pb.ExecutionScriptEOF{Length: uint64(len(script)), Sha256: hash[:]})
			case "write-failure":
				spool.failWrite = true
				err = m.ScriptChunk(p.Binding, &pb.ExecutionScriptChunk{Data: script})
			case "seal-failure":
				spool.failSeal = true
				_ = m.ScriptChunk(p.Binding, &pb.ExecutionScriptChunk{Data: script})
				hash := sha256.Sum256(script)
				err = m.ScriptEOF(p.Binding, &pb.ExecutionScriptEOF{Length: uint64(len(script)), Sha256: hash[:]})
			case "cancelled":
				uploadScript(t, m, p, script)
				_ = m.Cancel(&pb.ExecutionCancel{Binding: p.Binding})
				_, err = protectedStart(m, p, "fixture")
			case "expired":
				uploadScript(t, m, p, script)
				m.mu.Lock()
				m.prepared[p.ExecutionId].response.Binding.ExpiresUnixMilli = time.Now().Add(-time.Second).UnixMilli()
				m.mu.Unlock()
				_, err = protectedStart(m, p, "fixture")
			}
			if err == nil {
				t.Fatal("invalid protected input accepted")
			}
			if _, startErr := protectedStart(m, p, "fixture"); startErr == nil {
				t.Fatal("invalid frame still allowed a Start")
			}
			_ = m.Cancel(&pb.ExecutionCancel{Binding: p.Binding})
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("protected failure created marker")
			}
		})
	}
}
func TestProtectedScriptExactMaximumAndEmptyStdin(t *testing.T) {
	m, _ := protectedManager(t)
	script := bytes.Repeat([]byte{' '}, protectedinput.MaxScriptBytes)
	copy(script, []byte("exit 42\n#"))
	p := protectedPrepare(t, m, "bash -s", script)
	uploadScript(t, m, p, script)
	r, err := protectedStart(m, p, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	_, _, result := collect(t, r)
	if result.ExitCode != 42 {
		t.Fatal("max script failed")
	}
	m2, _ := protectedManager(t)
	p2 := protectedPrepare(t, m2, "cat; exit 42", nil)
	r2, err := protectedStart(m2, p2, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if r2.Input(&pb.ExecutionData{Data: []byte("raw")}) == nil {
		t.Fatal("protected ordinary command accepts arbitrary stdin")
	}
	_, _, result = collect(t, r2)
	if result.ExitCode != 42 {
		t.Fatal("protected empty stdin missing EOF")
	}
}
func TestProtectedCapabilityRequiresActualEncryptedStorage(t *testing.T) {
	m := testManager(t)
	if m.Capabilities().ProtectedScript {
		t.Fatal("unconfigured agent advertises protected execution")
	}
	if _, err := protectedinput.New(t.TempDir()); err == nil {
		t.Fatal("plain temporary directory accepted as encrypted")
	}
	p := m.Prepare(&pb.ExecutionPrepare{ExecutionId: "unsupported", NodeId: "node", Command: "id", Enhanced: true})
	if p.Error == "" {
		t.Fatal("unconfigured protected execution accepted")
	}
}

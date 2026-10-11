package execution

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestClosedProcessStdinDrainsValidFramesWithoutCancellingActualOutcome(t *testing.T) {
	m := testManager(t)
	dir := t.TempDir()
	ready, release := filepath.Join(dir, "stdin-closed"), filepath.Join(dir, "release")
	// Keep the real process alive after closing fd0, so an EPIPE and input
	// drain can be distinguished from process exit or manager cancellation.
	command := fmt.Sprintf(`exec 0<&-; printf ready > %q; while test ! -f %q; do sleep 0.01; done; printf '\000\377done'; printf diagnostic >&2; exit 42`, ready, release)
	p := prepare(t, m, "closed-stdin-drain", command)
	r := start(t, m, p)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("real shell did not close stdin")
		}
		time.Sleep(time.Millisecond)
	}
	if err := r.Input(&pb.ExecutionData{Sequence: 0, Data: []byte{0, 255, 1}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.inputStopped:
	case <-time.After(3 * time.Second):
		t.Fatal("closed stdin did not release the sole input writer")
	}
	select {
	case <-r.processExited:
		t.Fatal("stdin closure cancelled the still-live command")
	default:
	}
	if err := r.Input(&pb.ExecutionData{Sequence: 8, Data: []byte("invalid gap")}); err == nil {
		t.Fatal("draining ignored framing validation")
	}
	if err := r.Input(&pb.ExecutionData{Sequence: 1, Data: []byte{255, 0}}); err != nil {
		t.Fatal("valid unread input changed the process outcome:", err)
	}
	if err := r.InputEOF(&pb.ExecutionInputEOF{Sequence: 2}); err != nil {
		t.Fatal("valid EOF after closed stdin was refused:", err)
	}
	if err := r.InputEOF(&pb.ExecutionInputEOF{Sequence: 2}); err == nil {
		t.Fatal("drain accepted a duplicate EOF")
	}
	if err := os.WriteFile(release, []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, result := collect(t, r)
	if string(out) != "\x00\xffdone" || string(stderr) != "diagnostic" || result.State != "exited" || result.ExitCode != 42 || result.Reason != "" || !result.StdoutComplete || !result.StderrComplete {
		t.Fatalf("stdin drain replaced exact completed output or exit: %q %q %+v", out, stderr, result)
	}
	// Once the owned process is known exited, late cleanup must not signal a
	// potentially recycled PID or replace the already durable native result.
	r.terminate()
	stored := m.Status(p.ExecutionId)
	if stored.State != "exited" || stored.Result == nil || stored.Result.ExitCode != 42 {
		t.Fatal("post-exit cleanup changed the durable outcome")
	}
}

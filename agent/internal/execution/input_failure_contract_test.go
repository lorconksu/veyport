package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

func TestInputAndEOFBackpressureReleaseOnCancellation(t *testing.T) {
	for _, operation := range []string{"input", "eof"} {
		t.Run(operation, func(t *testing.T) {
			m := testManager(t)
			p := prepare(t, m, "blocked-stdin", "printf ready; sleep 30")
			r := start(t, m, p)
			// Observe the real command before applying backpressure. It keeps its
			// stdin open but never reads, so pipe and input queue both fill.
			ready := time.NewTimer(time.Second)
			defer ready.Stop()
			for {
				select {
				case msg := <-r.Messages():
					if msg.GetStarted() != nil {
						goto running
					}
				case <-ready.C:
					t.Fatal("command did not start")
				}
			}
		running:
			fillDone := make(chan error, 1)
			go func() {
				for seq := uint64(0); seq < 128; seq++ {
					if err := r.Input(&pb.ExecutionData{Sequence: seq, Data: make([]byte, MaxFrameBytes)}); err != nil {
						fillDone <- err
						return
					}
				}
				fillDone <- nil
			}()
			deadline := time.Now().Add(time.Second)
			for len(r.input) != cap(r.input) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if len(r.input) != cap(r.input) {
				t.Fatal("stdin did not reach bounded backpressure")
			}
			select {
			case err := <-fillDone:
				t.Fatalf("unread command accepted entire burst: %v", err)
			default:
			}
			var eofDone chan error
			if operation == "eof" {
				eofDone = make(chan error, 1)
				go func() { eofDone <- r.InputEOF(&pb.ExecutionInputEOF{Sequence: 128}) }()
			}
			if err := m.Cancel(&pb.ExecutionCancel{Binding: p.Binding, Reason: "client_lost"}); err != nil {
				t.Fatal(err)
			}
			_, _, result := collect(t, r)
			if result.State != "cancelled" || result.Reason != "client_lost" {
				t.Fatalf("backpressure changed cancellation: %+v", result)
			}
			select {
			case err := <-fillDone:
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Fatalf("input cancellation: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("input producer leaked after cancellation")
			}
			if eofDone != nil {
				select {
				case <-eofDone:
				case <-time.After(time.Second):
					t.Fatal("EOF producer leaked after cancellation")
				}
			}
			if durable := m.Status(p.ExecutionId); durable.Result == nil || !proto.Equal(durable.Result, result) {
				t.Fatalf("cancel result was not durable: %+v", durable)
			}
		})
	}
}

func TestInputAfterExitStillValidatesFramingWithoutReplacingResult(t *testing.T) {
	m := testManager(t)
	p := prepare(t, m, "finished-input", "exit 42")
	r := start(t, m, p)
	_, _, result := collect(t, r)
	for _, invalid := range []*pb.ExecutionData{nil, {Sequence: 1}, {Data: make([]byte, MaxFrameBytes+1)}} {
		if err := r.Input(invalid); err == nil {
			t.Fatal("completed command accepted malformed stdin")
		}
	}
	if err := r.InputEOF(nil); err == nil {
		t.Fatal("completed command accepted absent EOF")
	}
	if err := r.InputEOF(&pb.ExecutionInputEOF{Sequence: 1}); err == nil {
		t.Fatal("completed command accepted wrong EOF")
	}
	if err := r.Input(&pb.ExecutionData{Data: []byte("unread bytes")}); err != nil {
		t.Fatalf("late valid bytes changed completed outcome: %v", err)
	}
	if err := r.InputEOF(&pb.ExecutionInputEOF{Sequence: 1}); err != nil {
		t.Fatalf("late valid EOF changed completed outcome: %v", err)
	}
	if err := r.InputEOF(&pb.ExecutionInputEOF{Sequence: 1}); err == nil {
		t.Fatal("duplicate EOF accepted")
	}
	if durable := m.Status(p.ExecutionId); result.State != "exited" || result.ExitCode != 42 || durable.Result == nil || !proto.Equal(durable.Result, result) {
		t.Fatalf("late input replaced real exit: %+v", durable)
	}
}

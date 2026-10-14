package applicationproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnSenderFailureClosesTransportAndStopsFrames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sends atomic.Int32
	c := NewConn(ctx, func(Frame) error { sends.Add(1); return io.ErrClosedPipe }, cancel)
	defer c.Close()
	n, err := c.Write(make([]byte, MaxFrameBytes+1))
	if n != 0 || !(errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed)) {
		t.Fatalf("failed frame was counted: %d %v", n, err)
	}
	select {
	case <-c.SenderDone():
	case <-time.After(time.Second):
		t.Fatal("failed sender leaked")
	}
	if sends.Load() != 1 || ctx.Err() == nil {
		t.Fatal("sender failure did not cancel the transport")
	}
	if err := c.CloseWrite(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("EOF sent after failure: %v", err)
	}
}

func TestConnHalfCloseIsIdempotentAndReceiveBackpressureCancels(t *testing.T) {
	var sends atomic.Int32
	c := NewConn(context.Background(), func(f Frame) error {
		if !f.EOF || f.Sequence != 0 {
			t.Errorf("unexpected EOF frame: %+v", f)
		}
		sends.Add(1)
		return nil
	}, nil)
	defer c.Close()
	for range 2 {
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	if sends.Load() != 1 {
		t.Fatal("duplicate half close emitted another frame")
	}
	if n, err := c.Read(nil); n != 0 || err != nil {
		t.Fatalf("zero-byte read blocked: %d %v", n, err)
	}
	if err := c.Deliver(Frame{Data: []byte("first")}); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- c.Deliver(Frame{Sequence: 1, Data: []byte("second")}) }()
	select {
	case err := <-result:
		t.Fatalf("full receive slot did not apply backpressure: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	c.Close()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked receiver not cancelled: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked receiver leaked")
	}
	select {
	case <-c.SenderDone():
	case <-time.After(time.Second):
		t.Fatal("idle sender leaked")
	}
}

func TestConnLiveDeadlineUpdateInterruptsBothDirections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	c := NewConn(ctx, func(Frame) error { close(started); <-ctx.Done(); return ctx.Err() }, cancel)
	defer c.Close()
	writeResult, readResult := make(chan error, 1), make(chan error, 1)
	go func() { _, err := c.Write([]byte("blocked")); writeResult <- err }()
	go func() { _, err := c.Read(make([]byte, 1)); readResult <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("sender did not start")
	}
	if err := c.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	for _, result := range []chan error{writeResult, readResult} {
		select {
		case err := <-result:
			if !(errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, net.ErrClosed)) {
				t.Fatalf("deadline did not interrupt I/O: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("deadline update leaked I/O")
		}
	}
	select {
	case <-c.SenderDone():
	case <-time.After(time.Second):
		t.Fatal("deadline did not stop sender")
	}
}

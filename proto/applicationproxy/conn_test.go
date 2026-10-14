package applicationproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestConnFramesAndHalfClosePreserveByteStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var conn *Conn
	conn = NewConn(ctx, func(f Frame) error { return conn.Deliver(f) }, cancel)
	defer conn.Close()
	want := bytes.Repeat([]byte("bounded-stream"), MaxFrameBytes/2)
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Write(want)
		if err == nil {
			err = conn.CloseWrite()
		}
		errCh <- err
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("byte stream changed: %d vs %d", len(got), len(want))
	}
	if _, err := conn.Write([]byte("after EOF")); err == nil {
		t.Fatal("write after half close allowed")
	}
}

func TestConnRejectsMalformedAndOutOfOrderFrames(t *testing.T) {
	for _, f := range []Frame{{Sequence: 1, Data: []byte("x")}, {Data: make([]byte, MaxFrameBytes+1)}, {EOF: true, Data: []byte("x")}, {}} {
		c := NewConn(context.Background(), func(Frame) error { return nil }, func() {})
		if err := c.Deliver(f); err == nil {
			t.Fatalf("accepted invalid frame %+v", f)
		}
		c.Close()
	}
	c := NewConn(context.Background(), func(Frame) error { return nil }, func() {})
	defer c.Close()
	if err := c.Deliver(Frame{EOF: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.Deliver(Frame{Sequence: 1, Data: []byte("x")}); err == nil {
		t.Fatal("data after EOF allowed")
	}
}

func TestConnReadDeadlineCanBeResetAndCancellationUnblocks(t *testing.T) {
	c := NewConn(context.Background(), func(Frame) error { return nil }, func() {})
	defer c.Close()
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, err := c.Read(b[:])
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("missing timeout: %v", err)
	}
	c.SetReadDeadline(time.Time{})
	if err := c.Deliver(Frame{Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Read(b[:]); n != 1 || err != nil {
		t.Fatalf("reset deadline failed: %d %v", n, err)
	}
	result := make(chan error, 1)
	go func() { _, err := c.Read(b[:]); result <- err }()
	c.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("close read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt read")
	}
}

func TestConnWriteDeadlineCancelsBlockedSenderAndBoundsBuffering(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var once sync.Once
	cancelled := make(chan struct{})
	c := NewConn(ctx, func(Frame) error { <-ctx.Done(); return ctx.Err() }, func() { once.Do(func() { close(cancelled); cancel() }) })
	defer c.Close()
	c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	_, err := c.Write(bytes.Repeat([]byte("x"), 64<<20))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("blocked sender did not time out: %v", err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("write deadline did not cancel transport")
	}
}

func TestConnCloseCannotReleaseAlreadyBufferedData(t *testing.T) {
	c := NewConn(context.Background(), func(Frame) error { return nil }, func() {})
	if err := c.Deliver(Frame{Data: []byte("buffered")}); err != nil {
		t.Fatal(err)
	}
	var first [1]byte
	if _, err := c.Read(first[:]); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := c.Read(first[:]); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("revocation released cached data: %v", err)
	}
}

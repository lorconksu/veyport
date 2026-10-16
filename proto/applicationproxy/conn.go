package applicationproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const MaxFrameBytes = 64 << 10
const WriteStallTimeout = 30 * time.Second

var ErrFrame = errors.New("invalid application byte frame")

type Frame struct {
	Sequence uint64
	Data     []byte
	EOF      bool
}
type sendRequest struct {
	frame  Frame
	result chan error
}

// Conn bounds retained bytes to one incoming frame, one reader frame, one
// queued and one sending frame. A single goroutine owns Send. Its cancellation
// callback must interrupt the underlying RPC, including a blocked Send.
type Conn struct {
	ctx                           context.Context
	send                          func(Frame) error
	cancel                        func()
	done                          chan struct{}
	senderDone                    chan struct{}
	once                          sync.Once
	incoming                      chan Frame
	outgoing                      chan sendRequest
	readMu, writeMu, receiveMu    sync.Mutex
	readData                      []byte
	readEOF, writeEOF, receiveEOF bool
	receiveSequence, sendSequence uint64
	mu                            sync.Mutex
	readDeadline, writeDeadline   time.Time
	wake                          chan struct{}
}

func NewConn(ctx context.Context, send func(Frame) error, cancel func()) *Conn {
	c := &Conn{ctx: ctx, send: send, cancel: cancel, done: make(chan struct{}), senderDone: make(chan struct{}), incoming: make(chan Frame, 1), outgoing: make(chan sendRequest, 1), wake: make(chan struct{})}
	go c.sendLoop()
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-c.done:
		}
	}()
	return c
}
func (c *Conn) Done() <-chan struct{}       { return c.done }
func (c *Conn) SenderDone() <-chan struct{} { return c.senderDone }
func (c *Conn) Close() error {
	c.once.Do(func() {
		close(c.done)
		if c.cancel != nil {
			c.cancel()
		}
	})
	return nil
}
func (c *Conn) sendLoop() {
	defer close(c.senderDone)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		select {
		case <-c.done:
			return
		case request := <-c.outgoing:
			select {
			case <-c.done:
				request.result <- net.ErrClosed
				return
			default:
			}
			err := c.send(request.frame)
			request.result <- err
			if err != nil {
				c.Close()
				return
			}
		}
	}
}

// Deliver is called by the sole RPC receive owner. A full incoming slot blocks
// reception and lets HTTP/2 backpressure reach the sending endpoint.
func (c *Conn) Deliver(frame Frame) error {
	c.receiveMu.Lock()
	defer c.receiveMu.Unlock()
	if c.receiveEOF || frame.Sequence != c.receiveSequence || len(frame.Data) > MaxFrameBytes || frame.EOF && len(frame.Data) != 0 || !frame.EOF && len(frame.Data) == 0 {
		c.Close()
		return ErrFrame
	}
	frame.Data = append([]byte(nil), frame.Data...)
	select {
	case <-c.done:
		return net.ErrClosed
	case c.incoming <- frame:
		c.receiveSequence++
		c.receiveEOF = frame.EOF
		return nil
	}
}
func (c *Conn) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		select {
		case <-c.done:
			return 0, net.ErrClosed
		default:
		}
		if len(c.readData) > 0 {
			n := copy(data, c.readData)
			c.readData = c.readData[n:]
			return n, nil
		}
		if c.readEOF {
			return 0, io.EOF
		}
		deadline, wake := c.deadline(true, time.Time{})
		timer, ch := deadlineTimer(deadline)
		select {
		case <-c.done:
			stopTimer(timer)
			return 0, net.ErrClosed
		case <-ch:
			return 0, os.ErrDeadlineExceeded
		case <-wake:
			stopTimer(timer)
		case frame := <-c.incoming:
			stopTimer(timer)
			c.readData = frame.Data
			c.readEOF = frame.EOF
		}
	}
}
func (c *Conn) Write(data []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEOF {
		return 0, net.ErrClosed
	}
	written := 0
	for len(data) > 0 {
		n := min(len(data), MaxFrameBytes)
		frame := Frame{Sequence: c.sendSequence, Data: append([]byte(nil), data[:n]...)}
		if err := c.writeFrame(frame); err != nil {
			return written, err
		}
		c.sendSequence++
		written += n
		data = data[n:]
	}
	return written, nil
}
func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEOF {
		return nil
	}
	if err := c.writeFrame(Frame{Sequence: c.sendSequence, EOF: true}); err != nil {
		return err
	}
	c.sendSequence++
	c.writeEOF = true
	return nil
}
func (c *Conn) writeFrame(frame Frame) error {
	request := sendRequest{frame: frame, result: make(chan error, 1)}
	stall := time.Now().Add(WriteStallTimeout)
	queued := false
	for {
		deadline, wake := c.deadline(false, stall)
		timer, ch := deadlineTimer(deadline)
		if !queued {
			select {
			case <-c.done:
				stopTimer(timer)
				return net.ErrClosed
			case <-ch:
				c.Close()
				return os.ErrDeadlineExceeded
			case <-wake:
				stopTimer(timer)
			case c.outgoing <- request:
				stopTimer(timer)
				queued = true
			}
		} else {
			select {
			case <-c.done:
				stopTimer(timer)
				return net.ErrClosed
			case <-ch:
				c.Close()
				return os.ErrDeadlineExceeded
			case <-wake:
				stopTimer(timer)
			case err := <-request.result:
				stopTimer(timer)
				return err
			}
		}
	}
}
func (c *Conn) deadline(read bool, fallback time.Time) (time.Time, <-chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value := c.writeDeadline
	if read {
		value = c.readDeadline
	}
	if !fallback.IsZero() && (value.IsZero() || fallback.Before(value)) {
		value = fallback
	}
	return value, c.wake
}
func deadlineTimer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	timer := time.NewTimer(time.Until(deadline))
	return timer, timer.C
}
func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}
func (c *Conn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.notify()
	return nil
}
func (c *Conn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = deadline
	c.notify()
	return nil
}
func (c *Conn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = deadline
	c.notify()
	return nil
}
func (c *Conn) notify() { close(c.wake); c.wake = make(chan struct{}) }

type tunnelAddress string

func (a tunnelAddress) Network() string { return "application" }
func (a tunnelAddress) String() string  { return string(a) }
func (c *Conn) LocalAddr() net.Addr     { return tunnelAddress("hub") }
func (c *Conn) RemoteAddr() net.Addr    { return tunnelAddress("backend") }

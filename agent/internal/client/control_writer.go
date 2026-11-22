package client

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/wyiu/veyport/proto/fileview"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

type fileDataRecord struct {
	ctx     context.Context
	message *pb.AgentMessage
	sent    chan error
}

func (r fileDataRecord) forward(send func(*pb.AgentMessage) error, cancelStream context.CancelFunc) error {
	if err := r.ctx.Err(); err != nil {
		r.sent <- err
		return nil
	}
	// The worker context bounds its wait, but only cancellation of the
	// Connect generation can interrupt a blocked gRPC Send.
	expired := make(chan struct{})
	health := time.AfterFunc(fileview.FileDataIdleTimeout, func() {
		cancelStream()
		close(expired)
	})
	err := send(r.message)
	if !health.Stop() {
		<-expired
	}
	r.sent <- err
	return err
}

// The Connect stream has exactly one writer. Only one bulk record may be in
// flight, so ready control messages can go before another file record.
func runControlWriter(ctx context.Context, cancelStream context.CancelFunc, send func(*pb.AgentMessage) error, control <-chan *pb.AgentMessage, fileData <-chan fileDataRecord, recvErr <-chan error, reconnect <-chan struct{}) error {
	for {
		bulk := fileData
		if len(control) != 0 {
			// This writer is the only consumer of the buffered control queue.
			bulk = nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErr:
			return fmt.Errorf("receive error: %w", err)
		case message := <-control:
			if err := send(message); err != nil {
				return fmt.Errorf("send: %w", err)
			}
		case record := <-bulk:
			if err := record.forward(send, cancelStream); err != nil {
				return fmt.Errorf("send file data: %w", err)
			}
		case <-reconnect:
			log.Printf("adopting renewed certificate via reconnect")
			return errReconnectWithMTLS
		}
	}
}

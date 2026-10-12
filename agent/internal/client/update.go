package client

import (
	"context"
	"fmt"
	"log"

	"github.com/wyiu/veyport/agent/internal/update"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func (c *Client) handleUpdateMessage(ctx context.Context, message *pb.HubMessage, send chan<- *pb.AgentMessage) bool {
	switch payload := message.Payload.(type) {
	case *pb.HubMessage_AgentUpdateRequest:
		if c.updates == nil {
			return true
		}
		emit := func(status *pb.AgentUpdateStatus) {
			select {
			case send <- &pb.AgentMessage{Payload: &pb.AgentMessage_UpdateStatus{UpdateStatus: status}}:
			case <-ctx.Done():
			default:
				select {
				case c.reconnectCh <- struct{}{}:
				default:
				}
			}
		}
		select {
		case c.updateWorkers <- struct{}{}:
			go func() {
				defer func() { <-c.updateWorkers }()
				// This RPC connection can only use the enrolled mTLS identity.
				connection, err := c.dialExecutionHub()
				if err != nil {
					capabilities := c.updates.Capabilities()
					operation := ""
					if payload.AgentUpdateRequest != nil {
						operation = payload.AgentUpdateRequest.OperationId
					}
					emit(&pb.AgentUpdateStatus{OperationId: operation, State: "failed", Reason: "update requires enrolled mTLS", Version: capabilities.Version, Revision: capabilities.Revision, Sha256: capabilities.Sha256, BootId: capabilities.BootId})
					return
				}
				defer connection.Close()
				c.updates.Begin(ctx, payload.AgentUpdateRequest, pb.NewAgentServiceClient(connection), emit)
			}()
		default:
			// The in-flight operation owns the lease. A duplicate request never
			// spawns another worker or changes its durable operation binding.
		}
		return true
	case *pb.HubMessage_UpdateConfirmation:
		if c.updates != nil {
			if err := c.updates.Confirm(payload.UpdateConfirmation); err != nil {
				log.Printf("update confirmation refused: %v", err)
			} else if status := c.updates.ResumeStatus(); status != nil {
				select {
				case send <- &pb.AgentMessage{Payload: &pb.AgentMessage_UpdateStatus{UpdateStatus: status}}:
				case <-ctx.Done():
				default:
					select {
					case c.reconnectCh <- struct{}{}:
					default:
					}
				}
			}
		}
		return true
	default:
		return false
	}
}

func (c *Client) RunUpdateSupervisor(ctx context.Context, operation string) error {
	connection, err := c.dialExecutionHub()
	if err != nil {
		return err
	}
	defer connection.Close()
	service := pb.NewAgentServiceClient(connection)
	return update.Supervise(ctx, operation, func(ctx context.Context, op string) (*pb.UpdateAuthorization, error) {
		return service.AuthorizeUpdate(ctx, &pb.UpdateArtifactRequest{OperationId: op})
	})
}

func (c *Client) RunUpdateBootstrap(ctx context.Context, ticket, version, revision string) error {
	connection, err := c.dialExecutionHub()
	if err != nil {
		return fmt.Errorf("bootstrap requires existing enrolled mTLS: %w", err)
	}
	defer connection.Close()
	return update.Bootstrap(ctx, ticket, version, revision, pb.NewAgentServiceClient(connection))
}

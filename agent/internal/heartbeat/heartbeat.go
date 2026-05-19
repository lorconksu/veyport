package heartbeat

import (
	"time"

	"github.com/wyiu/veyport/agent/internal/sysinfo"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func BuildMessage(serverID string) *pb.AgentMessage {
	return &pb.AgentMessage{
		Payload: &pb.AgentMessage_Heartbeat{
			Heartbeat: &pb.Heartbeat{
				ServerId:   serverID,
				Timestamp:  time.Now().Unix(),
				SystemInfo: sysinfo.Collect(),
				IpAddress:  sysinfo.OutboundIP(),
			},
		},
	}
}

func StartTicker(serverID string, interval time.Duration, out chan<- *pb.AgentMessage, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			out <- BuildMessage(serverID)
		}
	}
}

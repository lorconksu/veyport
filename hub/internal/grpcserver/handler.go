package grpcserver

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/wyiu/aerodocs/hub/internal/ca"
	"github.com/wyiu/aerodocs/hub/internal/connmgr"
	"github.com/wyiu/aerodocs/hub/internal/model"
	"github.com/wyiu/aerodocs/hub/internal/notify"
	"github.com/wyiu/aerodocs/hub/internal/store"
	pb "github.com/wyiu/aerodocs/proto/aerodocs/v1"
)

type Handler struct {
	pb.UnimplementedAgentServiceServer
	store       *store.Store
	connMgr     *connmgr.ConnManager
	pending     *PendingRequests
	logSessions *LogSessions
	hbCoalescer *HeartbeatCoalescer
	caCert      *x509.Certificate
	caKey       *ecdsa.PrivateKey
	notifier    *notify.Notifier
}

type handshakeResult struct {
	serverID          string
	bootstrapOnly     bool
	requireClientCert bool
}

// extractServerIDFromCert extracts the server ID from a client certificate's CN.
func extractServerIDFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return cert.Subject.CommonName
}

func (h *Handler) Connect(stream pb.AgentService_ConnectServer) error {
	handshake, err := h.performHandshake(stream)
	if err != nil {
		return err
	}

	if handshake.bootstrapOnly {
		return nil
	}

	if err := h.verifyCertCN(stream, handshake.serverID, handshake.requireClientCert); err != nil {
		return err
	}

	serverID := handshake.serverID
	h.connMgr.Register(serverID, stream)

	// Use stored IP (set during handshake with agent-reported IP) for logging
	agentIP := h.peerAddr(stream)
	if srv, err := h.store.GetServerByID(serverID); err == nil && srv.IPAddress != nil && *srv.IPAddress != "" {
		agentIP = *srv.IPAddress
	}
	h.onAgentConnected(serverID, agentIP)
	defer h.onAgentDisconnected(serverID, stream)

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			log.Printf("agent stream closed (EOF): %s", serverID)
			return nil
		}
		if err != nil {
			log.Printf("agent stream error: %s — %v", serverID, err)
			return err
		}
		if err := h.routeAgentMessage(serverID, stream, msg); err != nil {
			log.Printf("agent message route error: %s — %v", serverID, err)
			return err
		}
	}
}

// verifyCertCN checks that the mTLS client certificate CN matches the server ID.
// Registration is allowed without a client certificate; reconnects must present one.
func (h *Handler) verifyCertCN(stream pb.AgentService_ConnectServer, serverID string, requireCert bool) error {
	p, ok := peer.FromContext(stream.Context())
	if !ok {
		if requireCert {
			return fmt.Errorf("missing peer info for authenticated reconnect")
		}
		log.Printf("warning: no peer info for agent %s — allowing bootstrap registration without cert verification", serverID)
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		if requireCert {
			return fmt.Errorf("agent %s connected without required client certificate", serverID)
		}
		log.Printf("warning: agent %s connected without client certificate during registration", serverID)
		return nil
	}
	certCN := extractServerIDFromCert(tlsInfo.State.PeerCertificates[0])
	if certCN != serverID {
		return fmt.Errorf("cert CN %q does not match server ID %q", certCN, serverID)
	}
	return nil
}

// peerAddr extracts the client IP from the gRPC peer address.
func (h *Handler) peerAddr(stream pb.AgentService_ConnectServer) string {
	if p, ok := peer.FromContext(stream.Context()); ok {
		if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
			return host
		}
		return p.Addr.String()
	}
	return ""
}

// onAgentConnected logs the audit event and sends the online notification.
func (h *Handler) onAgentConnected(serverID, peerAddr string) {
	h.store.LogAudit(model.AuditEntry{
		Action:    model.AuditServerConnected,
		Target:    &serverID,
		IPAddress: &peerAddr,
		ActorType: model.AuditActorTypeDevice,
	})
	if h.notifier != nil {
		serverName := h.resolveServerName(serverID)
		h.notifier.Notify(model.NotifyAgentOnline, map[string]string{
			"server_name": serverName,
			"server_id":   serverID,
			"timestamp":   time.Now().UTC().Format(model.NotifyTimestampFormat),
		})
	}
	log.Printf("agent connected: %s from %s", serverID, peerAddr)
}

// onAgentDisconnected unregisters the connection, flushes heartbeats, and logs the disconnect event.
func (h *Handler) onAgentDisconnected(serverID string, stream pb.AgentService_ConnectServer) {
	if !h.connMgr.UnregisterIfCurrent(serverID, stream) {
		return
	}
	if h.hbCoalescer != nil {
		h.hbCoalescer.Flush(serverID)
	}
	_ = h.store.UpdateServerStatus(serverID, "offline")
	h.store.LogAudit(model.AuditEntry{
		Action:    model.AuditServerDisconnected,
		Target:    &serverID,
		ActorType: model.AuditActorTypeDevice,
	})
	if h.notifier != nil {
		serverName := h.resolveServerName(serverID)
		h.notifier.Notify(model.NotifyAgentOffline, map[string]string{
			"server_name": serverName,
			"server_id":   serverID,
			"timestamp":   time.Now().UTC().Format(model.NotifyTimestampFormat),
		})
	}
	log.Printf("agent disconnected: %s", serverID)
}

// resolveServerName looks up the human-readable server name, falling back to the server ID.
func (h *Handler) resolveServerName(serverID string) string {
	if srv, err := h.store.GetServerByID(serverID); err == nil {
		return srv.Name
	}
	return serverID
}

// performHandshake receives the first message from the agent, handles registration or
// reconnect-via-heartbeat, sends the appropriate ack, and returns the authenticated server ID.
func (h *Handler) performHandshake(stream pb.AgentService_ConnectServer) (*handshakeResult, error) {
	peerIP := h.peerAddr(stream)

	msg, err := stream.Recv()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to receive first message: %v", err)
	}

	switch p := msg.Payload.(type) {
	case *pb.AgentMessage_Register:
		return h.performRegisterHandshake(stream, p.Register, peerIP)
	case *pb.AgentMessage_Heartbeat:
		return h.performHeartbeatHandshake(stream, p.Heartbeat, peerIP)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "first message must be Register or Heartbeat")
	}
}

func (h *Handler) performRegisterHandshake(stream pb.AgentService_ConnectServer, reg *pb.RegisterAgent, peerIP string) (*handshakeResult, error) {
	agentIP := preferredAgentIP(reg.GetIpAddress(), peerIP)
	serverID, clientCert, caCert, err := h.handleRegister(reg.Token, reg.Hostname, agentIP, reg.Os, reg.AgentVersion, reg.Csr)
	if err != nil {
		h.logRegistrationAuditFailure(reg, peerIP, err)
		_ = stream.Send(&pb.HubMessage{
			Payload: &pb.HubMessage_RegisterAck{
				RegisterAck: &pb.RegisterAck{Success: false, Error: err.Error()},
			},
		})
		return nil, status.Errorf(codes.Unauthenticated, "registration failed: %v", err)
	}
	h.logRegistrationAuditSuccess(serverID, reg, peerIP)
	if err := stream.Send(&pb.HubMessage{
		Payload: &pb.HubMessage_RegisterAck{
			RegisterAck: &pb.RegisterAck{
				Success:    true,
				ServerId:   serverID,
				ClientCert: clientCert,
				CaCert:     caCert,
			},
		},
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to send register ack: %v", err)
	}

	if h.notifier != nil {
		serverName := reg.Hostname
		if serverName == "" {
			serverName = serverID
		}
		h.notifier.Notify(model.NotifyAgentRegistered, map[string]string{
			"server_name": serverName,
			"server_id":   serverID,
			"timestamp":   time.Now().UTC().Format(model.NotifyTimestampFormat),
		})
	}

	return &handshakeResult{serverID: serverID, bootstrapOnly: true}, nil
}

func (h *Handler) logRegistrationAuditSuccess(serverID string, reg *pb.RegisterAgent, peerIP string) {
	detail := registrationAuditDetail(reg, "")
	h.store.LogAudit(model.AuditEntry{
		Action:    model.AuditServerRegistered,
		Target:    &serverID,
		Detail:    &detail,
		IPAddress: optionalStringPointer(peerIP),
		ActorType: model.AuditActorTypeDevice,
	})
}

func (h *Handler) logRegistrationAuditFailure(reg *pb.RegisterAgent, peerIP string, err error) {
	detail := registrationAuditDetail(reg, err.Error())
	h.store.LogAudit(model.AuditEntry{
		Action:    model.AuditServerRegistrationFailed,
		Detail:    &detail,
		IPAddress: optionalStringPointer(peerIP),
		ActorType: model.AuditActorTypeDevice,
	})
}

func registrationAuditDetail(reg *pb.RegisterAgent, failure string) string {
	parts := []string{"phase=bootstrap", "method=registration_token"}
	if reg != nil {
		if reg.Hostname != "" {
			parts = append(parts, "hostname="+reg.Hostname)
		}
		if reg.Os != "" {
			parts = append(parts, "os="+reg.Os)
		}
		if reg.AgentVersion != "" {
			parts = append(parts, "agent_version="+reg.AgentVersion)
		}
	}
	if failure != "" {
		parts = append(parts, "result=failed", "reason="+failure)
	} else {
		parts = append(parts, "result=accepted")
	}
	return strings.Join(parts, " ")
}

func optionalStringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func preferredAgentIP(reportedIP, peerIP string) string {
	if net.ParseIP(reportedIP) != nil {
		return reportedIP
	}
	return peerIP
}

func (h *Handler) performHeartbeatHandshake(stream pb.AgentService_ConnectServer, hb *pb.Heartbeat, peerIP string) (*handshakeResult, error) {
	serverID := hb.ServerId
	if err := h.verifyCertCN(stream, serverID, true); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "heartbeat authentication failed: %v", err)
	}
	if err := h.handleHeartbeat(serverID); err != nil {
		return nil, status.Errorf(codes.NotFound, "heartbeat failed: %v", err)
	}
	if err := stream.Send(&pb.HubMessage{
		Payload: &pb.HubMessage_HeartbeatAck{
			HeartbeatAck: &pb.HeartbeatAck{Timestamp: time.Now().Unix()},
		},
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to send heartbeat ack: %v", err)
	}

	if ip := preferredAgentIP(hb.GetIpAddress(), peerIP); ip != "" {
		_ = h.store.UpdateServerIP(serverID, ip)
	}

	return &handshakeResult{serverID: serverID}, nil
}

// routeAgentMessage dispatches an incoming agent message to the appropriate handler.
func (h *Handler) routeAgentMessage(serverID string, stream pb.AgentService_ConnectServer, msg *pb.AgentMessage) error {
	switch p := msg.Payload.(type) {
	case *pb.AgentMessage_Heartbeat:
		return h.handleStreamHeartbeat(serverID, stream)
	case *pb.AgentMessage_FileListResponse:
		if h.pending != nil {
			h.pending.Deliver(serverID, p.FileListResponse.RequestId, p.FileListResponse)
		}
	case *pb.AgentMessage_FileReadResponse:
		if h.pending != nil {
			h.pending.Deliver(serverID, p.FileReadResponse.RequestId, p.FileReadResponse)
		}
	case *pb.AgentMessage_LogStreamChunk:
		if h.logSessions != nil {
			h.logSessions.Deliver(serverID, p.LogStreamChunk.RequestId, p.LogStreamChunk.Data)
		}
	case *pb.AgentMessage_FileUploadAck:
		if h.pending != nil {
			h.pending.Deliver(serverID, p.FileUploadAck.RequestId, p.FileUploadAck)
		}
	case *pb.AgentMessage_FileDeleteResponse:
		if h.pending != nil {
			h.pending.Deliver(serverID, p.FileDeleteResponse.RequestId, p.FileDeleteResponse)
		}
	case *pb.AgentMessage_UnregisterAck:
		if h.pending != nil {
			h.pending.Deliver(serverID, p.UnregisterAck.RequestId, p.UnregisterAck)
		}
	case *pb.AgentMessage_CertRenewRequest:
		h.handleCertRenewal(serverID, stream, p.CertRenewRequest)
	default:
		log.Printf("unhandled message type from %s: %T", serverID, p)
	}
	return nil
}

// handleStreamHeartbeat processes an in-stream heartbeat, updates last-seen, and sends an ack.
func (h *Handler) handleStreamHeartbeat(serverID string, stream pb.AgentService_ConnectServer) error {
	h.connMgr.UpdateHeartbeat(serverID)
	if h.hbCoalescer != nil {
		h.hbCoalescer.RecordHeartbeat(serverID)
	} else {
		_ = h.store.UpdateServerLastSeen(serverID, nil)
	}
	conn := h.connMgr.GetConn(serverID)
	if conn == nil {
		return nil
	}
	conn.SendMu.Lock()
	err := stream.Send(&pb.HubMessage{
		Payload: &pb.HubMessage_HeartbeatAck{
			HeartbeatAck: &pb.HeartbeatAck{
				Timestamp: time.Now().Unix(),
			},
		},
	})
	conn.SendMu.Unlock()
	return err
}

func (h *Handler) handleRegister(rawToken, hostname, ip, os, agentVersion string, csr []byte) (string, []byte, []byte, error) {
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := fmt.Sprintf("%x", hash)
	srv, err := h.store.GetServerByToken(tokenHash)
	if err != nil {
		return "", nil, nil, fmt.Errorf("invalid or expired registration token")
	}
	if srv.TokenExpiresAt != nil {
		expiresAt, err := time.Parse("2006-01-02 15:04:05", *srv.TokenExpiresAt)
		if err == nil && time.Now().UTC().After(expiresAt) {
			return "", nil, nil, fmt.Errorf("registration token expired")
		}
	}
	clientCert, caCert, err := h.issueRegistrationCertificate(srv.ID, csr)
	if err != nil {
		return "", nil, nil, err
	}
	if err := h.store.ActivateServer(srv.ID, hostname, ip, os, agentVersion); err != nil {
		return "", nil, nil, fmt.Errorf("failed to activate server: %w", err)
	}
	return srv.ID, clientCert, caCert, nil
}

func (h *Handler) issueRegistrationCertificate(serverID string, csr []byte) ([]byte, []byte, error) {
	if len(csr) == 0 {
		return nil, nil, fmt.Errorf("registration CSR required")
	}
	if h.caCert == nil || h.caKey == nil {
		return nil, nil, fmt.Errorf("CA not configured")
	}
	clientCert, err := ca.SignCSR(h.caCert, h.caKey, csr, serverID, 12*time.Hour)
	if err != nil {
		return nil, nil, fmt.Errorf("sign client certificate: %w", err)
	}
	return clientCert.Raw, h.caCert.Raw, nil
}

func (h *Handler) handleHeartbeat(serverID string) error {
	srv, err := h.store.GetServerByID(serverID)
	if err != nil {
		return fmt.Errorf("unknown server: %s", serverID)
	}
	if srv.Status != "online" {
		if err := h.store.UpdateServerStatus(serverID, "online"); err != nil {
			return fmt.Errorf("failed to update status: %w", err)
		}
	}
	// Handshake heartbeat always writes immediately (bypass coalescing).
	if h.hbCoalescer != nil {
		h.hbCoalescer.ForceWrite(serverID)
	} else {
		_ = h.store.UpdateServerLastSeen(serverID, nil)
	}
	return nil
}

// handleCertRenewal processes a certificate renewal request from an agent.
// It signs the provided CSR with the CA and returns the new client certificate.
func (h *Handler) handleCertRenewal(serverID string, stream pb.AgentService_ConnectServer, req *pb.CertRenewRequest) {
	sendCertResponse := func(resp *pb.CertRenewResponse) {
		conn := h.connMgr.GetConn(serverID)
		if conn == nil {
			return
		}
		conn.SendMu.Lock()
		_ = stream.Send(&pb.HubMessage{
			Payload: &pb.HubMessage_CertRenewResponse{
				CertRenewResponse: resp,
			},
		})
		conn.SendMu.Unlock()
	}

	if h.caCert == nil || h.caKey == nil {
		sendCertResponse(&pb.CertRenewResponse{Error: "CA not configured"})
		return
	}

	clientCert, err := ca.SignCSR(h.caCert, h.caKey, req.Csr, serverID, 12*time.Hour)
	if err != nil {
		sendCertResponse(&pb.CertRenewResponse{Error: err.Error()})
		return
	}

	sendCertResponse(&pb.CertRenewResponse{
		ClientCert: clientCert.Raw,
		CaCert:     h.caCert.Raw,
	})
}

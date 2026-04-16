package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/wyiu/aerodocs/agent/internal/certs"
	"github.com/wyiu/aerodocs/agent/internal/dropzone"
	"github.com/wyiu/aerodocs/agent/internal/filebrowser"
	"github.com/wyiu/aerodocs/agent/internal/heartbeat"
	"github.com/wyiu/aerodocs/agent/internal/logtailer"
	pb "github.com/wyiu/aerodocs/proto/aerodocs/v1"
)

type Config struct {
	HubAddr         string
	ServerID        string
	Token           string
	Hostname        string
	IPAddress       string
	OS              string
	AgentVersion    string
	CertDir         string // directory for mTLS cert storage; empty uses /etc/aerodocs/tls/
	UnregisterToken string
	Insecure        bool
	AllowedPaths    []string
	HubCAPin        string
	DropzoneDir     string
	OnRegistered    func(serverID string)
}

const (
	maxTailSessions   = 50
	dropzonePathAlias = "aerodocs://dropzone"
)

var errReconnectWithMTLS = errors.New("reconnect required to authenticate with issued client certificate")

type Client struct {
	hubAddr         string
	serverID        string
	token           string
	hostname        string
	ipAddress       string
	os              string
	agentVersion    string
	backoff         time.Duration
	maxBackoff      time.Duration
	tailSessionsMu  sync.Mutex
	tailSessions    map[string]chan struct{}
	dropzone        *dropzone.Dropzone
	certStore       *certs.Store
	unregisterToken string
	insecure        bool
	allowedPaths    []string
	hubCAPin        string
	onRegistered    func(serverID string)
}

func New(cfg Config) *Client {
	certDir := cfg.CertDir
	if certDir == "" {
		certDir = "/etc/aerodocs/tls/"
	}
	dropzoneDir := cfg.DropzoneDir
	if dropzoneDir == "" {
		dropzoneDir = dropzone.DefaultDir
	}
	return &Client{
		hubAddr:         cfg.HubAddr,
		serverID:        cfg.ServerID,
		token:           cfg.Token,
		hostname:        cfg.Hostname,
		ipAddress:       cfg.IPAddress,
		os:              cfg.OS,
		agentVersion:    cfg.AgentVersion,
		backoff:         1 * time.Second,
		maxBackoff:      60 * time.Second,
		tailSessions:    make(map[string]chan struct{}),
		dropzone:        dropzone.New(dropzoneDir),
		certStore:       certs.NewStore(certDir),
		unregisterToken: cfg.UnregisterToken,
		insecure:        cfg.Insecure,
		allowedPaths:    cfg.AllowedPaths,
		hubCAPin:        cfg.HubCAPin,
		onRegistered:    cfg.OnRegistered,
	}
}

func (c *Client) ServerID() string {
	return c.serverID
}

// SelfUnregister calls the Hub's HTTP API to delete this server.
// Used by the install script to clean up the old registration before a re-install.
func (c *Client) SelfUnregister(ctx context.Context) error {
	// Derive HTTP base URL from the gRPC hub address
	host, port, err := net.SplitHostPort(c.hubAddr)
	if err != nil {
		host = c.hubAddr
		port = ""
	}

	var baseURL string
	if port == "443" || (net.ParseIP(host) == nil && strings.Contains(host, ".")) {
		// Hostname — use HTTPS (same host, default HTTPS port)
		baseURL = "https://" + host
	} else {
		// Direct IP — Hub HTTP is on port 8081 by convention, but we don't know for sure.
		// Try the common case: same host, port 8081
		baseURL = "http://" + host + ":8081"
	}

	url := fmt.Sprintf("%s/api/servers/%s/self-unregister", baseURL, c.serverID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if c.unregisterToken != "" {
		req.Header.Set("X-Unregister-Token", c.unregisterToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil // Success or already gone
	}
	return fmt.Errorf("unexpected status: %d", resp.StatusCode)
}

func (c *Client) Run(ctx context.Context) error {
	regFailures := 0
	for {
		err := c.connectAndStream(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, errReconnectWithMTLS) {
			regFailures = 0
			c.resetBackoff()
			continue
		}

		// Track consecutive registration failures — exit if the server
		// has been unregistered (avoids infinite reconnect loop).
		if err != nil && strings.Contains(err.Error(), "registration") {
			regFailures++
			if regFailures >= 3 {
				log.Printf("server appears unregistered after %d consecutive failures — exiting", regFailures)
				return fmt.Errorf("server unregistered: %w", err)
			}
		} else {
			regFailures = 0
		}

		wait := c.nextBackoff()
		log.Printf("connection lost: %v — reconnecting in %v", err, wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// isPathAllowed checks whether path falls under one of the allowed prefixes.
// If allowedPaths is empty, all paths are allowed.
func isPathAllowed(path string, allowedPaths []string) bool {
	if len(allowedPaths) == 0 {
		return true
	}
	cleaned := filepath.Clean(path)
	if !pathWithinAllowedRoots(cleaned, allowedPaths) {
		return false
	}

	// Paths that do not resolve yet should still reach the underlying handler so it can
	// return the appropriate "not found" style error.
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return true
	}

	return pathWithinAllowedRoots(filepath.Clean(resolved), allowedPaths)
}

func pathWithinAllowedRoots(path string, allowedPaths []string) bool {
	for _, allowed := range allowedPaths {
		for _, root := range candidateAllowedRoots(allowed) {
			if pathWithinRoot(path, root) {
				return true
			}
		}
	}
	return false
}

func candidateAllowedRoots(root string) []string {
	cleaned := filepath.Clean(root)
	roots := []string{cleaned}
	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		resolved = filepath.Clean(resolved)
		if resolved != cleaned {
			roots = append(roots, resolved)
		}
	}
	return roots
}

func pathWithinRoot(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func (c *Client) resolveAgentPath(path string) string {
	if path == dropzonePathAlias {
		return c.dropzone.Dir()
	}
	prefix := dropzonePathAlias + "/"
	if strings.HasPrefix(path, prefix) {
		rel := strings.TrimPrefix(path, prefix)
		return filepath.Join(c.dropzone.Dir(), filepath.Clean(rel))
	}
	return path
}

func (c *Client) handleFileListRequest(p *pb.HubMessage_FileListRequest, sendCh chan<- *pb.AgentMessage) {
	resolvedPath := c.resolveAgentPath(p.FileListRequest.Path)
	if !isPathAllowed(resolvedPath, c.allowedPaths) {
		sendCh <- &pb.AgentMessage{
			Payload: &pb.AgentMessage_FileListResponse{
				FileListResponse: &pb.FileListResponse{
					RequestId: p.FileListRequest.RequestId,
					Error:     "path not in allowed list",
				},
			},
		}
		return
	}
	resp, _ := filebrowser.ListDir(resolvedPath)
	if resp != nil {
		resp.RequestId = p.FileListRequest.RequestId
		sendCh <- &pb.AgentMessage{
			Payload: &pb.AgentMessage_FileListResponse{
				FileListResponse: resp,
			},
		}
	}
}

func (c *Client) handleFileReadRequest(p *pb.HubMessage_FileReadRequest, sendCh chan<- *pb.AgentMessage) {
	resolvedPath := c.resolveAgentPath(p.FileReadRequest.Path)
	if !isPathAllowed(resolvedPath, c.allowedPaths) {
		sendCh <- &pb.AgentMessage{
			Payload: &pb.AgentMessage_FileReadResponse{
				FileReadResponse: &pb.FileReadResponse{
					RequestId: p.FileReadRequest.RequestId,
					Error:     "path not in allowed list",
				},
			},
		}
		return
	}
	resp, _ := filebrowser.ReadFile(
		resolvedPath,
		p.FileReadRequest.Offset,
		p.FileReadRequest.Limit,
	)
	if resp != nil {
		resp.RequestId = p.FileReadRequest.RequestId
		sendCh <- &pb.AgentMessage{
			Payload: &pb.AgentMessage_FileReadResponse{
				FileReadResponse: resp,
			},
		}
	}
}

func (c *Client) handleLogStreamRequest(p *pb.HubMessage_LogStreamRequest, sendCh chan<- *pb.AgentMessage) {
	req := p.LogStreamRequest
	resolvedPath := c.resolveAgentPath(req.Path)
	if !isPathAllowed(resolvedPath, c.allowedPaths) {
		sendCh <- &pb.AgentMessage{
			Payload: &pb.AgentMessage_LogStreamChunk{
				LogStreamChunk: &pb.LogStreamChunk{
					RequestId: req.RequestId,
					Data:      []byte("error: path not in allowed list"),
				},
			},
		}
		return
	}
	c.tailSessionsMu.Lock()
	if len(c.tailSessions) >= maxTailSessions {
		c.tailSessionsMu.Unlock()
		sendCh <- &pb.AgentMessage{
			Payload: &pb.AgentMessage_LogStreamChunk{
				LogStreamChunk: &pb.LogStreamChunk{
					RequestId: req.RequestId,
					Data:      []byte("error: too many active tail sessions"),
				},
			},
		}
		return
	}
	stop := make(chan struct{})
	c.tailSessions[req.RequestId] = stop
	c.tailSessionsMu.Unlock()
	go logtailer.StartTail(resolvedPath, req.Grep, req.Offset, sendCh, req.RequestId, stop)
	log.Printf("started log tail: %s path=%s grep=%s", req.RequestId, resolvedPath, req.Grep)
}

func (c *Client) handleLogStreamStop(p *pb.HubMessage_LogStreamStop) {
	c.tailSessionsMu.Lock()
	stop, ok := c.tailSessions[p.LogStreamStop.RequestId]
	if ok {
		delete(c.tailSessions, p.LogStreamStop.RequestId)
	}
	c.tailSessionsMu.Unlock()
	if ok {
		close(stop)
		log.Printf("stopped log tail: %s", p.LogStreamStop.RequestId)
	}
}

func (c *Client) handleFileUploadRequest(p *pb.HubMessage_FileUploadRequest, sendCh chan<- *pb.AgentMessage) {
	req := p.FileUploadRequest
	ack := c.dropzone.HandleChunk(req.RequestId, req.Filename, req.Chunk, req.Done)
	if ack != nil {
		sendCh <- &pb.AgentMessage{
			Payload: &pb.AgentMessage_FileUploadAck{
				FileUploadAck: ack,
			},
		}
	}
}

func (c *Client) handleFileDeleteRequest(p *pb.HubMessage_FileDeleteRequest, sendCh chan<- *pb.AgentMessage) {
	req := p.FileDeleteRequest
	resp := &pb.FileDeleteResponse{RequestId: req.RequestId}
	// Only allow deletion from dropzone directory
	cleanPath := filepath.Clean(c.resolveAgentPath(req.Path))
	dropzonePrefix := filepath.Clean(c.dropzone.Dir()) + "/"
	if !strings.HasPrefix(cleanPath, dropzonePrefix) {
		resp.Success = false
		resp.Error = "deletion only allowed from dropzone directory"
	} else if err := os.Remove(cleanPath); err != nil {
		log.Printf("dropzone delete error: %v", err)
		resp.Success = false
		resp.Error = "file operation failed"
	} else {
		resp.Success = true
	}
	sendCh <- &pb.AgentMessage{
		Payload: &pb.AgentMessage_FileDeleteResponse{
			FileDeleteResponse: resp,
		},
	}
}

func (c *Client) handleUnregisterRequest(p *pb.HubMessage_UnregisterRequest, sendCh chan<- *pb.AgentMessage) {
	req := p.UnregisterRequest
	// Require mTLS for unregister — reject if no cert is present
	if !c.certStore.HasCert() {
		sendCh <- &pb.AgentMessage{
			Payload: &pb.AgentMessage_UnregisterAck{
				UnregisterAck: &pb.UnregisterAck{
					RequestId: req.RequestId,
					Success:   false,
				},
			},
		}
		log.Printf("unregister rejected: no mTLS certificate")
		return
	}
	// Send ack before self-destruct
	sendCh <- &pb.AgentMessage{
		Payload: &pb.AgentMessage_UnregisterAck{
			UnregisterAck: &pb.UnregisterAck{
				RequestId: req.RequestId,
				Success:   true,
			},
		},
	}
	log.Printf("unregister requested — initiating self-cleanup")
	// Give the ack time to send, then run cleanup
	go func() {
		time.Sleep(2 * time.Second)
		c.selfCleanup()
	}()
}

func (c *Client) handleMessage(msg *pb.HubMessage, sendCh chan<- *pb.AgentMessage) {
	switch p := msg.Payload.(type) {
	case *pb.HubMessage_FileListRequest:
		c.handleFileListRequest(p, sendCh)
	case *pb.HubMessage_FileReadRequest:
		c.handleFileReadRequest(p, sendCh)
	case *pb.HubMessage_LogStreamRequest:
		c.handleLogStreamRequest(p, sendCh)
	case *pb.HubMessage_LogStreamStop:
		c.handleLogStreamStop(p)
	case *pb.HubMessage_FileUploadRequest:
		c.handleFileUploadRequest(p, sendCh)
	case *pb.HubMessage_FileDeleteRequest:
		c.handleFileDeleteRequest(p, sendCh)
	case *pb.HubMessage_UnregisterRequest:
		c.handleUnregisterRequest(p, sendCh)
	case *pb.HubMessage_CertRenewResponse:
		c.handleCertRenewResponse(p)
	default:
		log.Printf("unhandled hub message: %T", p)
	}
}

func (c *Client) handleCertRenewResponse(p *pb.HubMessage_CertRenewResponse) {
	resp := p.CertRenewResponse
	if resp.Error != "" {
		log.Printf("cert renewal rejected: %s", resp.Error)
		return
	}
	if len(resp.ClientCert) == 0 || len(resp.CaCert) == 0 {
		log.Printf("cert renewal response missing certs")
		return
	}
	if err := c.certStore.StoreCert(resp.ClientCert, resp.CaCert); err != nil {
		log.Printf("failed to store renewed certs: %v", err)
		return
	}
	log.Printf("mTLS certificate renewed (will use on next reconnect)")
}

// startCertRenewalTicker checks cert expiry every 10s alongside heartbeats
// and sends a CertRenewRequest when renewal is needed.
func (c *Client) startCertRenewalTicker(interval time.Duration, sendCh chan<- *pb.AgentMessage, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if !c.certStore.HasCert() || !c.certStore.NeedsRenewal(6*time.Hour) {
				continue
			}
			csrDER, err := c.certStore.GenerateCSR(c.serverID)
			if err != nil {
				log.Printf("cert renewal CSR generation failed: %v", err)
				continue
			}
			sendCh <- &pb.AgentMessage{
				Payload: &pb.AgentMessage_CertRenewRequest{
					CertRenewRequest: &pb.CertRenewRequest{
						Csr: csrDER,
					},
				},
			}
			log.Printf("sent cert renewal request")
		}
	}
}

// dialHub creates a gRPC connection to the hub with 3-tier TLS:
//  1. mTLS if the cert store has a valid certificate
//  2. Insecure (no TLS) if the --insecure flag is set
//  3. Pinned-CA bootstrap TLS for the first registration
func (c *Client) dialHub() (*grpc.ClientConn, error) {
	var creds grpc.DialOption
	if tlsCfg := c.certStore.TLSConfig(); tlsCfg != nil {
		creds = grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
	} else if !c.useTLS() {
		creds = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else {
		tlsCfg, err := c.bootstrapTLSConfig()
		if err != nil {
			return nil, err
		}
		creds = grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
	}
	conn, err := grpc.NewClient(c.hubAddr, creds,
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("dial hub: %w", err)
	}
	return conn, nil
}

func (c *Client) bootstrapTLSConfig() (*tls.Config, error) {
	if c.hubCAPin == "" {
		return nil, fmt.Errorf("missing hub CA pin for bootstrap TLS")
	}
	expectedPin, err := hex.DecodeString(c.hubCAPin)
	if err != nil {
		return nil, fmt.Errorf("decode hub CA pin: %w", err)
	}
	host, _, err := net.SplitHostPort(c.hubAddr)
	if err != nil {
		host = c.hubAddr
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // NOSONAR: bootstrap trust is enforced by verifyPinnedHubCertificate against the pinned CA.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPinnedHubCertificate(rawCerts, expectedPin, host)
		},
	}, nil
}

func verifyPinnedHubCertificate(rawCerts [][]byte, expectedPin []byte, host string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("hub did not present a certificate chain")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("parse hub certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	leaf := certs[0]
	var pinnedCA *x509.Certificate
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		sum := sha256.Sum256(cert.Raw)
		if bytes.Equal(sum[:], expectedPin) {
			pinnedCA = cert
			continue
		}
		intermediates.AddCert(cert)
	}
	if pinnedCA == nil {
		return fmt.Errorf("hub TLS chain did not include the expected CA pin")
	}
	roots := x509.NewCertPool()
	roots.AddCert(pinnedCA)
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if parsedIP := net.ParseIP(host); parsedIP == nil && host != "" {
		opts.DNSName = host
	}
	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("verify hub certificate: %w", err)
	}
	return nil
}

// registerOrHandshake sends the initial register (first connect) or heartbeat
// (reconnect) message and waits for the corresponding ack.
func (c *Client) registerOrHandshake(stream pb.AgentService_ConnectClient) (bool, error) {
	if c.serverID == "" {
		return c.sendRegister(stream)
	}
	return false, c.sendHeartbeatHandshake(stream)
}

// sendRegister performs the initial agent registration, assigns the server ID,
// and stores any mTLS certificates provided in the ack.
func (c *Client) sendRegister(stream pb.AgentService_ConnectClient) (bool, error) {
	csrDER := c.generateCSRForRegistration()

	if err := stream.Send(&pb.AgentMessage{
		Payload: &pb.AgentMessage_Register{
			Register: &pb.RegisterAgent{
				Token:        c.token,
				Hostname:     c.hostname,
				IpAddress:    c.ipAddress,
				Os:           c.os,
				AgentVersion: c.agentVersion,
				Csr:          csrDER,
			},
		},
	}); err != nil {
		return false, fmt.Errorf("send register: %w", err)
	}

	msg, err := stream.Recv()
	if err != nil {
		return false, fmt.Errorf("recv register ack: %w", err)
	}
	ack := msg.GetRegisterAck()
	if ack == nil {
		return false, fmt.Errorf("expected RegisterAck, got %T", msg.Payload)
	}
	if !ack.Success {
		return false, fmt.Errorf("registration rejected: %s", ack.Error)
	}
	c.serverID = ack.ServerId
	log.Printf("registered successfully: server_id=%s", c.serverID)
	c.storeMTLSCerts(ack)
	if c.onRegistered != nil {
		c.onRegistered(c.serverID)
	}
	return true, nil
}

// generateCSRForRegistration generates a CSR with a placeholder CN.
// Returns nil on failure (registration proceeds without a CSR).
func (c *Client) generateCSRForRegistration() []byte {
	csr, err := c.certStore.GenerateCSR("pending")
	if err != nil {
		log.Printf("warning: failed to generate CSR for registration: %v", err)
		return nil
	}
	return csr
}

// storeMTLSCerts persists the mTLS client cert and CA cert from a register ack.
func (c *Client) storeMTLSCerts(ack interface {
	GetClientCert() []byte
	GetCaCert() []byte
}) {
	if len(ack.GetClientCert()) == 0 || len(ack.GetCaCert()) == 0 {
		return
	}
	if err := c.certStore.StoreCert(ack.GetClientCert(), ack.GetCaCert()); err != nil {
		log.Printf("warning: failed to store mTLS certs: %v", err)
	} else {
		log.Printf("mTLS certificate stored")
	}
}

// sendHeartbeatHandshake sends a heartbeat as the reconnect handshake and
// waits for the HeartbeatAck.
func (c *Client) sendHeartbeatHandshake(stream pb.AgentService_ConnectClient) error {
	if err := stream.Send(heartbeat.BuildMessage(c.serverID)); err != nil {
		return fmt.Errorf("send heartbeat: %w", err)
	}
	msg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("recv heartbeat ack: %w", err)
	}
	if msg.GetHeartbeatAck() == nil {
		return fmt.Errorf("expected HeartbeatAck, got %T", msg.Payload)
	}
	return nil
}

// startRecvLoop starts a goroutine that receives messages from the stream and
// dispatches them. It returns a channel that receives the first error (or nil
// on clean EOF).
func (c *Client) startRecvLoop(stream pb.AgentService_ConnectClient, sendCh chan<- *pb.AgentMessage) <-chan error {
	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				recvErr <- nil
				return
			}
			if err != nil {
				recvErr <- err
				return
			}
			// File upload chunks must be sequential to avoid race conditions.
			// Other messages can be handled concurrently.
			if _, ok := msg.Payload.(*pb.HubMessage_FileUploadRequest); ok {
				c.handleMessage(msg, sendCh)
			} else {
				go c.handleMessage(msg, sendCh)
			}
		}
	}()
	return recvErr
}

func (c *Client) connectAndStream(ctx context.Context) error {
	conn, err := c.dialHub()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)
	stream, err := client.Connect(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}

	bootstrapRegistered, err := c.registerOrHandshake(stream)
	if err != nil {
		return err
	}
	if bootstrapRegistered {
		return errReconnectWithMTLS
	}

	c.resetBackoff()
	log.Printf("connected to hub at %s", c.hubAddr)

	sendCh := make(chan *pb.AgentMessage, 16)
	defer func() {
		c.tailSessionsMu.Lock()
		for id, stop := range c.tailSessions {
			close(stop)
			delete(c.tailSessions, id)
		}
		c.tailSessionsMu.Unlock()
		c.dropzone.Cleanup()
	}()
	hbStop := make(chan struct{})
	defer close(hbStop)
	go heartbeat.StartTicker(c.serverID, 10*time.Second, sendCh, hbStop)
	go c.startCertRenewalTicker(10*time.Second, sendCh, hbStop)

	recvErr := c.startRecvLoop(stream, sendCh)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErr:
			return fmt.Errorf("receive error: %w", err)
		case msg := <-sendCh:
			if err := stream.Send(msg); err != nil {
				return fmt.Errorf("send: %w", err)
			}
		}
	}
}

func (c *Client) nextBackoff() time.Duration {
	current := c.backoff
	c.backoff *= 2
	if c.backoff > c.maxBackoff {
		c.backoff = c.maxBackoff
	}
	return current
}

func (c *Client) resetBackoff() {
	c.backoff = 1 * time.Second
}

func (c *Client) selfCleanup() {
	log.Printf("starting self-cleanup")

	// Remove agent binary and config
	os.Remove("/usr/local/bin/aerodocs-agent")
	os.RemoveAll("/etc/aerodocs/")
	os.RemoveAll(c.dropzone.Dir())

	// Disable and remove the systemd service using a sanitized environment
	cleanEnv := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmds := [][]string{
		{"systemctl", "disable", "aerodocs-agent"},
		{"systemctl", "stop", "aerodocs-agent"},
		{"systemctl", "daemon-reload"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = cleanEnv
		_ = cmd.Run()
	}
	os.Remove("/etc/systemd/system/aerodocs-agent.service")

	log.Printf("self-cleanup complete")
}

// useTLS returns true unless the insecure flag is explicitly set.
func (c *Client) useTLS() bool {
	return !c.insecure
}

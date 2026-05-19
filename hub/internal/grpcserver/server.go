package grpcserver

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/wyiu/veyport/hub/internal/ca"
	"github.com/wyiu/veyport/hub/internal/connmgr"
	"github.com/wyiu/veyport/hub/internal/notify"
	"github.com/wyiu/veyport/hub/internal/store"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

type Server struct {
	grpcServer  *grpc.Server
	store       *store.Store
	connMgr     *connmgr.ConnManager
	pending     *PendingRequests
	logSessions *LogSessions
	terminals   *TerminalSessions
	hbCoalescer *HeartbeatCoalescer
	addr        string
}

type Config struct {
	Addr                   string
	ExternalHostname       string // public hostname for TLS SAN (extracted from --grpc-external-addr)
	HeartbeatFlushInterval time.Duration
	Store                  *store.Store
	ConnMgr                *connmgr.ConnManager
	Pending                *PendingRequests
	LogSessions            *LogSessions
	TerminalSessions       *TerminalSessions
	CACert                 *x509.Certificate
	CAKey                  *ecdsa.PrivateKey
	Notifier               *notify.Notifier
}

func New(cfg Config) *Server {
	if cfg.Pending == nil {
		cfg.Pending = NewPendingRequests()
	}
	if cfg.LogSessions == nil {
		cfg.LogSessions = NewLogSessions()
	}
	if cfg.TerminalSessions == nil {
		cfg.TerminalSessions = NewTerminalSessions()
	}
	flushInterval := cfg.HeartbeatFlushInterval
	if flushInterval <= 0 {
		flushInterval = 30 * time.Second
	}
	hbCoalescer := NewHeartbeatCoalescer(cfg.Store, flushInterval)
	s := &Server{
		store:       cfg.Store,
		connMgr:     cfg.ConnMgr,
		pending:     cfg.Pending,
		logSessions: cfg.LogSessions,
		terminals:   cfg.TerminalSessions,
		hbCoalescer: hbCoalescer,
		addr:        cfg.Addr,
	}

	var opts []grpc.ServerOption

	// Limit inbound message size to 256KB (default is 4MB) to prevent
	// oversized payloads from consuming excessive memory.
	opts = append(opts, grpc.MaxRecvMsgSize(256*1024))

	// Keepalive: ping clients every 30s to keep long-lived streams alive through
	// reverse proxies (e.g., Traefik's default 60s idle timeout).
	opts = append(opts,
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)

	if cfg.CACert != nil && cfg.CAKey != nil {
		var sanHosts []string
		if cfg.ExternalHostname != "" {
			sanHosts = append(sanHosts, cfg.ExternalHostname)
		}
		if host, _, err := net.SplitHostPort(cfg.Addr); err == nil && host != "" {
			sanHosts = append(sanHosts, host)
		}
		sanHosts = append(sanHosts, "veyport-hub", "localhost")
		serverCert, serverKey, err := ca.GenerateServerCert(cfg.CACert, cfg.CAKey, "veyport-hub", sanHosts...)
		if err != nil {
			log.Fatalf("grpc: generate server TLS cert: %v", err)
		}
		caPool := x509.NewCertPool()
		caPool.AddCert(cfg.CACert)
		tlsCfg := &tls.Config{
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    caPool,
			Certificates: []tls.Certificate{{Certificate: [][]byte{serverCert.Raw, cfg.CACert.Raw}, PrivateKey: serverKey, Leaf: serverCert}},
			MinVersion:   tls.VersionTLS13,
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}

	s.grpcServer = grpc.NewServer(opts...)
	handler := &Handler{
		store:       cfg.Store,
		connMgr:     cfg.ConnMgr,
		pending:     s.pending,
		logSessions: s.logSessions,
		terminals:   s.terminals,
		hbCoalescer: hbCoalescer,
		caCert:      cfg.CACert,
		caKey:       cfg.CAKey,
		notifier:    cfg.Notifier,
	}
	pb.RegisterAgentServiceServer(s.grpcServer, handler)
	return s
}

func (s *Server) Start() error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}
	fmt.Printf("Veyport gRPC server listening on %s\n", s.addr)
	return s.grpcServer.Serve(lis)
}

func (s *Server) Stop() {
	if s.hbCoalescer != nil {
		s.hbCoalescer.FlushAll()
	}
	s.grpcServer.GracefulStop()
}

func (s *Server) ConnMgr() *connmgr.ConnManager {
	return s.connMgr
}

func (s *Server) StartHeartbeatMonitor(stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				s.sweepStaleConnections()
			}
		}
	}()
}

func (s *Server) sweepStaleConnections() {
	stale := s.connMgr.StaleConnections(30 * time.Second)
	for _, id := range stale {
		s.connMgr.Unregister(id)
		if err := s.store.UpdateServerStatus(id, "offline"); err != nil {
			log.Printf("heartbeat monitor: failed to mark %s offline: %v", id, err)
		}
		log.Printf("heartbeat monitor: marked %s offline (stale)", id)
	}
	activeIDs := s.connMgr.ActiveServerIDs()
	orphans, err := s.store.GetOnlineServersNotIn(activeIDs)
	if err != nil {
		log.Printf("heartbeat monitor: failed to query orphan servers: %v", err)
		return
	}
	for _, srv := range orphans {
		if err := s.store.UpdateServerStatus(srv.ID, "offline"); err != nil {
			log.Printf("heartbeat monitor: failed to mark orphan %s offline: %v", srv.ID, err)
		}
		log.Printf("heartbeat monitor: marked %s offline (orphan)", srv.ID)
	}
}

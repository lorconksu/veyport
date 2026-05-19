// Package agentclient provides a public API for creating and running an
// Veyport agent client. It wraps the internal client package so that
// external modules (e.g., integration tests in the hub module) can use it.
package agentclient

import (
	"context"

	"github.com/wyiu/veyport/agent/internal/client"
)

// Config mirrors client.Config for external consumers.
type Config struct {
	HubAddr      string
	ServerID     string
	Token        string
	CertDir      string
	DropzoneDir  string
	Hostname     string
	IPAddress    string
	OS           string
	AgentVersion string
	Insecure     bool
	HubCAPin     string
}

// Client wraps the internal agent client.
type Client struct {
	inner *client.Client
}

// New creates a new agent client with the given configuration.
func New(cfg Config) *Client {
	return &Client{
		inner: client.New(client.Config{
			HubAddr:      cfg.HubAddr,
			ServerID:     cfg.ServerID,
			Token:        cfg.Token,
			CertDir:      cfg.CertDir,
			DropzoneDir:  cfg.DropzoneDir,
			Hostname:     cfg.Hostname,
			IPAddress:    cfg.IPAddress,
			OS:           cfg.OS,
			AgentVersion: cfg.AgentVersion,
			Insecure:     cfg.Insecure,
			HubCAPin:     cfg.HubCAPin,
		}),
	}
}

// Run connects to the hub and streams messages until the context is cancelled.
func (c *Client) Run(ctx context.Context) error {
	return c.inner.Run(ctx)
}

// ServerID returns the server ID assigned after registration.
func (c *Client) ServerID() string {
	return c.inner.ServerID()
}

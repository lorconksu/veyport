// Package applicationtransport defines the HTTP core's narrow transport
// dependency. TLS and user/session authorization remain at the HTTP core.
package applicationtransport

import (
	"context"
	"github.com/wyiu/veyport/proto/applicationproxy"
	"net"
)

type Target = applicationproxy.Target
type Dialer interface {
	DialApplication(context.Context, Target) (net.Conn, error)
	ApplicationAvailability(nodeID string) (supported, online bool)
}
type Validator func(context.Context, Target) error

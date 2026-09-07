package server

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wyiu/veyport/hub/internal/account"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

// defaultSSHGatewayPort mirrors the port in sshconfig.DefaultAddr. It is only
// used when the resolved listen address cannot be parsed, so that the response
// still carries a usable hint instead of a zero port.
const defaultSSHGatewayPort = 2222

const (
	errSSHGatewayDisabled    = "SSH gateway is disabled"
	errSSHGatewayUnavailable = "SSH gateway key material is unavailable"
	errSSHInvalidPublicKey   = "invalid public key"
	errSSHIssueFailed        = "failed to issue certificate"
)

// supportedSSHKeyTypes are the client public key algorithms accepted as the
// subject of a user certificate. Ed25519 is what the CLI generates; ECDSA and
// RSA are accepted for operators reusing an existing key. Legacy DSA
// ("ssh-dss") and certificates are deliberately absent.
var supportedSSHKeyTypes = map[string]bool{
	ssh.KeyAlgoED25519:    true,
	ssh.KeyAlgoECDSA256:   true,
	ssh.KeyAlgoECDSA384:   true,
	ssh.KeyAlgoECDSA521:   true,
	ssh.KeyAlgoRSA:        true,
	ssh.KeyAlgoSKED25519:  true,
	ssh.KeyAlgoSKECDSA256: true,
}

// sshCertificateRequest is the body of POST /api/ssh/certificates. The client
// supplies only a public key: the principal is derived from the authenticated
// identity and can never be requested.
type sshCertificateRequest struct {
	PublicKey string `json:"public_key"`
}

// handleIssueSSHCertificate handles POST /api/ssh/certificates. It signs a
// short-lived user certificate for the caller's own username, which is the sole
// principal — the client cannot ask for another identity (FR-002).
//
// The interactiveOnly middleware, not this handler, is what excludes API-token
// sessions (SC-004); auditNonInteractiveSSHCertAttempt records those refusals.
func (s *Server) handleIssueSSHCertificate(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	// FR-015: while the gateway is disabled, refuse clearly rather than hand
	// out a certificate no listener will ever accept.
	if !s.sshConfig.Enabled {
		s.auditSSHCertRefused(r, userID, "gateway disabled")
		respondError(w, http.StatusServiceUnavailable, errSSHGatewayDisabled)
		return
	}
	// FR-006: unusable key material disables issuance instead of regenerating.
	if s.userCA == nil || s.sshHostKey == nil {
		s.auditSSHCertRefused(r, userID, "gateway key material unavailable")
		respondError(w, http.StatusServiceUnavailable, errSSHGatewayUnavailable)
		return
	}

	var req sshCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	clientPub, err := parseSSHSubjectKey(req.PublicKey)
	if err != nil {
		respondError(w, http.StatusBadRequest, errSSHInvalidPublicKey)
		return
	}

	// Identity comes from the validated token, never from the request body.
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		respondError(w, http.StatusNotFound, errUserNotFound)
		return
	}

	// A disabled or dormant account gets no new certificate: issuance is the
	// one moment the hub can shorten the window in which a still-valid
	// credential outlives the account's usability (008 FR-009).
	if st := s.accountStatus(user); accountRefuses(st) {
		msg, _ := account.Refusal(st)
		s.auditSSHCertRefused(r, userID, accountRefusalDetail(st))
		respondError(w, http.StatusForbidden, msg)
		return
	}

	ttl := time.Duration(s.sshConfig.CertTTLHours) * time.Hour
	cert, err := s.userCA.SignUserCert(clientPub, user.Username, ttl)
	if err != nil {
		log.Printf("ssh: sign user certificate for user %s: %v", userID, err)
		s.auditSSHCertRefused(r, userID, "certificate signing failed")
		respondError(w, http.StatusInternalServerError, errSSHIssueFailed)
		return
	}

	expiresAt := time.Unix(int64(cert.ValidBefore), 0).UTC()

	detail := fmt.Sprintf(`{"principal": %q, "ttl_hours": %d, "expires_at": %q, "serial": %d}`,
		user.Username, s.sshConfig.CertTTLHours, expiresAt.Format(time.RFC3339), cert.Serial)
	ip := clientIP(r)
	resourceType := "ssh"
	s.auditLogRequest(r, model.AuditEntry{
		UserID:       &userID,
		Action:       model.AuditSSHCertIssued,
		Target:       &user.Username,
		Detail:       &detail,
		IPAddress:    &ip,
		Outcome:      model.AuditOutcomeSuccess,
		ActorType:    model.AuditActorTypeUser,
		ResourceType: &resourceType,
	})

	respondJSON(w, http.StatusOK, model.SSHCertificateResponse{
		Certificate:        authorizedKeyLine(cert),
		Principal:          user.Username,
		ExpiresAt:          expiresAt.Format(time.RFC3339),
		HostKeyFingerprint: ssh.FingerprintSHA256(s.sshHostKey.PublicKey()),
		GatewayPort:        s.sshGatewayPort(),
	})
}

// handleSSHHostKey handles GET /api/ssh/host-key. The host identity is public
// trust material, so any authenticated caller (including an API token) may read
// it to pre-pin the gateway (FR-006, FR-013).
func (s *Server) handleSSHHostKey(w http.ResponseWriter, r *http.Request) {
	if s.sshHostKey == nil {
		respondError(w, http.StatusServiceUnavailable, errSSHGatewayUnavailable)
		return
	}

	hostPub := s.sshHostKey.PublicKey()
	respondJSON(w, http.StatusOK, model.SSHHostKeyResponse{
		Fingerprint: ssh.FingerprintSHA256(hostPub),
		PublicKey:   authorizedKeyLine(hostPub),
		Port:        s.sshGatewayPort(),
	})
}

// auditNonInteractiveSSHCertAttempt records ssh.cert_issue_refused when a
// non-interactive credential reaches the issuance endpoint. It deliberately
// does not block: the interactiveOnly middleware it wraps is the single place
// that enforces the rule (SC-004), so the refusal cannot drift between the two.
func (s *Server) auditNonInteractiveSSHCertAttempt(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if TokenTypeFromContext(r.Context()) != auth.TokenTypeAccess {
			s.auditSSHCertRefused(r, UserIDFromContext(r.Context()), "non-interactive session")
		}
		next.ServeHTTP(w, r)
	})
}

// auditSSHCertRefused writes a single ssh.cert_issue_refused entry.
func (s *Server) auditSSHCertRefused(r *http.Request, userID, reason string) {
	detail := fmt.Sprintf(`{"reason": %q}`, reason)
	ip := clientIP(r)
	resourceType := "ssh"

	entry := model.AuditEntry{
		Action:       model.AuditSSHCertIssueRefused,
		Detail:       &detail,
		IPAddress:    &ip,
		Outcome:      model.AuditOutcomeFailure,
		ActorType:    model.AuditActorTypeUser,
		ResourceType: &resourceType,
	}
	if userID != "" {
		entry.UserID = &userID
	} else {
		entry.ActorType = model.AuditActorTypeAnonymous
	}

	s.auditLogRequest(r, entry)
}

// sshGatewayPort returns the numeric port clients should connect to, taken from
// the resolved gateway listen address.
func (s *Server) sshGatewayPort() int {
	_, portStr, err := net.SplitHostPort(s.sshConfig.Addr)
	if err != nil {
		return defaultSSHGatewayPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return defaultSSHGatewayPort
	}
	return port
}

// parseSSHSubjectKey parses an authorized_keys line into the public key that
// will become the certificate's subject. An existing certificate is refused:
// re-signing one would let a caller chain principals it was never granted.
func parseSSHSubjectKey(line string) (ssh.PublicKey, error) {
	if strings.TrimSpace(line) == "" {
		return nil, errors.New("public key is empty")
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		return nil, errors.New("a certificate is not a valid subject key")
	}
	if !supportedSSHKeyTypes[pub.Type()] {
		return nil, fmt.Errorf("unsupported public key type %q", pub.Type())
	}
	return pub, nil
}

// authorizedKeyLine renders pub as a single authorized_keys line without the
// trailing newline ssh.MarshalAuthorizedKey appends.
func authorizedKeyLine(pub ssh.PublicKey) string {
	return strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\r\n")
}

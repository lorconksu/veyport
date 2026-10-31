// native-candidate is an external protocol client. It never starts Hub code or
// imports Hub internals; the coordinator supplies the running candidate bytes.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type config struct {
	BaseURL        string `json:"hub_base_url"`
	GRPCAddr       string `json:"grpc_addr"`
	GRPCServerName string `json:"grpc_server_name"`
	SSHAddr        string `json:"ssh_addr"`
	CertDir        string `json:"cert_dir"`
	AdminToken     string `json:"admin_token"`
	ViewerToken    string `json:"viewer_token"`
	AdminName      string `json:"admin_name"`
	ViewerName     string `json:"viewer_name"`
	ViewerID       string `json:"viewer_id"`
	OperatorToken  string `json:"operator_token"`
	OperatorName   string `json:"operator_name"`
	OperatorID     string `json:"operator_id"`
	ServerName     string `json:"server_name"`
}

type outcome struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Diagnostic string `json:"diagnostic,omitempty"`
}

type probe struct {
	config
	http           *http.Client
	results        []outcome
	adminSigner    ssh.Signer
	viewerSigner   ssh.Signer
	operatorSigner ssh.Signer
	hostKey        ssh.PublicKey
	clientTLS      *tls.Config
}

func (p *probe) check(id string, test func() error) {
	result := outcome{ID: id, Status: "pass"}
	if err := test(); err != nil {
		// This file stays private. The coordinator strips diagnostics before its
		// signed disclosure-safe receipt. No command transcripts are recorded.
		result.Status = "fail"
		result.Diagnostic = err.Error()
	}
	p.results = append(p.results, result)
}

func (p *probe) api(method, path, token string, body any, target any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, p.BaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	if target != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(target)
	}
	return nil
}

func (p *probe) issue(token string) (ssh.Signer, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	var result struct {
		Certificate string `json:"certificate"`
	}
	if err := p.api("POST", "/api/ssh/certificates", token, map[string]string{"public_key": string(ssh.MarshalAuthorizedKey(signer.PublicKey()))}, &result); err != nil {
		return nil, err
	}
	public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(result.Certificate))
	if err != nil {
		return nil, err
	}
	cert, ok := public.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("certificate required")
	}
	return ssh.NewCertSigner(cert, signer)
}

func (p *probe) dial(username string, signer ssh.Signer) (*ssh.Client, error) {
	if p.hostKey == nil || signer == nil {
		return nil, errors.New("missing SSH trust")
	}
	connection, err := net.DialTimeout("tcp", p.SSHAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
	client, channels, requests, err := ssh.NewClientConn(connection, p.SSHAddr, &ssh.ClientConfig{
		User: username + "+" + p.ServerName, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(p.hostKey), Timeout: 5 * time.Second,
	})
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	return ssh.NewClient(client, channels, requests), nil
}

func (p *probe) run(username string, signer ssh.Signer, command string, input []byte) ([]byte, []byte, int, error) {
	client, err := p.dial(username, signer)
	if err != nil {
		return nil, nil, 0, err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return nil, nil, 0, err
	}
	defer session.Close()
	var stdout, stderr bytes.Buffer
	session.Stdin, session.Stdout, session.Stderr = bytes.NewReader(input), &stdout, &stderr
	err = session.Run(command)
	code := 0
	if err != nil {
		var exit *ssh.ExitError
		if !errors.As(err, &exit) {
			return stdout.Bytes(), stderr.Bytes(), 0, err
		}
		code = exit.ExitStatus()
	}
	return stdout.Bytes(), stderr.Bytes(), code, nil
}

func (p *probe) execute(tlsConfig *tls.Config) error {
	return p.executeMessage(tlsConfig, &pb.ExecutionAgentMessage{})
}

func (p *probe) executeMessage(tlsConfig *tls.Config, message *pb.ExecutionAgentMessage) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	connection, err := grpc.NewClient(p.GRPCAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}
	defer connection.Close()
	stream, err := pb.NewAgentServiceClient(connection).Execute(ctx)
	if err != nil {
		return err
	}
	_ = stream.Send(message)
	_, err = stream.Recv()
	return err
}

func (p *probe) grpcCases() {
	p.check("grpc.oversized-message-rejected", func() error {
		message := &pb.ExecutionAgentMessage{Payload: &pb.ExecutionAgentMessage_Stdout{Stdout: &pb.ExecutionData{Data: make([]byte, 1<<20)}}}
		if status.Code(p.executeMessage(p.clientTLS, message)) != codes.ResourceExhausted {
			return errors.New("oversized protected message not rejected at transport bound")
		}
		return nil
	})
	p.check("grpc.enrolled-identity-reaches-protected-handler", func() error {
		if status.Code(p.execute(p.clientTLS)) != codes.InvalidArgument {
			return errors.New("enrolled identity did not reach attachment validation")
		}
		return nil
	})
	p.check("grpc.missing-client-certificate-rejected", func() error {
		config := p.clientTLS.Clone()
		config.Certificates = nil
		if status.Code(p.execute(config)) != codes.Unauthenticated {
			return errors.New("missing identity was not rejected")
		}
		return nil
	})
	p.check("grpc.enrollment-listener-reachable-without-client-certificate", func() error {
		config := p.clientTLS.Clone()
		config.Certificates = nil
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		connection, err := grpc.NewClient(p.GRPCAddr, grpc.WithTransportCredentials(credentials.NewTLS(config)))
		if err != nil {
			return err
		}
		defer connection.Close()
		stream, err := pb.NewAgentServiceClient(connection).Connect(ctx)
		if err != nil {
			return err
		}
		if err = stream.Send(&pb.AgentMessage{Payload: &pb.AgentMessage_Register{Register: &pb.RegisterAgent{Token: "invalid-disposable-token"}}}); err != nil {
			return err
		}
		message, err := stream.Recv()
		if err != nil || message.GetRegisterAck() == nil || message.GetRegisterAck().Success {
			return errors.New("enrollment must give explicit registration refusal")
		}
		return nil
	})
	p.check("grpc.foreign-client-certificate-rejected", func() error {
		if status.Code(p.execute(p.clientTLS)) != codes.InvalidArgument {
			return errors.New("foreign-certificate positive control failed")
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "foreign-node"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		if err != nil {
			return err
		}
		config := p.clientTLS.Clone()
		config.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}
		var credentialSent atomic.Bool
		// Force this explicit foreign credential onto the wire; otherwise TLS
		// may omit it after the server advertises a different acceptable CA.
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			credentialSent.Store(true)
			return &config.Certificates[0], nil
		}
		err = p.execute(config)
		if status.Code(err) != codes.Unavailable || !credentialSent.Load() {
			return fmt.Errorf("foreign credential RPC refusal not demonstrated: status=%s credential_sent=%t", status.Code(err), credentialSent.Load())
		}
		if status.Code(p.execute(p.clientTLS)) != codes.InvalidArgument {
			return errors.New("foreign-certificate recovery positive control failed")
		}
		return nil
	})
}

func (p *probe) sshCases() {
	p.check("ssh.certificates-issued-to-mfa-sessions", func() error {
		var err error
		p.adminSigner, err = p.issue(p.AdminToken)
		if err != nil {
			return err
		}
		p.viewerSigner, err = p.issue(p.ViewerToken)
		if err != nil {
			return err
		}
		p.operatorSigner, err = p.issue(p.OperatorToken)
		return err
	})
	p.check("ssh.stdin-stdout-stderr-exit-status", func() error {
		out, errout, code, err := p.run(p.AdminName, p.adminSigner, "cat; printf done; printf 'ssdf-stderr' >&2; exit 7", []byte{0, 1, 255})
		if err != nil || code != 7 || !bytes.Equal(out, []byte{0, 1, 255, 'd', 'o', 'n', 'e'}) || string(errout) != "ssdf-stderr" {
			return fmt.Errorf("execution result mismatch: error=%v exit=%d stdout=%x stderr=%s", err, code, out, errout)
		}
		return nil
	})
	p.check("ssh.execution-user-enforced", func() error {
		out, _, code, err := p.run(p.AdminName, p.adminSigner, "id -u", nil)
		if err != nil || code != 0 || string(out) != "0\n" {
			return errors.New("disposable node execution identity mismatch")
		}
		return nil
	})
	p.check("ssh.client-cancellation-terminates-work", func() error {
		client, err := p.dial(p.AdminName, p.adminSigner)
		if err != nil {
			return err
		}
		session, err := client.NewSession()
		if err != nil {
			client.Close()
			return err
		}
		stdout, err := session.StdoutPipe()
		if err != nil {
			session.Close()
			client.Close()
			return err
		}
		if err = session.Start("printf ready; sleep 3; touch /tmp/ssdf-cancel-marker"); err != nil {
			session.Close()
			client.Close()
			return err
		}
		ready := make([]byte, 5)
		_, err = io.ReadFull(stdout, ready)
		_ = session.Close()
		_ = client.Close()
		if err != nil || string(ready) != "ready" {
			return errors.New("cancellation positive control did not start")
		}
		_, _, code, err := p.run(p.AdminName, p.adminSigner, "sleep 4; test ! -e /tmp/ssdf-cancel-marker", nil)
		if err != nil || code != 0 {
			return errors.New("cancelled command reached delayed marker")
		}
		return nil
	})
	p.check("ssh.principal-substitution-rejected", func() error {
		client, err := p.dial(p.ViewerName, p.adminSigner)
		if client != nil {
			_ = client.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
			return errors.New("principal refusal not demonstrated")
		}
		return nil
	})
	p.check("ssh.foreign-ca-certificate-rejected", func() error {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		subject, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return err
		}
		_, authorityKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		authority, err := ssh.NewSignerFromKey(authorityKey)
		if err != nil {
			return err
		}
		cert := &ssh.Certificate{Key: subject.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{p.AdminName}, ValidAfter: uint64(time.Now().Add(-time.Hour).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix())}
		if err = cert.SignCert(rand.Reader, authority); err != nil {
			return err
		}
		signer, err := ssh.NewCertSigner(cert, subject)
		if err != nil {
			return err
		}
		client, err := p.dial(p.AdminName, signer)
		if client != nil {
			_ = client.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
			return errors.New("foreign authority refusal not demonstrated")
		}
		return nil
	})
	p.check("ssh.viewer-node-execution-denied", func() error {
		// Prove its certificate authenticates before testing command authorization.
		client, err := p.dial(p.ViewerName, p.viewerSigner)
		if err != nil {
			return err
		}
		_ = client.Close()
		out, _, code, err := p.run(p.ViewerName, p.viewerSigner, "printf unauthorized-execution", nil)
		if err != nil || code == 0 || bytes.Contains(out, []byte("unauthorized-execution")) {
			return errors.New("unauthorized command not explicitly denied")
		}
		return nil
	})
	p.check("ssh.forwarding-and-subsystems-denied", func() error {
		client, err := p.dial(p.AdminName, p.adminSigner)
		if err != nil {
			return err
		}
		defer client.Close()
		channel, _, err := client.OpenChannel("direct-tcpip", ssh.Marshal(struct {
			Host       string
			Port       uint32
			Origin     string
			OriginPort uint32
		}{"127.0.0.1", 1, "127.0.0.1", 1}))
		if channel != nil {
			_ = channel.Close()
		}
		if err == nil {
			return errors.New("forwarding accepted")
		}
		session, err := client.NewSession()
		if err != nil {
			return err
		}
		defer session.Close()
		if session.RequestSubsystem("sftp") == nil {
			return errors.New("subsystem accepted")
		}
		return nil
	})
	p.check("ssh.disabled-account-execution-denied", func() error {
		// Establish the same certificate's execution authority before revocation.
		out, _, code, err := p.run(p.OperatorName, p.operatorSigner, "printf previously-authorized", nil)
		if err != nil || code != 0 || string(out) != "previously-authorized" {
			return errors.New("revocation positive control failed")
		}
		if err := p.api("PUT", "/api/users/"+p.OperatorID+"/status", p.AdminToken, map[string]bool{"disabled": true}, nil); err != nil {
			return err
		}
		out, _, code, err = p.run(p.OperatorName, p.operatorSigner, "printf revoked-command-executed", nil)
		if bytes.Contains(out, []byte("revoked-command-executed")) || (err == nil && code == 0) {
			return errors.New("disabled account executed command")
		}
		if err != nil && !strings.Contains(err.Error(), "unable to authenticate") {
			return err
		}
		return nil
	})
	p.check("ssh.standard-audit-records-present", func() error {
		for _, action := range []string{"execution.dispatched", "execution.finished", "ssh.session_refused"} {
			var response struct {
				Entries []json.RawMessage `json:"entries"`
			}
			if err := p.api("GET", "/api/audit-logs?action="+action, p.AdminToken, nil, &response); err != nil {
				return err
			}
			if len(response.Entries) == 0 {
				return errors.New("missing audit action")
			}
		}
		return nil
	})
}

func run(path, phase string) ([]outcome, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config config
	if err = json.Unmarshal(raw, &config); err != nil {
		return nil, err
	}
	p := &probe{config: config, http: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }}}
	var host struct {
		PublicKey string `json:"public_key"`
	}
	if err = p.api("GET", "/api/ssh/host-key", p.AdminToken, nil, &host); err != nil {
		return nil, err
	}
	p.hostKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(host.PublicKey))
	if err != nil {
		return nil, err
	}
	root, err := os.ReadFile(filepath.Join(p.CertDir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) {
		return nil, errors.New("CA required")
	}
	identity, err := tls.LoadX509KeyPair(filepath.Join(p.CertDir, "client.crt"), filepath.Join(p.CertDir, "client.key"))
	if err != nil {
		return nil, err
	}
	p.clientTLS = &tls.Config{RootCAs: pool, ServerName: p.GRPCServerName, Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS13}
	// Parse the original CA to prevent accepting a malformed trust bundle.
	block, _ := pem.Decode(root)
	if block == nil {
		return nil, errors.New("CA PEM required")
	}
	if _, err = x509.ParseCertificate(block.Bytes); err != nil {
		return nil, err
	}
	switch phase {
	case "protocols":
		p.grpcCases()
		p.sshCases()
	case "audit-outage", "audit-recovery":
		p.adminSigner, err = p.issue(p.AdminToken)
		if err != nil {
			return nil, err
		}
		if phase == "audit-outage" {
			p.check("ssh.required-audit-failure-denies-execution", func() error {
				_, _, code, err := p.run(p.AdminName, p.adminSigner, "touch /tmp/ssdf-audit-denied-marker", nil)
				if err != nil || code == 0 {
					return errors.New("required audit refusal not demonstrated")
				}
				return nil
			})
		} else {
			p.check("ssh.audit-recovery-verifies-denied-command-never-ran", func() error {
				out, errout, code, err := p.run(p.AdminName, p.adminSigner, "test ! -e /tmp/ssdf-audit-denied-marker && printf recovered", nil)
				if err != nil || code != 0 || string(out) != "recovered" {
					return fmt.Errorf("audit recovery or marker absence failed: error=%v exit=%d stdout=%x stderr=%s", err, code, out, errout)
				}
				return nil
			})
		}
	default:
		return nil, errors.New("unknown phase")
	}
	return p.results, nil
}

func main() {
	config := flag.String("config", "", "private configuration")
	output := flag.String("output", "", "private output")
	phase := flag.String("phase", "protocols", "protocols, audit-outage or audit-recovery")
	flag.Parse()
	results, err := run(*config, *phase)
	if err != nil {
		results = append(results, outcome{ID: "probe.initialization", Status: "fail"})
	}
	raw, encodeErr := json.MarshalIndent(results, "", "  ")
	if encodeErr != nil || os.WriteFile(*output, raw, 0600) != nil {
		os.Exit(1)
	}
	for _, r := range results {
		if r.Status != "pass" {
			os.Exit(1)
		}
	}
}

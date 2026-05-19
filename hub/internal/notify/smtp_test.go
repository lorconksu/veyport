package notify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

const (
	testSMTPEHLOReply     = "250-localhost\r\n250 OK\r\n"
	testSMTPGreeting      = "220 localhost ESMTP\r\n"
	testSMTPMailFrom      = "MAIL FROM"
	testSMTPOK            = "250 OK\r\n"
	testSMTPRcptTo        = "RCPT TO"
	testSMTPSendData      = "354 Send data\r\n"
	testSMTPDataEnd       = "\r\n.\r\n"
	testSMTPBye           = "221 Bye\r\n"
	testRecipient         = "to@example.com"
	testListenAddr        = "127.0.0.1:0"
	testMockServerFmt     = "failed to start mock server: %v"
	testLocalhost         = "127.0.0.1"
	testSenderEmail       = "sender@example.com"
	testRecipientEmail    = "recipient@example.com"
	testFromEmail         = "test@test.com"
	testServerNameWeb01   = "web-01"
	testTimestamp20260330 = "2026-03-30 12:00:00 UTC"
)

// mockSMTPServer handles a minimal SMTP conversation on ln,
// then sends all received data to the received channel.
func mockSMTPServer(t *testing.T, ln net.Listener, received chan<- string) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	fmt.Fprintf(conn, testSMTPGreeting)
	buf := make([]byte, 4096)
	var allData string
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		data := string(buf[:n])
		allData += data
		if strings.HasPrefix(data, "EHLO") || strings.HasPrefix(data, "HELO") {
			fmt.Fprintf(conn, testSMTPEHLOReply)
		} else if strings.HasPrefix(data, testSMTPMailFrom) {
			fmt.Fprintf(conn, testSMTPOK)
		} else if strings.HasPrefix(data, testSMTPRcptTo) {
			fmt.Fprintf(conn, testSMTPOK)
		} else if strings.HasPrefix(data, "DATA") {
			fmt.Fprintf(conn, testSMTPSendData)
		} else if strings.Contains(data, testSMTPDataEnd) {
			fmt.Fprintf(conn, testSMTPOK)
		} else if strings.HasPrefix(data, "QUIT") {
			fmt.Fprintf(conn, testSMTPBye)
			break
		}
	}
	received <- allData
}

func TestSendEmail_Disabled(t *testing.T) {
	cfg := model.SMTPConfig{
		Host:    "localhost",
		Port:    25,
		Enabled: false,
	}
	err := SendEmail(cfg, testRecipient, "Subject", "Body")
	if err != nil {
		t.Errorf("expected nil error when disabled, got: %v", err)
	}
}

func TestSendEmail_PlainSMTP(t *testing.T) {
	ln, err := net.Listen("tcp", testListenAddr)
	if err != nil {
		t.Fatalf(testMockServerFmt, err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go mockSMTPServer(t, ln, received)

	addr := ln.Addr().(*net.TCPAddr)
	cfg := model.SMTPConfig{
		Host:    testLocalhost,
		Port:    addr.Port,
		From:    testSenderEmail,
		Enabled: true,
		TLS:     false,
	}

	err = SendEmail(cfg, testRecipientEmail, "[Veyport] Test Subject", "Hello from Veyport.")
	if err != nil {
		t.Fatalf("SendEmail returned error: %v", err)
	}

	select {
	case data := <-received:
		if !strings.Contains(data, testSMTPMailFrom) {
			t.Errorf("expected MAIL FROM in SMTP exchange, got: %q", data)
		}
		if !strings.Contains(data, testSMTPRcptTo) {
			t.Errorf("expected RCPT TO in SMTP exchange, got: %q", data)
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for mock SMTP server to receive data")
	}
}

func TestSendEmail_MessageContents(t *testing.T) {
	ln, err := net.Listen("tcp", testListenAddr)
	if err != nil {
		t.Fatalf(testMockServerFmt, err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go mockSMTPServer(t, ln, received)

	addr := ln.Addr().(*net.TCPAddr)
	cfg := model.SMTPConfig{
		Host:    testLocalhost,
		Port:    addr.Port,
		From:    "noreply@veyport.local",
		Enabled: true,
		TLS:     false,
	}

	subject, body := RenderEmail(model.NotifyAgentOffline, map[string]string{
		"server_name": "test-server",
	})

	err = SendEmail(cfg, "admin@example.com", subject, body)
	if err != nil {
		t.Fatalf("SendEmail returned error: %v", err)
	}

	select {
	case data := <-received:
		if !strings.Contains(data, "test-server") {
			t.Errorf("expected message to contain 'test-server', got: %q", data)
		}
		if !strings.Contains(data, "[Veyport]") {
			t.Errorf("expected message to contain '[Veyport]', got: %q", data)
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for mock SMTP server to receive data")
	}
}

func TestBuildMessage(t *testing.T) {
	msg := buildMessage("from@example.com", testRecipient, "Test Subject", "Test body content.")

	if !strings.Contains(msg, "From: from@example.com") {
		t.Errorf("missing From header in message: %q", msg)
	}
	if !strings.Contains(msg, "To: to@example.com") {
		t.Errorf("missing To header in message: %q", msg)
	}
	if !strings.Contains(msg, "Subject: Test Subject") {
		t.Errorf("missing Subject header in message: %q", msg)
	}
	if !strings.Contains(msg, "MIME-Version: 1.0") {
		t.Errorf("missing MIME-Version header in message: %q", msg)
	}
	if !strings.Contains(msg, "Content-Type: text/plain") {
		t.Errorf("missing Content-Type header in message: %q", msg)
	}
	if !strings.Contains(msg, "Test body content.") {
		t.Errorf("missing body content in message: %q", msg)
	}
}

// generateSelfSignedCert generates an in-memory self-signed TLS certificate for testing.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: testLocalhost},
		IPAddresses:  []net.IP{net.ParseIP(testLocalhost)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	return cert
}

// TestSendEmail_WithAuth verifies that PlainAuth credentials are used when username and password are set.
func TestSendEmail_WithAuth(t *testing.T) {
	ln, err := net.Listen("tcp", testListenAddr)
	if err != nil {
		t.Fatalf(testMockServerFmt, err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	// Mock server that handles AUTH LOGIN/PLAIN exchange
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			received <- ""
			return
		}
		defer conn.Close()
		fmt.Fprintf(conn, testSMTPGreeting)
		buf := make([]byte, 4096)
		var allData string
		for {
			n, connErr := conn.Read(buf)
			if connErr != nil {
				break
			}
			data := string(buf[:n])
			allData += data
			switch {
			case strings.HasPrefix(data, "EHLO") || strings.HasPrefix(data, "HELO"):
				fmt.Fprintf(conn, "250-localhost\r\n250 AUTH PLAIN LOGIN\r\n")
			case strings.HasPrefix(data, "AUTH"):
				fmt.Fprintf(conn, "235 Authentication successful\r\n")
			case strings.HasPrefix(data, testSMTPMailFrom):
				fmt.Fprintf(conn, testSMTPOK)
			case strings.HasPrefix(data, testSMTPRcptTo):
				fmt.Fprintf(conn, testSMTPOK)
			case strings.HasPrefix(data, "DATA"):
				fmt.Fprintf(conn, testSMTPSendData)
			case strings.Contains(data, testSMTPDataEnd):
				fmt.Fprintf(conn, testSMTPOK)
			case strings.HasPrefix(data, "QUIT"):
				fmt.Fprintf(conn, testSMTPBye)
				received <- allData
				return
			}
		}
		received <- allData
	}()

	addr := ln.Addr().(*net.TCPAddr)
	cfg := model.SMTPConfig{
		Host:     testLocalhost,
		Port:     addr.Port,
		Username: "user@example.com",
		Password: "secretpass",
		From:     testSenderEmail,
		Enabled:  true,
		TLS:      false,
	}

	err = SendEmail(cfg, testRecipientEmail, "Auth Test", "Testing auth path.")
	if err != nil {
		t.Fatalf("SendEmail with auth returned error: %v", err)
	}

	select {
	case data := <-received:
		if !strings.Contains(data, "AUTH") {
			t.Errorf("expected AUTH in SMTP exchange, got: %q", data)
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for mock SMTP server")
	}
}

// TestSendEmail_TLS_DialError verifies that sendTLS returns a wrapped error when the TLS dial fails.
func TestSendEmail_TLS_DialError(t *testing.T) {
	cfg := model.SMTPConfig{
		Host:    testLocalhost,
		Port:    19998, // nothing listening here
		From:    testSenderEmail,
		Enabled: true,
		TLS:     true,
	}
	err := SendEmail(cfg, testRecipient, "Test Subject", "Test body.")
	if err == nil {
		t.Fatal("expected error when TLS dial fails, got nil")
	}
	if !strings.Contains(err.Error(), "smtp tls dial") {
		t.Errorf("expected 'smtp tls dial' in error, got: %v", err)
	}
}

// smtpResponse returns the SMTP response for a given client command line.
func smtpResponse(data string) (response string, quit bool) {
	switch {
	case strings.HasPrefix(data, "EHLO"), strings.HasPrefix(data, "HELO"):
		return testSMTPEHLOReply, false
	case strings.HasPrefix(data, testSMTPMailFrom):
		return testSMTPOK, false
	case strings.HasPrefix(data, testSMTPRcptTo):
		return testSMTPOK, false
	case strings.HasPrefix(data, "DATA"):
		return testSMTPSendData, false
	case strings.Contains(data, testSMTPDataEnd):
		return testSMTPOK, false
	case strings.HasPrefix(data, "QUIT"):
		return testSMTPBye, true
	default:
		return "", false
	}
}

// runMockSMTPServer accepts one TLS connection and runs a minimal SMTP conversation,
// sending the accumulated data on the received channel when done.
func runMockSMTPServer(ln net.Listener, cert tls.Certificate, received chan<- string) {
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	conn, err := tlsLn.Accept()
	if err != nil {
		received <- ""
		return
	}
	defer conn.Close()
	fmt.Fprintf(conn, testSMTPGreeting)
	buf := make([]byte, 4096)
	var allData string
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		data := string(buf[:n])
		allData += data
		resp, quit := smtpResponse(data)
		if resp != "" {
			fmt.Fprint(conn, resp)
		}
		if quit {
			break
		}
	}
	received <- allData
}

// TestSendEmail_TLS_Success verifies that sendTLS successfully sends a message over TLS.
// It starts a mock TLS SMTP server with a self-signed certificate and uses InsecureSkipVerify.
func TestSendEmail_TLS_Success(t *testing.T) {
	cert := generateSelfSignedCert(t)

	ln, err := net.Listen("tcp", testListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go runMockSMTPServer(ln, cert, received)

	addr := ln.Addr().(*net.TCPAddr)

	// Use InsecureSkipVerify to connect to the self-signed cert server.
	// We override the package-level tlsDialer to inject test settings.
	origDialer := tlsDialer
	tlsDialer = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		cfg = cfg.Clone()
		cfg.InsecureSkipVerify = true //nolint:gosec // test only — self-signed cert
		return tls.Dial(network, addr, cfg)
	}
	defer func() { tlsDialer = origDialer }()

	smtpCfg := model.SMTPConfig{
		Host:    testLocalhost,
		Port:    addr.Port,
		From:    testSenderEmail,
		Enabled: true,
		TLS:     true,
	}

	if err := SendEmail(smtpCfg, testRecipientEmail, "TLS Test", "Hello over TLS."); err != nil {
		t.Fatalf("SendEmail with TLS returned error: %v", err)
	}

	select {
	case data := <-received:
		if !strings.Contains(data, testSMTPMailFrom) {
			t.Errorf("expected MAIL FROM in TLS SMTP exchange, got: %q", data)
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for TLS SMTP server to receive data")
	}
}

func TestStripCRLF_Header(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"clean string", "hello@example.com", "hello@example.com"},
		{"CRLF injection", "victim@example.com\r\nBcc: attacker@evil.com", "victim@example.comBcc: attacker@evil.com"},
		{"LF only", "test\nBcc: bad", "testBcc: bad"},
		{"CR only", "test\rBcc: bad", "testBcc: bad"},
		{"multiple CRLF", "a\r\nb\r\nc", "abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripCRLF(tt.input)
			if result != tt.expected {
				t.Errorf("stripCRLF(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBuildMessage_CRLFInjection(t *testing.T) {
	msg := buildMessage(
		"noreply@example.com\r\nBcc: spy@evil.com",
		"victim@example.com",
		"Normal Subject\r\nBcc: spy2@evil.com",
		"body",
	)
	// The injected Bcc headers must NOT appear as separate header lines
	lines := strings.Split(msg, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Errorf("CRLF injection succeeded — found injected header: %q", line)
		}
	}
}

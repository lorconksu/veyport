package notify

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

func TestBuildMessageRecipientCannotInjectContent(t *testing.T) {
	recipient := "victim@example.test\r\nBcc: attacker@example.test\r\n\r\nhttps://attacker.invalid"
	message, err := mail.ReadMessage(strings.NewReader(buildMessage(testSenderEmail, recipient, "Fixed subject", "Fixed body")))
	if err != nil {
		t.Fatal(err)
	}
	if message.Header.Get("Bcc") != "" || message.Header.Get("Subject") != "Fixed subject" {
		t.Fatalf("recipient injected a header: %#v", message.Header)
	}
	body, err := io.ReadAll(message.Body)
	if err != nil || string(body) != "Fixed body" {
		t.Fatalf("recipient changed body: %q, %v", body, err)
	}
}

func TestSendEmailRejectsRecipientCRLF(t *testing.T) {
	recipient := "victim@example.test\r\nRCPT TO:<attacker@example.test>"
	cfg := model.SMTPConfig{Enabled: true, Host: testLocalhost, Port: 1, From: testSenderEmail}
	// SendMail validates the envelope before dialing, so no server is needed.
	if err := SendEmail(cfg, recipient, "Fixed subject", "Fixed body"); err == nil || !strings.Contains(err.Error(), "CR or LF") {
		t.Fatalf("plain SMTP did not reject recipient: %v", err)
	}

	cert := generateSelfSignedCert(t)
	root, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	originalDialer := tlsDialer
	tlsDialer = func(network, addr string, config *tls.Config) (*tls.Conn, error) {
		config = config.Clone()
		config.RootCAs = pool
		return tls.Dial(network, addr, config)
	}
	t.Cleanup(func() { tlsDialer = originalDialer })
	listener, err := tls.Listen("tcp", testListenAddr, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	commands := make(chan string, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			commands <- ""
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(conn, testSMTPGreeting)
		var received strings.Builder
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			line := scanner.Text()
			received.WriteString(line + "\n")
			fmt.Fprint(conn, testSMTPOK)
		}
		commands <- received.String()
	}()
	cfg.TLS = true
	cfg.Port = listener.Addr().(*net.TCPAddr).Port
	if err := SendEmail(cfg, recipient, "Fixed subject", "Fixed body"); err == nil || !strings.Contains(err.Error(), "CR or LF") {
		t.Fatalf("TLS SMTP did not reject recipient: %v", err)
	}
	select {
	case received := <-commands:
		if !strings.Contains(received, "MAIL FROM:") || strings.Contains(received, "RCPT TO:") || strings.Contains(received, "DATA") {
			t.Fatalf("unexpected TLS SMTP commands: %q", received)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("timed out waiting for local TLS SMTP capture")
	}
}

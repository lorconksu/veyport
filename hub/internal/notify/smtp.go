package notify

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/wyiu/veyport/hub/internal/model"
)

// SendEmail sends a plain-text email using the provided SMTP configuration.
// Returns nil immediately if cfg.Enabled is false.
func SendEmail(cfg model.SMTPConfig, to, subject, body string) error {
	if !cfg.Enabled {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	msg := buildMessage(cfg.From, to, subject, body)

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	if cfg.TLS {
		return sendTLS(cfg, addr, auth, to, msg)
	}
	return smtp.SendMail(addr, auth, cfg.From, []string{to}, []byte(msg)) // NOSONAR — cleartext SMTP is an intentional config option; STARTTLS is used when TLS=true
}

// sendTLS connects using tlsDialer and sends the message over an encrypted connection.
func sendTLS(cfg model.SMTPConfig, addr string, auth smtp.Auth, to, msg string) error {
	tlsCfg := &tls.Config{
		ServerName: cfg.Host,
		MinVersion: tls.VersionTLS12,
	}

	conn, err := tlsDialer("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("smtp tls dial: %w", err)
	}

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer client.Close()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := fmt.Fprint(wc, msg); err != nil {
		return fmt.Errorf("smtp write data: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp close data writer: %w", err)
	}

	return client.Quit()
}

// tlsDialer is used for TLS connections; wraps tls.Dial to allow test injection.
var tlsDialer = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
	return tls.Dial(network, addr, cfg)
}

// buildMessage constructs a minimal RFC 2822 email message.
func buildMessage(from, to, subject, body string) string {
	var sb strings.Builder
	sb.WriteString("From: " + stripCRLF(from) + "\r\n")
	sb.WriteString("To: " + stripCRLF(to) + "\r\n")
	sb.WriteString("Subject: " + stripCRLF(subject) + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}

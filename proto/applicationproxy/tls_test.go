package applicationproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"
)

func TestConnSupportsPrivateCATLSWithVerifiedHostnameAndDeadlines(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "backend.test"}, DNSNames: []string{"backend.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	for _, hostname := range []string{"backend.test", "wrong.test"} {
		t.Run(hostname, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var hub, agent *Conn
			hub = NewConn(ctx, func(f Frame) error { return agent.Deliver(f) }, cancel)
			agent = NewConn(ctx, func(f Frame) error { return hub.Deliver(f) }, cancel)
			defer hub.Close()
			defer agent.Close()
			hub.SetDeadline(time.Now().Add(time.Second))
			agent.SetDeadline(time.Now().Add(time.Second))
			server := tls.Server(agent, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
			client := tls.Client(hub, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: hostname})
			serverDone := make(chan error, 1)
			go func() {
				err := server.Handshake()
				if err == nil {
					var value [4]byte
					_, err = io.ReadFull(server, value[:])
					if err == nil {
						_, err = server.Write(value[:])
					}
				}
				serverDone <- err
			}()
			err := client.Handshake()
			if hostname == "wrong.test" {
				if err == nil {
					t.Fatal("wrong backend hostname accepted")
				}
				cancel()
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			hub.SetDeadline(time.Time{})
			agent.SetDeadline(time.Time{})
			if _, err := client.Write([]byte("test")); err != nil {
				t.Fatal(err)
			}
			var reply [4]byte
			if _, err := io.ReadFull(client, reply[:]); err != nil || string(reply[:]) != "test" {
				t.Fatalf("TLS data changed: %q %v", reply, err)
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
			if hub.LocalAddr().Network() != "application" || hub.RemoteAddr().String() == "" {
				t.Fatal("tunnel addresses missing")
			}
			cancel()
			select {
			case <-hub.Done():
			case <-time.After(time.Second):
				t.Fatal("TLS context did not close adapter")
			}
			select {
			case <-hub.SenderDone():
			case <-time.After(time.Second):
				t.Fatal("TLS sender leaked")
			}
		})
	}
}

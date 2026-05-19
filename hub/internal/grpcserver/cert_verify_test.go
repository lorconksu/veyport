package grpcserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/ca"
	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

const (
	testGenerateCAFmt          = "generate CA: %v"
	testGenerateClientKeyFmt   = "generate client key: %v"
	testCreateCSRFmt           = "create CSR: %v"
	testServerIDCert           = "s-cert"
	testExpectCertRenewResp    = "expected a CertRenewResponse to be sent"
	testExpectCertRenewPayload = "expected CertRenewResponse payload"
	testServerIDNoCA           = "s-noca"
	testServerIDBadCSR         = "s-badcsr"
	testServerIDRouteCert      = "s-route-cert"
	testReconnectServerID      = "server-1"
)

func TestExtractServerIDFromCert(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "server-42"},
	}
	got := extractServerIDFromCert(cert)
	if got != "server-42" {
		t.Fatalf("expected 'server-42', got '%s'", got)
	}
}

func TestExtractServerIDFromCert_NilCert(t *testing.T) {
	got := extractServerIDFromCert(nil)
	if got != "" {
		t.Fatalf("expected empty string for nil cert, got '%s'", got)
	}
}

func TestHandleCertRenewal(t *testing.T) {
	h, st := testHandler(t)

	// Set up CA
	caCert, caKey, err := ca.GenerateCA()
	if err != nil {
		t.Fatalf(testGenerateCAFmt, err)
	}
	h.caCert = caCert
	h.caKey = caKey

	// Create and register server
	st.CreateServer(&model.Server{ID: testServerIDCert, Name: "cert-test", Status: "online", Labels: "{}"})
	stream := &mockStream{}
	h.connMgr.Register(testServerIDCert, stream)

	// Generate a CSR
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf(testGenerateClientKeyFmt, err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: testServerIDCert},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, clientKey)
	if err != nil {
		t.Fatalf(testCreateCSRFmt, err)
	}

	req := &pb.CertRenewRequest{Csr: csrDER}
	h.handleCertRenewal(testServerIDCert, stream, req)

	if len(stream.sent) == 0 {
		t.Fatal(testExpectCertRenewResp)
	}

	resp := stream.sent[0].GetCertRenewResponse()
	if resp == nil {
		t.Fatal(testExpectCertRenewPayload)
	}
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if len(resp.ClientCert) == 0 {
		t.Fatal("expected non-empty client cert")
	}
	if len(resp.CaCert) == 0 {
		t.Fatal("expected non-empty CA cert")
	}

	// Verify the returned certificate
	clientCert, err := x509.ParseCertificate(resp.ClientCert)
	if err != nil {
		t.Fatalf("parse returned client cert: %v", err)
	}
	if clientCert.Subject.CommonName != testServerIDCert {
		t.Fatalf("expected CN 's-cert', got '%s'", clientCert.Subject.CommonName)
	}
	if time.Until(clientCert.NotAfter) < 11*time.Hour {
		t.Fatal("expected cert validity of ~12 hours")
	}
}

func TestHandleCertRenewal_NoCA(t *testing.T) {
	h, st := testHandler(t)
	h.caCert = nil
	h.caKey = nil

	st.CreateServer(&model.Server{ID: testServerIDNoCA, Name: "noca-test", Status: "online", Labels: "{}"})
	stream := &mockStream{}
	h.connMgr.Register(testServerIDNoCA, stream)

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf(testGenerateClientKeyFmt, err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: testServerIDNoCA},
	}, clientKey)
	if err != nil {
		t.Fatalf(testCreateCSRFmt, err)
	}

	req := &pb.CertRenewRequest{Csr: csrDER}
	h.handleCertRenewal(testServerIDNoCA, stream, req)

	if len(stream.sent) == 0 {
		t.Fatal(testExpectCertRenewResp)
	}
	resp := stream.sent[0].GetCertRenewResponse()
	if resp == nil {
		t.Fatal(testExpectCertRenewPayload)
	}
	if resp.Error != "CA not configured" {
		t.Fatalf("expected 'CA not configured' error, got '%s'", resp.Error)
	}
}

func TestHandleCertRenewal_InvalidCSR(t *testing.T) {
	h, st := testHandler(t)

	caCert, caKey, err := ca.GenerateCA()
	if err != nil {
		t.Fatalf(testGenerateCAFmt, err)
	}
	h.caCert = caCert
	h.caKey = caKey

	st.CreateServer(&model.Server{ID: testServerIDBadCSR, Name: "badcsr-test", Status: "online", Labels: "{}"})
	stream := &mockStream{}
	h.connMgr.Register(testServerIDBadCSR, stream)

	req := &pb.CertRenewRequest{Csr: []byte("not-a-valid-csr")}
	h.handleCertRenewal(testServerIDBadCSR, stream, req)

	if len(stream.sent) == 0 {
		t.Fatal(testExpectCertRenewResp)
	}
	resp := stream.sent[0].GetCertRenewResponse()
	if resp == nil {
		t.Fatal(testExpectCertRenewPayload)
	}
	if resp.Error == "" {
		t.Fatal("expected error for invalid CSR")
	}
}

func TestRouteAgentMessage_CertRenewRequest(t *testing.T) {
	h, st := testHandler(t)

	caCert, caKey, err := ca.GenerateCA()
	if err != nil {
		t.Fatalf(testGenerateCAFmt, err)
	}
	h.caCert = caCert
	h.caKey = caKey

	st.CreateServer(&model.Server{ID: testServerIDRouteCert, Name: "route-cert", Status: "online", Labels: "{}"})
	stream := &mockStream{}
	h.connMgr.Register(testServerIDRouteCert, stream)

	// Generate a valid CSR
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf(testGenerateClientKeyFmt, err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: testServerIDRouteCert},
	}, clientKey)
	if err != nil {
		t.Fatalf(testCreateCSRFmt, err)
	}

	msg := &pb.AgentMessage{
		Payload: &pb.AgentMessage_CertRenewRequest{
			CertRenewRequest: &pb.CertRenewRequest{Csr: csrDER},
		},
	}
	err = h.routeAgentMessage(testServerIDRouteCert, stream, msg)
	if err != nil {
		t.Fatalf("route cert renew request: %v", err)
	}

	if len(stream.sent) == 0 {
		t.Fatal("expected CertRenewResponse to be sent via routing")
	}
	resp := stream.sent[0].GetCertRenewResponse()
	if resp == nil {
		t.Fatal(testExpectCertRenewPayload)
	}
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
}

func TestVerifyCertCN_RequiresClientCertForReconnect(t *testing.T) {
	h, _ := testHandler(t)
	if err := h.verifyCertCN(&mockStream{}, testReconnectServerID, true); err == nil {
		t.Fatal("expected reconnect without client cert to be rejected")
	}
}

func TestVerifyCertCN_AllowsRegistrationWithoutClientCert(t *testing.T) {
	h, _ := testHandler(t)
	if err := h.verifyCertCN(&mockStream{}, testReconnectServerID, false); err != nil {
		t.Fatalf("expected registration without client cert to be allowed, got %v", err)
	}
}

func TestVerifyCertCN_AcceptsMatchingCert(t *testing.T) {
	h, _ := testHandler(t)
	if err := h.verifyCertCN(streamWithPeerCert(testReconnectServerID), testReconnectServerID, true); err != nil {
		t.Fatalf("expected matching client cert to be accepted, got %v", err)
	}
}

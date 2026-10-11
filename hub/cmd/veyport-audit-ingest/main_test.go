package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCommandArgumentsAndSafeFailures(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), []string{"--version"}, &output); err != nil || strings.TrimSpace(output.String()) != version {
		t.Fatal("version unavailable")
	}
	output.Reset()
	if err := run(context.Background(), []string{"--help"}, &output); err != nil || !strings.Contains(output.String(), "--config") {
		t.Fatal("help unavailable")
	}
	for _, args := range [][]string{nil, {"--unknown=SYNTHETIC_SECRET"}, {"--config", "missing"}, {"--config", "missing", "extra"}} {
		output.Reset()
		if err := run(context.Background(), args, &output); err == nil {
			t.Fatal("invalid configuration accepted")
		}
		if strings.Contains(output.String(), "SYNTHETIC_SECRET") {
			t.Fatal("secret argument logged")
		}
	}
}

func TestServiceShutdownAndStartupFailure(t *testing.T) {
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	config := fixture.TLS.Clone()
	fixture.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	var output bytes.Buffer
	err := runWithBuilder(ctx, []string{"--config", "protected"}, &output, func(context.Context, string) (*http.Server, error) {
		return &http.Server{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }), TLSConfig: config, ReadHeaderTimeout: time.Second}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = runWithBuilder(context.Background(), []string{"--config", "protected"}, &output, func(context.Context, string) (*http.Server, error) { return nil, errors.New("SYNTHETIC_SECRET_build") }); err == nil || strings.Contains(output.String(), "SYNTHETIC_SECRET") {
		t.Fatal("startup failure exposed detail")
	}
	if err = runWithBuilder(context.Background(), []string{"--config", "protected"}, &output, func(context.Context, string) (*http.Server, error) {
		return &http.Server{Addr: "invalid-address", TLSConfig: &tls.Config{}}, nil
	}); err == nil {
		t.Fatal("invalid listener accepted")
	}
}

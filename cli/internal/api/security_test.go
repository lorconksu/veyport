package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

func TestBoundedSecurityResponses(t *testing.T) {
	for _, test := range []struct {
		name, body string
		want       int
	}{{"valid", `{"state":"standard","unknown":"ignored"}`, 0}, {"oversized", strings.Repeat("x", 65), 1}, {"trailing", `{"state":"standard"}{}`, 1}, {"empty", "", 1}, {"malformed", "{", 1}} {
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, test.body) }))
			defer srv.Close()
			client := NewClient(srv.URL, "")
			client.MaxResponseBytes = 64
			var result SecurityPolicyStatus
			err := client.Get(context.Background(), "/api/audit-policy", nil, &result)
			if cmdutil.Code(err) != test.want {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestBoundedSecurityInterruptedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "{")
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "")
	client.MaxResponseBytes = 128
	var result SecurityPolicyStatus
	if err := client.Get(context.Background(), "/api/audit-policy", nil, &result); cmdutil.Code(err) != cmdutil.ExitConn {
		t.Fatal(err)
	}
}

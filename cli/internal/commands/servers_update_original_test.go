package commands

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

func TestServersUpdateOriginalAssertionReachesBoundRequestAndPrintedHelper(t *testing.T) {
	for _, fault := range []string{"valid", "known_capabilities", "native"} {
		t.Run(fault, func(t *testing.T) {
			mux, srv, dir := seedForServers(t, "tok")
			mux.HandleFunc("GET /api/servers/node", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(api.Server{ID: "node"}) })
			artifact := api.AgentArtifact{Version: "2.0.1-prototype.5", Revision: strings.Repeat("f", 40)}
			check := api.AgentUpdateCheck{BootstrapRequired: true, BootstrapIdleConfirmationRequired: true, ConnectionID: "fresh", Target: artifact}
			if fault == "known_capabilities" {
				check.Current = &struct {
					Version  string `json:"version"`
					Revision string `json:"revision"`
					SHA256   string `json:"sha256"`
				}{Version: "0.1.0"}
			}
			if fault == "native" {
				check.BootstrapRequired = false
				check.BootstrapIdleConfirmationRequired = false
				check.Supported = true
				check.UpdateAvailable = true
			}
			mux.HandleFunc("GET /api/servers/node/agent-update", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(check) })
			posts := 0
			mux.HandleFunc("POST /api/servers/node/agent-update", func(w http.ResponseWriter, r *http.Request) {
				posts++
				var body struct {
					Version    string `json:"bootstrap_original_version"`
					SHA256     string `json:"bootstrap_original_sha256"`
					Confirmed  bool   `json:"bootstrap_idle_confirmed"`
					Connection string `json:"expected_connection_id"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Version != "0.1.0" || body.SHA256 != strings.Repeat("b", 64) || !body.Confirmed || body.Connection != "fresh" {
					t.Error("original assertion not bound to checked operation", body, err)
				}
				json.NewEncoder(w).Encode(api.AgentUpdateStart{Operation: api.AgentUpdate{ID: "op", NodeID: "node", State: "bootstrap_required", Target: artifact}, BootstrapTicket: strings.Repeat("c", 64)})
			})
			ctx, out, stderr := newCmdContext(srv.URL, dir, false, []string{"update", "node", "--bootstrap-idle-confirmed", "--bootstrap-original-version", "0.1.0", "--bootstrap-original-sha256", strings.Repeat("b", 64)})
			code := RunServers(ctx)
			if fault == "valid" {
				if code != 0 || posts != 1 || !strings.Contains(out.String(), "--original-version '0.1.0' --original-sha256 '"+strings.Repeat("b", 64)+"'") || !strings.Contains(out.String(), "--status --operation op") {
					t.Fatal("bound helper omitted assertion/status", code, posts, out.String(), stderr.String())
				}
			} else if code != cmdutil.ExitForbidden || posts != 0 {
				t.Fatal("original assertion became native escape hatch", code, posts, stderr.String())
			}
		})
	}
}

func TestServersUpdateOriginalFlagsRequireCompleteScopedComparableAssertion(t *testing.T) {
	valid := []string{"node", "--bootstrap-idle-confirmed", "--bootstrap-original-version", "0.1.0", "--bootstrap-original-sha256", strings.Repeat("a", 64)}
	if _, err := parseServersUpdate(valid); err != nil {
		t.Fatal(err)
	}
	invalid := [][]string{
		{"node", "--bootstrap-original-version", "0.1.0", "--bootstrap-original-sha256", strings.Repeat("a", 64)},
		valid[:4],
		append(append([]string{}, valid...), "--bootstrap-original-version", "0.1.0"),
		append(append([]string{}, valid...), "--bootstrap-original-sha256", strings.Repeat("a", 64)),
		append(append([]string{}, valid...), "--check"),
		append(append([]string{}, valid...), "--status"),
		append(append([]string{}, valid...), "--acknowledge-recovery", "op", "--verified-sha256", strings.Repeat("a", 64)),
	}
	for _, value := range []string{"dev", "0.01.0", "0.1.0; touch /tmp/untrusted", "0.1.0+" + strings.Repeat("a", 122)} {
		args := append([]string{}, valid...)
		args[3] = value
		invalid = append(invalid, args)
	}
	for _, value := range []string{"", "bad", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		args := append([]string{}, valid...)
		args[5] = value
		invalid = append(invalid, args)
	}
	for _, args := range invalid {
		if _, err := parseServersUpdate(args); err == nil {
			t.Fatal("unsafe original flags accepted", args)
		}
	}
}

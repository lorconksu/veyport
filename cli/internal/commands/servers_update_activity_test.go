package commands

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

func TestServersUpdateManualBootstrapFlagIsScopedAndPinsFreshConnection(t *testing.T) {
	for _, phase := range []string{"unconfirmed", "confirmed", "missing-connection", "native", "check"} {
		t.Run(phase, func(t *testing.T) {
			mux, srv, dir := seedForServers(t, "tok")
			mux.HandleFunc("GET /api/servers/node", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(api.Server{ID: "node"}) })
			artifact := api.AgentArtifact{Version: "2.0.1-prototype.5", Revision: strings.Repeat("f", 40), SHA256: strings.Repeat("a", 64)}
			check := api.AgentUpdateCheck{BootstrapRequired: true, BootstrapIdleConfirmationRequired: true, ConnectionID: "fresh-generation", Target: artifact}
			if phase == "missing-connection" {
				check.ConnectionID = ""
			}
			if phase == "native" {
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
					Version    string `json:"expected_version"`
					Revision   string `json:"expected_revision"`
					Confirmed  bool   `json:"bootstrap_idle_confirmed"`
					Connection string `json:"expected_connection_id"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !body.Confirmed || body.Connection != "fresh-generation" || body.Version != artifact.Version || body.Revision != artifact.Revision {
					t.Error("manual bootstrap assertion did not bind checked identity", body, err)
				}
				json.NewEncoder(w).Encode(api.AgentUpdateStart{Operation: api.AgentUpdate{ID: "op", NodeID: "node", State: "bootstrap_required", Target: artifact}, BootstrapTicket: strings.Repeat("b", 64)})
			})
			args := []string{"update", "node"}
			if phase == "check" {
				args = append(args, "--check")
			} else if phase != "unconfirmed" {
				args = append(args, "--bootstrap-idle-confirmed")
			}
			ctx, out, stderr := newCmdContext(srv.URL, dir, false, args)
			code := RunServers(ctx)
			if phase == "confirmed" {
				if code != 0 || posts != 1 || !strings.Contains(out.String(), "--ticket") {
					t.Fatal(code, posts, out.String(), stderr.String())
				}
			} else if phase == "check" {
				if code != 0 || posts != 0 || !strings.Contains(out.String(), "Bootstrap required: true") {
					t.Fatal(code, posts, out.String(), stderr.String())
				}
			} else {
				if code != cmdutil.ExitForbidden || posts != 0 {
					t.Fatal("unsafe manual path created authority", code, posts, stderr.String())
				}
				if phase == "unconfirmed" && !strings.Contains(stderr.String(), "direct SSH") {
					t.Fatal("refusal missing actionable idle precondition", stderr.String())
				}
			}
		})
	}
}
func TestServersUpdateManualIdleFlagParsingCannotChangeStatusOrRecovery(t *testing.T) {
	for _, args := range [][]string{{"node", "--bootstrap-idle-confirmed"}, {"--bootstrap-idle-confirmed", "node"}} {
		if _, err := parseServersUpdate(args); err != nil {
			t.Fatal(args, err)
		}
	}
	for _, args := range [][]string{{"node", "--bootstrap-idle-confirmed", "--check"}, {"node", "--bootstrap-idle-confirmed", "--status"}, {"node", "--bootstrap-idle-confirmed", "--bootstrap-idle-confirmed"}, {"node", "--bootstrap-idle-confirmed", "--acknowledge-recovery", "op", "--verified-sha256", "hash"}} {
		if _, err := parseServersUpdate(args); err == nil {
			t.Fatal("unsafe flag combination accepted", args)
		}
	}
}

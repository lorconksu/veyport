package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

func TestServersUpdateFlagsWorkAfterNodeAndRejectUnsafeCombinations(t *testing.T) {
	for _, args := range [][]string{{"node", "--check"}, {"--check", "node"}, {"node", "--status", "--operation", "op"}, {"node", "--acknowledge-recovery", "op", "--verified-sha256", "hash"}} {
		if _, err := parseServersUpdate(args); err != nil {
			t.Fatal(args, err)
		}
	}
	for _, args := range [][]string{nil, {"node", "extra"}, {"node", "--url", "https://bad"}, {"node", "--check", "--status"}, {"node", "--operation", "op"}, {"node", "--acknowledge-recovery", "op"}, {"node", "--verified-sha256", "hash"}, {"node", "--status", "--acknowledge-recovery", "op", "--verified-sha256", "hash"}} {
		if _, err := parseServersUpdate(args); err == nil {
			t.Fatal("accepted unsafe args", args)
		}
	}
}
func TestServersUpdateCheckNeverStartsAndUsesStoredInteractiveSession(t *testing.T) {
	mux, srv, dir := seedForServers(t, "tok")
	mux.HandleFunc("GET /api/servers/node", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(api.Server{ID: "node"}) })
	mux.HandleFunc("GET /api/servers/node/agent-update", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(api.AgentUpdateCheck{Supported: true, UpdateAvailable: true, Target: api.AgentArtifact{Version: "2.0.1", SHA256: strings.Repeat("a", 64)}})
	})
	mux.HandleFunc("POST /api/servers/node/agent-update", func(http.ResponseWriter, *http.Request) { t.Fatal("check mutated remote node") })
	ctx, out, stderr := newCmdContext(srv.URL, dir, true, []string{"update", "node", "--check"})
	if code := RunServers(ctx); code != 0 || !json.Valid(out.Bytes()) {
		t.Fatal(code, out.String(), stderr.String())
	}
	t.Setenv("VEYPORT_TOKEN", "adt_API_TOKEN_CANARY")
	ctx, out, stderr = newCmdContext(srv.URL, dir, false, []string{"update", "node", "--check"})
	if code := RunServers(ctx); code != cmdutil.ExitForbidden || out.Len() != 0 || strings.Contains(stderr.String(), "CANARY") {
		t.Fatal("API token path was accepted/disclosed", code, stderr.String())
	}
}

func TestServersUpdateUnsupportedApplyRefusesAndCurrentArtifactIsNoOp(t *testing.T) {
	for _, supported := range []bool{false, true} {
		t.Run(fmt.Sprint(supported), func(t *testing.T) {
			mux, srv, dir := seedForServers(t, "tok")
			mux.HandleFunc("GET /api/servers/node", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(api.Server{ID: "node"}) })
			mux.HandleFunc("GET /api/servers/node/agent-update", func(w http.ResponseWriter, _ *http.Request) {
				json.NewEncoder(w).Encode(api.AgentUpdateCheck{Supported: supported, Reason: "noncanonical installation", Target: api.AgentArtifact{Version: "2.0.1"}})
			})
			mux.HandleFunc("POST /api/servers/node/agent-update", func(http.ResponseWriter, *http.Request) { t.Fatal("unsupported/current agent mutated") })
			ctx, _, stderr := newCmdContext(srv.URL, dir, false, []string{"update", "node"})
			code := RunServers(ctx)
			if supported && code != 0 || !supported && code != cmdutil.ExitForbidden {
				t.Fatal("apply confused unsupported with current", code, stderr.String())
			}
		})
	}
}
func TestServersUpdatePollsSameOperationAndRequiresExactReconnectEvidence(t *testing.T) {
	for _, phase := range []string{"success", "false-success", "rollback", "unknown", "bootstrap"} {
		t.Run(phase, func(t *testing.T) {
			mux, srv, dir := seedForServers(t, "tok")
			artifact := api.AgentArtifact{Version: "2.0.1-prototype.4", Revision: strings.Repeat("f", 40), SHA256: strings.Repeat("a", 64)}
			op := api.AgentUpdate{ID: "op", NodeID: "node", State: "requested", Target: artifact}
			mux.HandleFunc("GET /api/servers/node", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(api.Server{ID: "node"}) })
			mux.HandleFunc("GET /api/servers/node/agent-update", func(w http.ResponseWriter, _ *http.Request) {
				json.NewEncoder(w).Encode(api.AgentUpdateCheck{Supported: true, UpdateAvailable: true, Target: artifact, BootstrapRequired: phase == "bootstrap"})
			})
			posts := 0
			mux.HandleFunc("POST /api/servers/node/agent-update", func(w http.ResponseWriter, r *http.Request) {
				posts++
				var body map[string]string
				json.NewDecoder(r.Body).Decode(&body)
				if body["expected_version"] != artifact.Version || body["expected_revision"] != artifact.Revision || len(body) != 2 {
					t.Error("request did not pin checked artifact", body)
				}
				response := api.AgentUpdateStart{Operation: op}
				if phase == "bootstrap" {
					response.Operation.State = "bootstrap_required"
					response.BootstrapTicket = strings.Repeat("b", 64)
				}
				json.NewEncoder(w).Encode(response)
			})
			mux.HandleFunc("GET /api/servers/node/agent-update/status", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("operation_id") != "op" {
					t.Error("followed another operation")
				}
				result := op
				result.State = "succeeded"
				result.ObservedVersion = artifact.Version
				result.ObservedRevision = artifact.Revision
				result.ObservedSHA256 = artifact.SHA256
				if phase == "false-success" {
					result.ObservedSHA256 = "other"
				}
				if phase == "rollback" {
					result.State = "rolled_back"
				}
				if phase == "unknown" {
					result.State = "unknown"
					result.PreviousSHA256 = strings.Repeat("c", 64)
				}
				json.NewEncoder(w).Encode(result)
			})
			ctx, out, stderr := newCmdContext(srv.URL, dir, phase != "bootstrap", []string{"update", "node"})
			code := RunServers(ctx)
			if posts != 1 {
				t.Fatal("update retried", posts)
			}
			if phase == "success" || phase == "bootstrap" {
				if code != 0 {
					t.Fatal(code, stderr.String())
				}
			} else if code == 0 {
				t.Fatal("unconfirmed result exited success", phase, out.String())
			}
			if phase == "bootstrap" && (!strings.Contains(out.String(), "sudo bash -s -- --hub") || !strings.Contains(out.String(), "--ticket")) {
				t.Fatal("missing concise preserving bootstrap", out.String())
			}
		})
	}
}
func TestServersUpdateStatusAndRecoveryNeverCreateAnotherOperation(t *testing.T) {
	for _, phase := range []string{"status", "recovery"} {
		t.Run(phase, func(t *testing.T) {
			mux, srv, dir := seedForServers(t, "tok")
			mux.HandleFunc("GET /api/servers/node", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(api.Server{ID: "node"}) })
			mux.HandleFunc("POST /api/servers/node/agent-update", func(http.ResponseWriter, *http.Request) { t.Fatal("status/recovery started another update") })
			args := []string{"update", "node", "--status", "--operation", "op"}
			mux.HandleFunc("GET /api/servers/node/agent-update/status", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("operation_id") != "op" {
					t.Fatal("unbound status")
				}
				json.NewEncoder(w).Encode(api.AgentUpdate{ID: "op", State: "unknown"})
			})
			mux.HandleFunc("POST /api/servers/node/agent-update/recovery", func(w http.ResponseWriter, r *http.Request) {
				var body map[string]string
				json.NewDecoder(r.Body).Decode(&body)
				if body["operation_id"] != "op" || body["verified_sha256"] != "hash" {
					t.Fatal("recovery unbound", body)
				}
				json.NewEncoder(w).Encode(api.AgentUpdate{ID: "op", State: "recovery_acknowledged"})
			})
			if phase == "recovery" {
				args = []string{"update", "node", "--acknowledge-recovery", "op", "--verified-sha256", "hash"}
			}
			ctx, out, stderr := newCmdContext(srv.URL, dir, true, args)
			if code := RunServers(ctx); code != 0 || !json.Valid(out.Bytes()) {
				t.Fatal(code, out.String(), stderr.String())
			}
		})
	}
}

func TestServersUpdateHumanUnknownStatusExplainsArtifactAndRecovery(t *testing.T) {
	mux, srv, dir := seedForServers(t, "tok")
	mux.HandleFunc("GET /api/servers/node", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(api.Server{ID: "node"}) })
	mux.HandleFunc("GET /api/servers/node/agent-update/status", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(api.AgentUpdate{ID: "op", NodeID: "node", State: "unknown", Reason: "legacy rollback remains unconfirmed", Target: api.AgentArtifact{Version: "2.0.1"}, PreviousSHA256: strings.Repeat("a", 64), ObservedVersion: "0.1.0", ObservedSHA256: strings.Repeat("b", 64)})
	})
	ctx, out, stderr := newCmdContext(srv.URL, dir, false, []string{"update", "node", "--status"})
	if code := RunServers(ctx); code != 0 {
		t.Fatal(code, stderr.String())
	}
	for _, word := range []string{"unknown", "legacy rollback remains unconfirmed", "sudo sha256sum", "Expected original SHA256"} {
		if !strings.Contains(out.String(), word) {
			t.Fatal("unknown status omitted actionable recovery", word, out.String())
		}
	}
}

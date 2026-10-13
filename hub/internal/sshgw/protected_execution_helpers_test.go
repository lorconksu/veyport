package sshgw

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestGatewayReadinessRequiresLiveListener(t *testing.T) {
	if (*Server)(nil).Ready() {
		t.Fatal("nil gateway reported ready")
	}
	t.Run("running-and-stopped", func(t *testing.T) {
		f := newFixture(t, nil)
		if f.srv.Ready() {
			t.Fatal("configuration alone reported readiness")
		}
		f.start()
		if !f.srv.Ready() {
			t.Fatal("bound gateway did not report ready")
		}
		if err := f.srv.Stop(context.Background()); err != nil {
			t.Fatal(err)
		}
		if f.srv.Ready() {
			t.Fatal("stopped gateway reported ready")
		}
	})
	t.Run("externally-closed", func(t *testing.T) {
		f := newFixture(t, nil)
		f.start()
		f.srv.mu.Lock()
		listener := f.srv.listener
		f.srv.mu.Unlock()
		_ = listener.Close()
		select {
		case err := <-f.startErr:
			if err == nil {
				t.Fatal("unexpected listener closure was not reported")
			}
		case <-time.After(time.Second):
			t.Fatal("closed listener did not end serving")
		}
		if f.srv.Ready() {
			t.Fatal("closed listener reported ready")
		}
	})
	t.Run("bind-failure", func(t *testing.T) {
		occupied, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer occupied.Close()
		f := newFixture(t, func(c *Config) { c.Addr = occupied.Addr().String() })
		if err := f.srv.Start(); err == nil || f.srv.Ready() {
			t.Fatal("failed bind reported a ready gateway")
		}
	})
	t.Run("disabled", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.Enabled = false })
		if err := f.srv.Start(); err != nil || f.srv.Ready() {
			t.Fatal("disabled gateway reported ready")
		}
	})
}

func TestLifecycleAndDenialKeepOnlyStableRedactedBindings(t *testing.T) {
	now := time.Now().UTC()
	code := int32(42)
	e := &model.Execution{ID: "execution", ActorID: "actor", ActorPersonID: "person", ActorName: "Alice", NodeID: "node", NodeName: "target", PolicyVersion: "2", PolicySHA256: auditrecord.Hash([]byte("policy")), CommandSHA256: auditrecord.Hash([]byte("SYNTHETIC_SECRET_command")), CommandLength: 24, State: "exited", ExitCode: &code, Reason: "SYNTHETIC_SECRET_reason", UpdatedAt: now.Add(-time.Second), FinishedAt: &now, Preparation: model.ExecutionPreparation{PreparationID: "preparation", BootID: "boot", ExpiresUnixMilli: now.Add(time.Minute).UnixMilli(), Identity: model.ExecutionIdentity{Username: "root", Groups: []uint32{0}, GroupsSHA256: auditrecord.Hash([]byte("groups")), IdentitySHA256: auditrecord.Hash([]byte("identity")), Home: "/root", Shell: "/bin/sh", Cwd: "/root"}, Limits: model.ExecutionLimits{MaxFrameBytes: 65536, MaxBufferBytes: 2 << 20, RuntimeSeconds: 3600, TermGraceSeconds: 5, BlockedConsumerSeconds: 60}}}
	for _, prepared := range []bool{true, false} {
		if !prepared {
			e.Preparation = model.ExecutionPreparation{}
		}
		envelope, err := lifecycleEnvelope(e)
		if err != nil {
			t.Fatal(err)
		}
		if err := envelope.Validate(); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(envelope)
		if err != nil || bytes.Contains(raw, []byte("SYNTHETIC_SECRET")) {
			t.Fatal("raw submission or diagnostic entered lifecycle evidence")
		}
		if !envelope.OccurredAt.Equal(now) || envelope.Details.ExitCode == nil || *envelope.Details.ExitCode != 42 {
			t.Fatal("evidence changed the stable actual completion")
		}
		if prepared {
			if envelope.Execution == nil || envelope.Execution.Identity.IdentitySHA256 != e.Preparation.Identity.IdentitySHA256 {
				t.Fatal("prepared identity was lost")
			}
		} else if envelope.EventType != auditrecord.ExecutionDenial || envelope.Execution != nil || envelope.Details.Submission.NodeID != e.NodeID || envelope.Details.Submission.CommandSHA256 != e.CommandSHA256 {
			t.Fatal("denial lost its submission binding or fabricated an identity")
		}
	}
	e.PolicyVersion = "invalid"
	if _, err := lifecycleEnvelope(e); err == nil {
		t.Fatal("invalid policy identity entered recovery")
	}
}

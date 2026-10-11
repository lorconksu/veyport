package auditrecord

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validEnvelope() Envelope {
	return Envelope{SchemaVersion: 1, EventID: "event-1", EventType: ExecutionAdmission, Actor: Actor{UserID: "user-1", PersonID: "person-1", Name: "actor", Provider: "local", Subject: "user-1"}, PolicyVersion: 1, PolicySHA256: Hash([]byte("policy")), OccurredAt: time.Now().UTC(), Command: []byte("true"), Execution: &ExecutionBinding{ExecutionID: "exec-1", PreparationID: "prep-1", BootID: "boot-1", NodeID: "node-1", NodeName: "node", Identity: Identity{Username: "actor", UID: 1000, GID: 1000, GroupsSHA256: Hash([]byte("groups")), IdentitySHA256: Hash([]byte("identity")), Home: "/home/actor", Shell: "/bin/bash", CWD: "/home/actor"}, CommandSHA256: Hash([]byte("true")), CommandBytes: 4, PreparedUntil: time.Now().Add(time.Minute).UTC(), Limits: Limits{MaxFrameBytes: 65536, MaxBufferBytes: 2097152, RuntimeSeconds: 60, TermGraceSeconds: 3, BlockedConsumerSeconds: 30}}}
}

func TestStrictDecode(t *testing.T) {
	b, _ := json.Marshal(validEnvelope())
	cases := []string{strings.Replace(string(b), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1), strings.Replace(string(b), `"uid":1000`, `"uid":1000,"uid":1001`, 1), strings.Replace(string(b), `"uid":1000`, `"UID":1000`, 1), strings.Replace(string(b), `"uid":1000`, `"unknown":1000`, 1), string(b) + `{}`, `null`, strings.Replace(string(b), `"actor":{`, `"actor":{"name":"other",`, 1)}
	for _, raw := range cases {
		var e Envelope
		if Decode([]byte(raw), &e, MaxEnvelopeBytes) == nil {
			t.Errorf("accepted ambiguous schema")
		}
	}
	var e Envelope
	if Decode(b, &e, MaxEnvelopeBytes) != nil || e.Validate() != nil {
		t.Fatal("valid record rejected")
	}
	if Decode(b, &e, len(b)-1) == nil || Decode([]byte{0xff}, &e, 128) == nil {
		t.Fatal("invalid bounds accepted")
	}
}

func TestAdmissionBindings(t *testing.T) {
	changes := []func(*Envelope){func(e *Envelope) { e.SchemaVersion = 2 }, func(e *Envelope) { e.EventID = "../bad" }, func(e *Envelope) { e.Command = []byte("else") }, func(e *Envelope) { e.Command = make([]byte, MaxCommandBytes+1) }, func(e *Envelope) { e.Execution = nil }, func(e *Envelope) { e.Execution.Identity.Shell = "relative" }, func(e *Envelope) { e.Execution.ScriptSHA256 = Hash([]byte("script")) }, func(e *Envelope) { e.Attachments = []Attachment{{ID: "script", SHA256: Hash(nil), Bytes: -1}} }, func(e *Envelope) { e.EventType = "other" }, func(e *Envelope) { e.PolicyVersion = 0 }, func(e *Envelope) { e.Details = &Details{CorrelationID: "id", Reason: strings.Repeat("x", 4097)} }}
	for _, change := range changes {
		e := validEnvelope()
		change(&e)
		if e.Validate() == nil {
			t.Fatal("bad binding accepted")
		}
	}
	e := validEnvelope()
	e.Execution.ScriptSHA256 = Hash(nil)
	e.Attachments = []Attachment{{ID: "script", SHA256: Hash(nil)}}
	if e.Validate() != nil {
		t.Fatal("empty finite script rejected")
	}
	b, _ := json.Marshal(e)
	want, _, err := ExpectedFor(b)
	if err != nil || want.RecordSHA256 != Hash(b) || want.ActorSHA256 != Digest(e.Actor) {
		t.Fatal("exact bytes not bound")
	}
}

func TestProtectedSchemas(t *testing.T) {
	for _, typ := range []string{PolicyIntent, PolicyCommit, PolicyResult, PolicyAnchor, OriginalReadIntent, OriginalReadResult, ExecutionLifecycle} {
		e := validEnvelope()
		e.EventType = typ
		e.Command = nil
		if strings.HasPrefix(typ, "policy.") {
			e.Execution = nil
		}
		e.Details = &Details{CorrelationID: "correlation", RequestID: "request", RequestSHA256: Hash([]byte("request")), SessionSHA256: Hash([]byte("session")), Reason: "investigation", Originals: []ObjectRef{{Bucket: "archive", Key: "event", VersionID: "version", SHA256: Hash(nil), RetainUntil: time.Now()}}}
		if !strings.HasPrefix(typ, "policy.") && e.Validate() != nil {
			t.Fatalf("rejects %s", typ)
		}
		if typ == PolicyIntent {
			e.Details.Requester = &Actor{UserID: "requester", PersonID: "requester", Name: "requester"}
			e.Details.ApprovedChange = []byte("request")
			e.Details.Approvals = []ApprovalEvidence{{UserID: "a", PersonID: "a", StepupProofSHA256: Hash(nil), ApprovedAt: time.Now()}, {UserID: "b", PersonID: "b", StepupProofSHA256: Hash(nil), ApprovedAt: time.Now()}}
		}
		if !strings.HasPrefix(typ, "policy.") && e.Validate() != nil {
			t.Fatalf("rejects enriched %s", typ)
		}
		if typ == PolicyAnchor {
			e.Details.InstallationID = "installation"
			e.Details.ExpectedPolicyVersion = 1
			e.Details.NewPolicyVersion = 2
			e.PolicyVersion = 2
			e.Execution = nil
		}
		e.Details = nil
		if typ != ExecutionLifecycle && e.Validate() == nil {
			t.Fatalf("missing binding accepted %s", typ)
		}
	}
}

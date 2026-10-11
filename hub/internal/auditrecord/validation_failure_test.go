package auditrecord

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type strictTree struct {
	Value int           `json:"value"`
	Next  *strictTree   `json:"next,omitempty"`
	List  []*strictTree `json:"list,omitempty"`
}

func TestDecodeRejectsMalformedNestedTypesAndDepth(t *testing.T) {
	for _, raw := range []string{
		`{"value":`, `{"value":1,`, `{"value":{}}`, `{"value":[]}`,
		`{"value":"1"}`, `{"value":1.5}`, `{"next":{"value":`,
		`{"list":[{"value":1},`, `{"list":[{"value":true}]}`,
		`{"list":{}}`, `{"next":[]}`, `{"value":1} null`,
		strings.Repeat(`{"next":`, 34) + `{}` + strings.Repeat(`}`, 34),
	} {
		var out strictTree
		if err := Decode([]byte(raw), &out, 4096); !errors.Is(err, ErrSchema) {
			t.Fatalf("malformed/deep input accepted: %q: %v", raw, err)
		}
	}
	for _, dst := range []any{nil, strictTree{}, (*strictTree)(nil)} {
		if Decode([]byte(`{}`), dst, 4096) == nil {
			t.Fatal("unusable destination accepted")
		}
	}
	var out strictTree
	if Decode(nil, &out, 4096) == nil {
		t.Fatal("empty record accepted")
	}
	if err := Decode([]byte(`{"next":{"value":2},"list":[{"value":3}]}`), &out, 4096); err != nil || out.Next.Value != 2 || len(out.List) != 1 || out.List[0].Value != 3 {
		t.Fatal("valid nested structure rejected", err)
	}
}

func TestDecodePreservesExactExportedFieldNames(t *testing.T) {
	type PublicFields struct {
		Event string `json:"event"`
	}
	type document struct {
		PublicFields
		Count   int
		Ignored string `json:"-"`
		private string
		At      time.Time `json:"at"`
	}
	var d document
	if err := Decode([]byte(`{"event":"event-1","Count":2,"at":"2026-10-11T00:00:00Z"}`), &d, 4096); err != nil || d.Event != "event-1" || d.Count != 2 || d.At.IsZero() {
		t.Fatal("valid exact schema rejected", err)
	}
	for _, raw := range []string{`{"Ignored":"secret"}`, `{"private":"secret"}`, `{"count":2}`, `{"at":{}}`, `{"event":"one","event":"two"}`} {
		if Decode([]byte(raw), &d, 4096) == nil {
			t.Fatalf("unknown/aliased field accepted: %s", raw)
		}
	}
}

func TestEnvelopeFailureContracts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Envelope)
	}{
		{"script_size_without_hash", func(e *Envelope) { e.Execution.ScriptBytes = 1 }},
		{"invalid_script_hash", func(e *Envelope) { e.Execution.ScriptSHA256 = "invalid" }},
		{"attachment_without_script_binding", func(e *Envelope) { e.Attachments = []Attachment{{ID: "script", SHA256: Hash(nil)}} }},
		{"duplicate_attachment", func(e *Envelope) {
			e.Attachments = []Attachment{{ID: "script", SHA256: Hash(nil)}, {ID: "script", SHA256: Hash(nil)}}
		}},
		{"aggregate_attachment_limit", func(e *Envelope) {
			e.Attachments = []Attachment{{ID: "one", SHA256: Hash(nil), Bytes: MaxAttachmentBytes}, {ID: "two", SHA256: Hash(nil), Bytes: 1}}
		}},
		{"lifecycle_without_execution", func(e *Envelope) { e.EventType = ExecutionLifecycle; e.Execution = nil; e.Command = nil }},
		{"lifecycle_with_command", func(e *Envelope) { e.EventType = ExecutionLifecycle }},
		{"invalid_approver_person", func(e *Envelope) {
			e.Details = &Details{CorrelationID: "review", ApproverPersonIDs: []string{"../person"}}
		}},
		{"invalid_original_reference", func(e *Envelope) { e.Details = &Details{CorrelationID: "read", Originals: []ObjectRef{{}}} }},
		{"approval_without_fresh_evidence", func(e *Envelope) {
			e.Details = &Details{CorrelationID: "review", Approvals: []ApprovalEvidence{{UserID: "one", PersonID: "one", StepupProofSHA256: Hash(nil)}}}
		}},
		{"submission_outside_denial", func(e *Envelope) {
			e.Details = &Details{CorrelationID: "denial", Submission: &SubmissionBinding{NodeID: "node", CommandBytes: 4, CommandSHA256: Hash([]byte("true"))}}
		}},
		{"read_without_reason", func(e *Envelope) {
			e.EventType = OriginalReadIntent
			e.Execution = nil
			e.Command = nil
			e.Details = &Details{CorrelationID: "read", SessionSHA256: Hash(nil), Originals: []ObjectRef{{Bucket: "archive", Key: "original", VersionID: "v1", SHA256: Hash(nil), RetainUntil: time.Now().Add(time.Hour)}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := validEnvelope()
			tc.change(&e)
			raw, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := ExpectedFor(raw); !errors.Is(err, ErrSchema) {
				t.Fatalf("invalid event produced receipt expectation: %v", err)
			}
		})
	}
}

func TestPolicyAnchorRejectsNonSequentialOrContentBearingChanges(t *testing.T) {
	e := validEnvelope()
	e.EventType, e.Command, e.Execution = PolicyAnchor, nil, nil
	e.PolicyVersion = 2
	e.Details = &Details{CorrelationID: "change", RequestID: "request", RequestSHA256: Hash(nil), InstallationID: "installation", ExpectedPolicyVersion: 1, NewPolicyVersion: 2}
	if e.Validate() != nil {
		t.Fatal("valid anchor rejected")
	}
	for _, change := range []func(*Envelope){
		func(e *Envelope) { e.Details.ExpectedPolicyVersion = ^uint64(0) },
		func(e *Envelope) { e.Details.NewPolicyVersion = 3 },
		func(e *Envelope) { e.PolicyVersion = 3 },
		func(e *Envelope) { e.Details.ApprovedChange = []byte("raw change") },
	} {
		bad := e
		d := *e.Details
		bad.Details = &d
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid external policy sequence accepted")
		}
	}
}

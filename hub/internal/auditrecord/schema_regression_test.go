package auditrecord

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGovernanceCannotContainExecutionOriginals(t *testing.T) {
	for _, typ := range []string{PolicyIntent, PolicyCommit, PolicyResult, PolicyAnchor} {
		e := validEnvelope()
		e.EventType = typ
		e.Command = nil
		e.Details = &Details{CorrelationID: "change", RequestID: "change", RequestSHA256: Hash(nil)}
		if e.Validate() == nil {
			t.Fatal("policy record accepted execution identity")
		}
		e.Execution = nil
		e.Attachments = []Attachment{{ID: "script", SHA256: Hash(nil)}}
		if e.Validate() == nil {
			t.Fatal("policy record accepted original attachment")
		}
	}
}

func TestRequesterAndBoundedSchemaFields(t *testing.T) {
	e := validEnvelope()
	e.Details = &Details{CorrelationID: "id", Requester: &Actor{UserID: "requester", PersonID: "person", Name: "requester"}}
	if e.Validate() != nil {
		t.Fatal("valid requester rejected")
	}
	e.Details.Requester.Subject = strings.Repeat("x", 513)
	if e.Validate() == nil {
		t.Fatal("unbounded requester subject")
	}
	e = validEnvelope()
	e.Execution.Identity.Groups = make([]uint32, 1025)
	if e.Validate() == nil {
		t.Fatal("unbounded groups accepted")
	}
	e = validEnvelope()
	e.EventType = OriginalReadIntent
	e.Command = nil
	e.Attachments = []Attachment{{ID: "raw", SHA256: Hash(nil)}}
	if e.Validate() == nil {
		t.Fatal("read intent accepted raw attachment")
	}
	e = validEnvelope()
	e.EventType = PolicyIntent
	e.Execution = nil
	e.Command = nil
	e.Details = &Details{CorrelationID: "change", RequestID: "change", RequestSHA256: Hash([]byte("approved")), ApprovedChange: []byte("approved"), Reason: "reviewed", Requester: &Actor{UserID: "requester", PersonID: "requester"}, Approvals: []ApprovalEvidence{{UserID: "a", PersonID: "a", StepupProofSHA256: Hash(nil), ApprovedAt: time.Now()}, {UserID: "b", PersonID: "b", StepupProofSHA256: Hash(nil), ApprovedAt: time.Now()}}}
	if e.Validate() != nil {
		t.Fatal("full approved policy intent rejected")
	}
	raw, _ := json.Marshal(e)
	if _, _, err := ExpectedFor(raw); err != nil {
		t.Fatal(err)
	}
	e.Details.Requester = nil
	if e.Validate() == nil {
		t.Fatal("policy requester missing")
	}
}

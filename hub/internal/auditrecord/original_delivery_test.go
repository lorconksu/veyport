package auditrecord

import (
	"testing"
	"time"
)

func TestOriginalDeliveryHasExplicitBoundedHubScope(t *testing.T) {
	e := validEnvelope()
	e.EventType = OriginalReadResult
	e.Execution = nil
	e.Command = nil
	n := int64(3)
	e.Details = &Details{CorrelationID: "read", SessionSHA256: Hash([]byte("session")), Reason: "incident", State: "interrupted", Originals: []ObjectRef{{Bucket: "archive", Key: "original", VersionID: "exact-version", SHA256: Hash(nil), Bytes: 3, RetainUntil: time.Now().Add(time.Hour)}}, Delivery: &OriginalDelivery{BytesWritten: &n, Scope: "hub_response"}}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []int64{-1, MaxAttachmentBytes + 1} {
		n = bad
		if e.Validate() == nil {
			t.Fatal("unbounded delivery count accepted")
		}
	}
	n = 3
	e.Details.Delivery.Scope = "client_disk"
	if e.Validate() == nil {
		t.Fatal("unprovable client-disk scope accepted")
	}
	e.Details.Delivery.Scope = "hub_response"
	e.Details.State = "started"
	if e.Validate() == nil {
		t.Fatal("started evidence claimed transferred bytes")
	}
	e.Details.State = "completed"
	e.Details.Delivery.BytesWritten = nil
	if e.Validate() == nil {
		t.Fatal("completion has unknown count")
	}
	e.Details.State = "unconfirmed"
	if e.Validate() != nil {
		t.Fatal("uncertain crash evidence required fabricated count")
	}
	e.EventType = OriginalReadIntent
	if e.Validate() == nil {
		t.Fatal("intent smuggled result delivery")
	}
	e.EventType = ExecutionLifecycle
	if e.Validate() == nil {
		t.Fatal("process record smuggled original delivery")
	}
}

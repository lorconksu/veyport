package auditingest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func TestSyntheticReadinessProjectionHasNoProcessOrOSIdentity(t *testing.T) {
	now := time.Now().UTC()
	raw, _ := testRecord(t, now, nil)
	var envelope auditrecord.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.EventType = auditrecord.ExecutionLifecycle
	envelope.Command = nil
	envelope.Details = &auditrecord.Details{CorrelationID: "readiness", State: "synthetic-readiness-no-process"}
	for _, eventType := range []string{auditrecord.ExecutionLifecycle, auditrecord.ExecutionAdmission} {
		envelope.EventType = eventType
		if eventType == auditrecord.ExecutionAdmission {
			envelope.Command = []byte("printf SYNTHETIC_SECRET_command")
			envelope.Execution.CommandBytes = int64(len(envelope.Command))
			envelope.Execution.CommandSHA256 = auditrecord.Hash(envelope.Command)
		}
		raw, _ = json.Marshal(envelope)
		ref := ExportReference{envelope.EventID, eventType, auditrecord.Hash(raw), auditrecord.ObjectRef{Bucket: "archive", Key: "manifests/"+envelope.EventID, VersionID: "v1", SHA256: auditrecord.Hash(nil), RetainUntil: now.Add(time.Hour)}}
		projection, err := Project(raw, ref)
		if err != nil {
			t.Fatal(err)
		}
		if eventType == auditrecord.ExecutionLifecycle {
			if projection.ProcessState != "synthetic_readiness_not_applicable" || projection.UID != nil || projection.GID != nil || projection.RunAs != "" {
				t.Fatal("synthetic readiness presented as a remote process or OS identity")
			}
		} else if projection.ProcessState != "unconfirmed" || projection.UID == nil {
			t.Fatal("admission used synthetic metadata to hide real process uncertainty")
		}
	}
}

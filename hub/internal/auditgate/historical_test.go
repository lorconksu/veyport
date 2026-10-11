package auditgate

import (
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func TestHistoricalCompletionCannotRenewAdmission(t *testing.T) {
	v, key, claims, expected, now := fixture(t)
	old := sign(t, key, claims)
	if _, err := v.VerifyHistorical(old, expected, now.Add(2*time.Minute)); err == nil {
		t.Fatal("historical admission renewed")
	}
	expected.EventType = auditrecord.ExecutionLifecycle
	claims.EventType = expected.EventType
	token := sign(t, key, claims)
	if _, err := v.Verify(token, expected, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired current receipt accepted")
	}
	if _, err := v.VerifyHistorical(token, expected, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	expected.RecordSHA256 = auditrecord.Hash([]byte("wrong"))
	if _, err := v.VerifyHistorical(token, expected, now.Add(2*time.Minute)); err == nil {
		t.Fatal("wrong historical record accepted")
	}
}

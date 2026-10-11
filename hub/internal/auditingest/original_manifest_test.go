package auditingest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

func TestOriginalManifestAdminOnlyExactRetainedMetadata(t *testing.T) {
	h, s, archive, now := testHandler(t)
	canary := []byte("SYNTHETIC_ORIGINAL_CANARY_never_metadata")
	raw, inputs := testRecord(t, now, canary)
	receipt, err := s.Preserve(context.Background(), raw, inputs)
	if err != nil {
		t.Fatal(err)
	}
	_, envelope, _ := auditrecord.ExpectedFor(raw)
	path := "/v1/manifests/" + envelope.EventID + "?" + url.Values{"sha256": {auditrecord.Hash(raw)}, "version_id": {receipt.Manifest.VersionID}}.Encode()
	for _, credential := range []string{strings.Repeat("i", 32), strings.Repeat("r", 32), ""} {
		if w := callHandler(h, "GET", path, credential, nil); w.Code != 401 {
			t.Fatal("nonadmin read manifest:", w.Code)
		}
	}
	w := callHandler(h, "GET", path, strings.Repeat("a", 32), nil)
	if w.Code != 200 || bytes.Contains(w.Body.Bytes(), canary) || int64(w.Body.Len()) != receipt.Manifest.Bytes || auditrecord.Hash(w.Body.Bytes()) != receipt.Manifest.SHA256 {
		t.Fatal("exact metadata response failed:", w.Code)
	}
	var m auditrecord.Manifest
	if json.Unmarshal(w.Body.Bytes(), &m) != nil || m.Envelope.SHA256 != auditrecord.Hash(raw) || len(m.Attachments) != 1 {
		t.Fatal("manifest lost exact refs")
	}
	for _, bad := range []string{path + "&version_id=duplicate", path + "&extra=value", strings.Replace(path, receipt.Manifest.VersionID, "shadow-version", 1), strings.Replace(path, auditrecord.Hash(raw), auditrecord.Hash(nil), 1)} {
		if callHandler(h, "GET", bad, strings.Repeat("a", 32), nil).Code == 200 {
			t.Fatal("wrong version/query metadata accepted")
		}
	}
	archive.failVerify = m.Attachments[0].Key
	if callHandler(h, "GET", path, strings.Repeat("a", 32), nil).Code != 503 {
		t.Fatal("partial/unqualified manifest accepted")
	}
	archive.failVerify = ""
	archive.mu.Lock()
	original := archive.objects[receipt.Manifest.Key]
	original.ref.VersionID = "replacement-version"
	archive.objects[receipt.Manifest.Key] = original
	archive.mu.Unlock()
	if callHandler(h, "GET", path, strings.Repeat("a", 32), nil).Code != 503 {
		t.Fatal("latest replacement concealed exact version")
	}
}

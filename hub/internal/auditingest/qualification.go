package auditingest

import (
	"github.com/wyiu/veyport/hub/internal/auditrecord"
	"net/url"
	"time"
)

// Qualification is an operator-reviewed, digest-pinned report for one exact
// archive configuration. A reachable service or successful HEAD is not a report.
type Qualification struct {
	SchemaVersion           int       `json:"schema_version"`
	ArchiveEndpoint         string    `json:"archive_endpoint"`
	ArchiveVersion          string    `json:"archive_version"`
	Bucket                  string    `json:"bucket"`
	KMSKeyID                string    `json:"kms_key_id"`
	DefaultRetentionSeconds uint64    `json:"default_retention_seconds"`
	ConfigurationSHA256     string    `json:"configuration_sha256"`
	ReportSHA256            string    `json:"report_sha256"`
	VerifiedAt              time.Time `json:"verified_at"`
	Checks                  []string  `json:"checks"`
	Digest                  string    `json:"-"`
}

var requiredChecks = []string{"versioning", "compliance_retention", "sse_kms", "exact_version_reads", "conditional_create", "writer_no_delete", "writer_no_retention_reduction", "acknowledged_write_process_crash", "acknowledged_write_power_loss", "encrypted_backup_restore", "key_restore"}

func LoadQualification(raw []byte, pinnedSHA256 string) (Qualification, error) {
	var q Qualification
	if !auditrecord.ValidHash(pinnedSHA256) || auditrecord.Hash(raw) != pinnedSHA256 || auditrecord.Decode(raw, &q, 64<<10) != nil {
		return q, ErrUnavailable
	}
	q.Digest = pinnedSHA256
	if q.Validate() != nil {
		return q, ErrUnavailable
	}
	return q, nil
}

func (q Qualification) Validate() error {
	u, err := url.Parse(q.ArchiveEndpoint)
	// Storage defaults may include one day of precision margin beyond the
	// maximum 3650-day application promise. This does not raise policy maxima.
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || q.SchemaVersion != 1 || q.ArchiveVersion == "" || q.Bucket == "" || q.KMSKeyID == "" || q.DefaultRetentionSeconds < 3600 || q.DefaultRetentionSeconds > 3651*86400 || !auditrecord.ValidHash(q.ConfigurationSHA256) || !auditrecord.ValidHash(q.ReportSHA256) || !auditrecord.ValidHash(q.Digest) || q.VerifiedAt.IsZero() {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	for _, s := range q.Checks {
		if seen[s] {
			return ErrUnavailable
		}
		seen[s] = true
	}
	for _, s := range requiredChecks {
		if !seen[s] {
			return ErrUnavailable
		}
	}
	if len(seen) != len(requiredChecks) {
		return ErrUnavailable
	}
	if q.VerifiedAt.After(time.Now().Add(5 * time.Minute)) {
		return ErrUnavailable
	}
	return nil
}

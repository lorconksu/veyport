package auditingest

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type exportListS3 struct {
	S3API
	result *s3.ListObjectsV2Output
	err    error
	input  *s3.ListObjectsV2Input
}

func (s *exportListS3) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	s.input = in
	return s.result, s.err
}

func TestExportS3PaginationCannotEscapeEventLedger(t *testing.T) {
	api := &exportListS3{result: &s3.ListObjectsV2Output{Contents: []types.Object{{Key: aws.String("events/b")}, {Key: aws.String("events/c")}}, IsTruncated: aws.Bool(true)}}
	archive := &S3Archive{config: S3Config{Bucket: "governance"}, api: api}
	ids, more, err := archive.ExportKeys(context.Background(), "a", 2)
	if err != nil || !more || len(ids) != 2 || aws.ToString(api.input.Prefix) != "events/" || aws.ToString(api.input.StartAfter) != "events/a" || aws.ToInt32(api.input.MaxKeys) != 2 {
		t.Fatal("pagination not bounded to ledger")
	}
	for _, bad := range []string{"../raw", "events/x", "a/b"} {
		if _, _, err := archive.ExportKeys(context.Background(), bad, 1); err == nil {
			t.Fatal("arbitrary cursor accepted")
		}
	}
	api.result.Contents = []types.Object{{Key: aws.String("envelopes/b")}}
	if _, _, err := archive.ExportKeys(context.Background(), "a", 2); err == nil {
		t.Fatal("unrelated key accepted")
	}
	api.result.Contents = []types.Object{{Key: aws.String("events/a")}}
	if _, _, err := archive.ExportKeys(context.Background(), "a", 2); err == nil {
		t.Fatal("non-progress cursor accepted")
	}
	api.result.Contents = nil
	if _, _, err := archive.ExportKeys(context.Background(), "a", 2); err == nil {
		t.Fatal("empty truncated page accepted")
	}
	api.result = nil
	if _, _, err := archive.ExportKeys(context.Background(), "", 2); err == nil {
		t.Fatal("nil result accepted")
	}
	if _, _, err := archive.ExportKeys(context.Background(), "", MaxExportPage+1); err == nil {
		t.Fatal("oversize page accepted")
	}
}

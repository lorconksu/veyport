package auditingest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

type fakeS3 struct {
	objects              map[string]object
	defaultRetentionDays int32
	lostReplyPrefix      string
	promises             map[string]string
	fail                 string
	headChange           func(*s3.HeadObjectOutput)
	readChange           func(*s3.GetObjectOutput)
	retentionChange      func(*s3.GetObjectRetentionOutput)
	versioning           types.BucketVersioningStatus
	lockMode             types.ObjectLockRetentionMode
	listTruncated        bool
	calls                []string
	now                  func() time.Time
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: map[string]object{}, promises: map[string]string{}, defaultRetentionDays: 1, versioning: types.BucketVersioningStatusEnabled, lockMode: types.ObjectLockRetentionModeCompliance}
}
func (f *fakeS3) PutObject(_ context.Context, i *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.calls = append(f.calls, "put")
	if f.fail == "put" {
		return nil, errors.New("SYNTHETIC_SECRET_backend_error")
	}
	if aws.ToString(i.IfNoneMatch) != "*" || i.ServerSideEncryption != types.ServerSideEncryptionAwsKms || aws.ToString(i.SSEKMSKeyId) != "archive-key" || i.ObjectLockRetainUntilDate != nil || i.ObjectLockMode != "" || i.ContentMD5 == nil {
		return nil, errors.New("unsafe write")
	}
	key := aws.ToString(i.Key)
	if _, ok := f.objects[key]; ok {
		return nil, &smithy.GenericAPIError{Code: "PreconditionFailed"}
	}
	b, _ := io.ReadAll(i.Body)
	createdAt := time.Now()
	if f.now != nil {
		createdAt = f.now()
	}
	r := auditrecord.ObjectRef{Bucket: aws.ToString(i.Bucket), Key: key, VersionID: "version-1", SHA256: auditrecord.Hash(b), Bytes: int64(len(b)), RetainUntil: createdAt.Add(time.Duration(f.defaultRetentionDays) * 24 * time.Hour)}
	f.objects[key] = object{r, b}
	f.promises[key] = i.Metadata["retain-until"]
	if f.lostReplyPrefix != "" && strings.HasPrefix(key, f.lostReplyPrefix) {
		return nil, ErrUnavailable
	}
	return &s3.PutObjectOutput{VersionId: aws.String(r.VersionID)}, nil
}
func (f *fakeS3) HeadObject(_ context.Context, i *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	f.calls = append(f.calls, "head:"+aws.ToString(i.VersionId))
	if f.fail == "head" {
		return nil, errors.New("SYNTHETIC_SECRET_head")
	}
	o, ok := f.objects[aws.ToString(i.Key)]
	if !ok {
		return nil, &smithy.GenericAPIError{Code: "NotFound"}
	}
	if i.VersionId != nil && aws.ToString(i.VersionId) != o.ref.VersionID {
		return nil, errors.New("wrong version")
	}
	h := &s3.HeadObjectOutput{VersionId: aws.String(o.ref.VersionID), ContentLength: aws.Int64(o.ref.Bytes), Metadata: map[string]string{"sha256": o.ref.SHA256, "retain-until": f.promises[aws.ToString(i.Key)]}, ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String("archive-key"), ObjectLockMode: types.ObjectLockModeCompliance, ObjectLockRetainUntilDate: &o.ref.RetainUntil}
	if f.headChange != nil {
		f.headChange(h)
	}
	return h, nil
}
func (f *fakeS3) GetObject(_ context.Context, i *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.calls = append(f.calls, "get:"+aws.ToString(i.VersionId))
	if f.fail == "get" {
		return nil, errors.New("SYNTHETIC_SECRET_get")
	}
	o, ok := f.objects[aws.ToString(i.Key)]
	if !ok || aws.ToString(i.VersionId) != o.ref.VersionID {
		return nil, errors.New("not exact version")
	}
	g := &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(o.data)), VersionId: aws.String(o.ref.VersionID), ContentLength: aws.Int64(o.ref.Bytes), ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String("archive-key")}
	if f.readChange != nil {
		f.readChange(g)
	}
	return g, nil
}
func (f *fakeS3) GetObjectRetention(_ context.Context, i *s3.GetObjectRetentionInput, _ ...func(*s3.Options)) (*s3.GetObjectRetentionOutput, error) {
	f.calls = append(f.calls, "retention:"+aws.ToString(i.VersionId))
	if f.fail == "retention" {
		return nil, errors.New("SYNTHETIC_SECRET_retention")
	}
	o, ok := f.objects[aws.ToString(i.Key)]
	if !ok || aws.ToString(i.VersionId) != o.ref.VersionID {
		return nil, errors.New("not exact version")
	}
	r := &s3.GetObjectRetentionOutput{Retention: &types.ObjectLockRetention{Mode: types.ObjectLockRetentionModeCompliance, RetainUntilDate: &o.ref.RetainUntil}}
	if f.retentionChange != nil {
		f.retentionChange(r)
	}
	return r, nil
}
func (f *fakeS3) GetBucketVersioning(_ context.Context, _ *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	if f.fail == "versioning" {
		return nil, ErrUnavailable
	}
	return &s3.GetBucketVersioningOutput{Status: f.versioning}, nil
}
func (f *fakeS3) GetObjectLockConfiguration(_ context.Context, _ *s3.GetObjectLockConfigurationInput, _ ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error) {
	if f.fail == "lock" {
		return nil, ErrUnavailable
	}
	return &s3.GetObjectLockConfigurationOutput{ObjectLockConfiguration: &types.ObjectLockConfiguration{ObjectLockEnabled: types.ObjectLockEnabledEnabled, Rule: &types.ObjectLockRule{DefaultRetention: &types.DefaultRetention{Mode: f.lockMode, Days: aws.Int32(f.defaultRetentionDays)}}}}, nil
}
func (f *fakeS3) ListObjectsV2(_ context.Context, i *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	if f.fail == "list" {
		return nil, ErrUnavailable
	}
	var contents []types.Object
	for key := range f.objects {
		if strings.HasPrefix(key, aws.ToString(i.Prefix)) {
			contents = append(contents, types.Object{Key: aws.String(key)})
		}
	}
	return &s3.ListObjectsV2Output{Contents: contents, IsTruncated: aws.Bool(f.listTruncated), NextContinuationToken: aws.String("cursor")}, nil
}

func testS3(t *testing.T) (*S3Archive, *fakeS3) {
	t.Helper()
	q := validQualification()
	f := newFakeS3()
	a, err := NewS3Archive(context.Background(), S3Config{Endpoint: q.ArchiveEndpoint, Region: "region", Bucket: q.Bucket, KMSKeyID: q.KMSKeyID, AllowedHosts: []string{"archive.example:8333"}, Qualification: q}, f)
	if err != nil {
		t.Fatal(err)
	}
	return a, f
}

func TestS3ExactProtectedWritesAndReads(t *testing.T) {
	a, f := testS3(t)
	ctx := context.Background()
	if a.Ready(ctx) != nil {
		t.Fatal("qualified archive unavailable")
	}
	f.versioning = types.BucketVersioningStatusSuspended
	if a.Ready(ctx) == nil {
		t.Fatal("runtime versioning removal did not close readiness")
	}
	f.versioning = types.BucketVersioningStatusEnabled
	want := []byte("SYNTHETIC_SECRET_original")
	minimum := time.Now().Add(time.Hour)
	r, err := a.Put(ctx, "envelope", want, minimum)
	if err != nil {
		t.Fatal(err)
	}
	if r.VersionID != "version-1" || r.SHA256 != auditrecord.Hash(want) {
		t.Fatal("write version not bound")
	}
	found, b, err := a.Find(ctx, "envelope")
	if err != nil || !bytes.Equal(b, want) || found.VersionID != r.VersionID {
		t.Fatal("exact lookup failed")
	}
	b, err = a.Read(ctx, r)
	if err != nil || !bytes.Equal(b, want) {
		t.Fatal("read failed")
	}
	if _, err = a.Put(ctx, "envelope", []byte("replace"), minimum); err == nil || len(f.objects) != 1 {
		t.Fatal("conditional write overwritten")
	}
	if _, _, err = a.Find(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal("not found misclassified")
	}
	keys, err := a.ListKeys(ctx, "envelope")
	if err != nil || len(keys) != 1 {
		t.Fatal("list failed")
	}
	if a.Qualification().Digest != a.config.Qualification.Digest {
		t.Fatal("qualification lost")
	}
}

func TestS3RejectsUnprotectedVersions(t *testing.T) {
	changes := []func(*s3.HeadObjectOutput){func(h *s3.HeadObjectOutput) { h.VersionId = aws.String("other") }, func(h *s3.HeadObjectOutput) { h.ContentLength = aws.Int64(1) }, func(h *s3.HeadObjectOutput) { h.Metadata["sha256"] = auditrecord.Hash(nil) }, func(h *s3.HeadObjectOutput) { h.ServerSideEncryption = types.ServerSideEncryptionAes256 }, func(h *s3.HeadObjectOutput) { h.SSEKMSKeyId = aws.String("other") }, func(h *s3.HeadObjectOutput) { h.ObjectLockMode = types.ObjectLockModeGovernance }, func(h *s3.HeadObjectOutput) { h.ObjectLockRetainUntilDate = nil }, func(h *s3.HeadObjectOutput) { past := time.Now().Add(-time.Hour); h.ObjectLockRetainUntilDate = &past }, func(h *s3.HeadObjectOutput) { h.DeleteMarker = aws.Bool(true) }}
	for i, change := range changes {
		a, f := testS3(t)
		r, err := a.Put(context.Background(), "object", []byte("content"), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		f.headChange = change
		if a.Verify(context.Background(), r, r.RetainUntil) == nil {
			t.Errorf("unprotected head %d accepted", i)
		}
	}
	for _, op := range []string{"head", "get", "retention"} {
		a, f := testS3(t)
		r, _ := a.Put(context.Background(), "object", []byte("content"), time.Now().Add(time.Hour))
		f.fail = op
		if err := a.Verify(context.Background(), r, r.RetainUntil); err == nil || strings.Contains(err.Error(), "SYNTHETIC_SECRET") {
			t.Fatal("backend failure accepted or leaked")
		}
	}
	a, f := testS3(t)
	r, _ := a.Put(context.Background(), "object", []byte("content"), time.Now().Add(time.Hour))
	f.retentionChange = func(r *s3.GetObjectRetentionOutput) { r.Retention.Mode = types.ObjectLockRetentionModeGovernance }
	if a.Verify(context.Background(), r, r.RetainUntil) == nil {
		t.Fatal("governance retention accepted")
	}
	f.retentionChange = nil
	f.readChange = func(g *s3.GetObjectOutput) { g.Body = io.NopCloser(strings.NewReader("changed")) }
	if a.Verify(context.Background(), r, r.RetainUntil) == nil {
		t.Fatal("content corrupt accepted")
	}
	f.readChange = func(g *s3.GetObjectOutput) { g.VersionId = aws.String("other") }
	if a.Verify(context.Background(), r, r.RetainUntil) == nil {
		t.Fatal("other content version accepted")
	}
}

func TestS3StartupAndRetentionFailClosed(t *testing.T) {
	for _, op := range []string{"versioning", "lock"} {
		a, f := testS3(t)
		f.fail = op
		if a.ready(context.Background()) == nil {
			t.Fatal("failed readiness accepted")
		}
	}
	a, f := testS3(t)
	f.versioning = types.BucketVersioningStatusSuspended
	if a.ready(context.Background()) == nil {
		t.Fatal("suspended versioning accepted")
	}
	f.versioning = types.BucketVersioningStatusEnabled
	f.lockMode = types.ObjectLockRetentionModeGovernance
	if a.ready(context.Background()) == nil {
		t.Fatal("governance bucket accepted")
	}
	a, f = testS3(t)
	if _, err := a.Put(context.Background(), "longer-than-default", nil, time.Now().Add(48*time.Hour)); err == nil {
		t.Fatal("insufficient bucket retention accepted")
	}
	f.listTruncated = true
	if _, err := a.ListKeys(context.Background(), "prefix/"); err == nil {
		t.Fatal("unbounded list allowed")
	}
	f.fail = "list"
	if _, err := a.ListKeys(context.Background(), "prefix/"); err == nil {
		t.Fatal("list failure ignored")
	}
	c := a.config
	c.Endpoint = "http://archive"
	if _, err := NewS3Archive(context.Background(), c, f); err == nil {
		t.Fatal("cleartext endpoint accepted")
	}
	c = a.config
	c.Bucket = "other"
	if _, err := NewS3Archive(context.Background(), c, f); err == nil {
		t.Fatal("qualification reused for different bucket")
	}
	c = a.config
	c.AllowedHosts = nil
	if _, err := NewS3Archive(context.Background(), c, f); err == nil {
		t.Fatal("arbitrary endpoint allowed")
	}
}

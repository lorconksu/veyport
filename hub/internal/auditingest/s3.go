package auditingest

import (
	"bytes"
	"context"
	"crypto/md5" // S3 Object Lock requires this transport checksum, not an identity hash.
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/wyiu/veyport/hub/internal/auditgate"
	"github.com/wyiu/veyport/hub/internal/auditrecord"
)

// S3API deliberately exposes no delete, retention mutation, or public URL API.
type S3API interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	GetObjectRetention(context.Context, *s3.GetObjectRetentionInput, ...func(*s3.Options)) (*s3.GetObjectRetentionOutput, error)
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetObjectLockConfiguration(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

type S3Config struct {
	Endpoint         string
	Region           string
	Bucket           string
	KMSKeyID         string
	AllowedHosts     []string
	AllowedAddresses []string
	TLS              *tls.Config
	Credentials      aws.CredentialsProvider
	Qualification    Qualification
}

type S3Archive struct {
	config S3Config
	api    S3API
}

func NewS3Archive(ctx context.Context, c S3Config, api S3API) (*S3Archive, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || c.Region == "" || c.Bucket != c.Qualification.Bucket || c.KMSKeyID != c.Qualification.KMSKeyID || c.Endpoint != c.Qualification.ArchiveEndpoint || c.Qualification.Validate() != nil {
		return nil, ErrUnavailable
	}
	allowed := false
	for _, h := range c.AllowedHosts {
		if h == u.Host {
			allowed = true
		}
	}
	if !allowed {
		return nil, ErrUnavailable
	}
	if api == nil {
		if c.Credentials == nil || c.TLS == nil || c.TLS.InsecureSkipVerify || c.TLS.RootCAs == nil || c.TLS.MinVersion < tls.VersionTLS12 {
			return nil, ErrUnavailable
		}
		client, clientErr := auditgate.NewTLSClient(auditgate.TransportConfig{Endpoint: c.Endpoint, AllowedHosts: c.AllowedHosts, AllowedAddresses: c.AllowedAddresses, TLS: c.TLS, Timeout: 10 * time.Second, Connections: 4})
		if clientErr != nil {
			return nil, ErrUnavailable
		}
		api = s3.NewFromConfig(aws.Config{Region: c.Region, Credentials: c.Credentials, HTTPClient: client, RetryMaxAttempts: 1, RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired, ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired}, func(o *s3.Options) { o.BaseEndpoint = aws.String(c.Endpoint); o.UsePathStyle = true })
	}
	a := &S3Archive{c, api}
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if a.ready(deadline) != nil {
		return nil, ErrUnavailable
	}
	return a, nil
}

func (a *S3Archive) Qualification() Qualification { return a.config.Qualification }

func (a *S3Archive) Ready(ctx context.Context) error { return a.ready(ctx) }

func (a *S3Archive) ready(ctx context.Context) error {
	if a.config.Qualification.Validate() != nil {
		return ErrUnavailable
	}
	v, err := a.api.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(a.config.Bucket)})
	if err != nil || v == nil || v.Status != types.BucketVersioningStatusEnabled {
		return ErrUnavailable
	}
	lock, err := a.api.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: aws.String(a.config.Bucket)})
	if err != nil || lock == nil || lock.ObjectLockConfiguration == nil || lock.ObjectLockConfiguration.ObjectLockEnabled != types.ObjectLockEnabledEnabled || lock.ObjectLockConfiguration.Rule == nil || lock.ObjectLockConfiguration.Rule.DefaultRetention == nil || lock.ObjectLockConfiguration.Rule.DefaultRetention.Mode != types.ObjectLockRetentionModeCompliance {
		return ErrUnavailable
	}
	r := lock.ObjectLockConfiguration.Rule.DefaultRetention
	days, years := aws.ToInt32(r.Days), aws.ToInt32(r.Years)
	if days < 0 || years < 0 || days != 0 && years != 0 || uint64(days)*86400+uint64(years)*365*86400 != a.config.Qualification.DefaultRetentionSeconds {
		return ErrUnavailable
	}
	return nil
}

func (a *S3Archive) Put(ctx context.Context, key string, data []byte, retain time.Time) (auditrecord.ObjectRef, error) {
	if len(data) > auditrecord.MaxAttachmentBytes || a.ready(ctx) != nil {
		return auditrecord.ObjectRef{}, ErrUnavailable
	}
	// Object Lock's Content-MD5 is a wire integrity checksum, not audit trust:
	// https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
	// Exact immutable refs use SHA256; receipts use ES256. See s3_test.go.
	checksum := md5.Sum(data) // nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-md5
	// Bucket default COMPLIANCE retention avoids granting the writer the ability
	// to mutate existing version retention. Exact post-write checks enforce retain.
	out, err := a.api.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(a.config.Bucket), Key: aws.String(key), Body: bytes.NewReader(data), ContentLength: aws.Int64(int64(len(data))), ContentMD5: aws.String(base64.StdEncoding.EncodeToString(checksum[:])), ContentType: aws.String("application/octet-stream"), Metadata: map[string]string{"sha256": auditrecord.Hash(data), "retain-until": retain.UTC().Format(time.RFC3339Nano)}, IfNoneMatch: aws.String("*"), ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(a.config.KMSKeyID)})
	if err != nil {
		return auditrecord.ObjectRef{}, ErrUnavailable
	}
	if out == nil || aws.ToString(out.VersionId) == "" || aws.ToString(out.VersionId) == "null" {
		return auditrecord.ObjectRef{}, ErrUnavailable
	}
	ref := auditrecord.ObjectRef{Bucket: a.config.Bucket, Key: key, VersionID: aws.ToString(out.VersionId), SHA256: auditrecord.Hash(data), Bytes: int64(len(data)), RetainUntil: retain}
	if a.Verify(ctx, ref, retain) != nil {
		return ref, ErrUnavailable
	}
	return ref, nil
}

func (a *S3Archive) Find(ctx context.Context, key string) (auditrecord.ObjectRef, []byte, error) {
	h, err := a.api.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(a.config.Bucket), Key: aws.String(key)})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && (apiErr.ErrorCode() == "NotFound" || apiErr.ErrorCode() == "NoSuchKey") {
			return auditrecord.ObjectRef{}, nil, ErrNotFound
		}
		return auditrecord.ObjectRef{}, nil, ErrUnavailable
	}
	if h == nil || h.DeleteMarker != nil && *h.DeleteMarker || h.ContentLength == nil || h.ObjectLockRetainUntilDate == nil {
		return auditrecord.ObjectRef{}, nil, ErrUnavailable
	}
	promised, parseErr := time.Parse(time.RFC3339Nano, h.Metadata["retain-until"])
	if parseErr != nil {
		return auditrecord.ObjectRef{}, nil, ErrUnavailable
	}
	ref := auditrecord.ObjectRef{Bucket: a.config.Bucket, Key: key, VersionID: aws.ToString(h.VersionId), SHA256: h.Metadata["sha256"], Bytes: aws.ToInt64(h.ContentLength), RetainUntil: promised}
	if !ref.Valid() || ref.Bytes > auditrecord.MaxAttachmentBytes || a.checkHead(h, ref, ref.RetainUntil) != nil || a.checkRetention(ctx, ref, ref.RetainUntil) != nil {
		return ref, nil, ErrUnavailable
	}
	data, err := a.read(ctx, ref)
	return ref, data, err
}

func (a *S3Archive) Verify(ctx context.Context, ref auditrecord.ObjectRef, retain time.Time) error {
	if !ref.Valid() || ref.Bucket != a.config.Bucket || ref.Bytes > auditrecord.MaxAttachmentBytes || ref.RetainUntil.Before(retain) || a.config.Qualification.Validate() != nil {
		return ErrUnavailable
	}
	h, err := a.api.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(ref.Bucket), Key: aws.String(ref.Key), VersionId: aws.String(ref.VersionID)})
	if err != nil || a.checkHead(h, ref, retain) != nil || a.checkRetention(ctx, ref, retain) != nil {
		return ErrUnavailable
	}
	_, err = a.read(ctx, ref)
	return err
}

func (a *S3Archive) checkHead(h *s3.HeadObjectOutput, r auditrecord.ObjectRef, retain time.Time) error {
	if h == nil || h.DeleteMarker != nil && *h.DeleteMarker || aws.ToString(h.VersionId) != r.VersionID || h.ContentLength == nil || *h.ContentLength != r.Bytes || h.Metadata["sha256"] != r.SHA256 || h.Metadata["retain-until"] != r.RetainUntil.UTC().Format(time.RFC3339Nano) || h.ServerSideEncryption != types.ServerSideEncryptionAwsKms || aws.ToString(h.SSEKMSKeyId) != a.config.KMSKeyID || h.ObjectLockMode != types.ObjectLockModeCompliance || h.ObjectLockRetainUntilDate == nil || h.ObjectLockRetainUntilDate.Before(retain) {
		return ErrUnavailable
	}
	return nil
}

func (a *S3Archive) checkRetention(ctx context.Context, r auditrecord.ObjectRef, retain time.Time) error {
	o, err := a.api.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{Bucket: aws.String(r.Bucket), Key: aws.String(r.Key), VersionId: aws.String(r.VersionID)})
	if err != nil || o == nil || o.Retention == nil || o.Retention.Mode != types.ObjectLockRetentionModeCompliance || o.Retention.RetainUntilDate == nil || o.Retention.RetainUntilDate.Before(retain) {
		return ErrUnavailable
	}
	return nil
}

func (a *S3Archive) read(ctx context.Context, r auditrecord.ObjectRef) ([]byte, error) {
	o, err := a.api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(r.Bucket), Key: aws.String(r.Key), VersionId: aws.String(r.VersionID)})
	if err != nil || o == nil || o.Body == nil {
		return nil, ErrUnavailable
	}
	defer o.Body.Close()
	if aws.ToString(o.VersionId) != r.VersionID || o.ContentLength == nil || *o.ContentLength != r.Bytes || o.ServerSideEncryption != types.ServerSideEncryptionAwsKms || aws.ToString(o.SSEKMSKeyId) != a.config.KMSKeyID {
		return nil, ErrUnavailable
	}
	b, err := readExact(o.Body, r.Bytes)
	if err != nil || int64(len(b)) != r.Bytes || auditrecord.Hash(b) != r.SHA256 {
		return nil, ErrUnavailable
	}
	return b, nil
}

func (a *S3Archive) Read(ctx context.Context, r auditrecord.ObjectRef) ([]byte, error) {
	if !r.Valid() || r.Bucket != a.config.Bucket || r.Bytes > auditrecord.MaxAttachmentBytes {
		return nil, ErrUnavailable
	}
	h, err := a.api.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(r.Bucket), Key: aws.String(r.Key), VersionId: aws.String(r.VersionID)})
	if err != nil || a.checkHead(h, r, r.RetainUntil) != nil || a.checkRetention(ctx, r, r.RetainUntil) != nil || a.config.Qualification.Validate() != nil {
		return nil, ErrUnavailable
	}
	return a.read(ctx, r)
}

func (a *S3Archive) ListKeys(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	var cursor *string
	for page := 0; page < 16; page++ {
		o, err := a.api.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(a.config.Bucket), Prefix: aws.String(prefix), MaxKeys: aws.Int32(1000), ContinuationToken: cursor})
		if err != nil || o == nil {
			return nil, ErrUnavailable
		}
		for _, entry := range o.Contents {
			key := aws.ToString(entry.Key)
			if !strings.HasPrefix(key, prefix) {
				return nil, ErrUnavailable
			}
			keys = append(keys, key)
		}
		if !aws.ToBool(o.IsTruncated) {
			return keys, nil
		}
		if o.NextContinuationToken == nil || aws.ToString(o.NextContinuationToken) == "" {
			return nil, ErrUnavailable
		}
		cursor = o.NextContinuationToken
	}
	return nil, ErrUnavailable
}

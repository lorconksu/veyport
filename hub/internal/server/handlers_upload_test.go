package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

// TestHandleUploadFile_NoFile verifies that uploading without a file field returns 400.
func TestHandleUploadFile_NoFile(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Send a multipart form without any file field
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.Close()

	req := httptest.NewRequest("POST", testS1Upload, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	req.Header.Set(testContentType, writer.FormDataContentType())
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for no file, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleUploadFile_NoAgent verifies that a valid upload request without a connected agent returns 502.
func TestHandleUploadFile_NoAgent(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Build a valid multipart form with a file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	part.Write([]byte("hello world"))
	writer.Close()

	req := httptest.NewRequest("POST", testS1Upload, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	req.Header.Set(testContentType, writer.FormDataContentType())
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf(testExpected502Body, rec.Code, rec.Body.String())
	}
}

// TestHandleDeleteDropzone_NoFilename verifies that a missing filename param returns 400.
func TestHandleDeleteDropzone_NoFilename(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("DELETE", "/api/servers/s1/dropzone", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing filename, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleDeleteDropzone_NoAgent verifies that with a valid filename but no connected agent returns 502.
func TestHandleDeleteDropzone_NoAgent(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("DELETE", "/api/servers/s1/dropzone?filename=test.txt", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf(testExpected502Body, rec.Code, rec.Body.String())
	}
}

// TestDropzoneDeletePathTraversal verifies that path traversal filenames are sanitized.
func TestDropzoneDeletePathTraversal(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	traversalNames := []string{
		"../../etc/passwd",
		"../../../etc/shadow",
		"..%2F..%2Fetc%2Fpasswd", // won't be decoded by Go but test anyway
		"/etc/passwd",
		"foo/../../../etc/passwd",
	}

	for _, name := range traversalNames {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("DELETE", "/api/servers/s1/dropzone?filename="+name, nil)
			req.Header.Set("Authorization", testBearerPrefix+token)
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)

			// After sanitization with filepath.Base, the filename should be safe.
			// The request should proceed past validation (502 = no agent, which means
			// the filename was accepted but stripped of directory components).
			// It should NOT return 400 "invalid filename" for these cases because
			// filepath.Base extracts a valid base name (e.g. "passwd").
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("expected 502 (no agent) after sanitization for %q, got %d: %s",
					name, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestDropzoneDeleteDotFilename verifies that "." and "/" filenames are rejected.
func TestDropzoneDeleteDotFilename(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// filepath.Base(".") returns ".", filepath.Base("/") returns "/"
	// but we only get "." from query param since "/" is part of URL path
	req := httptest.NewRequest("DELETE", "/api/servers/s1/dropzone?filename=.", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for dot filename, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestDropzoneUploadPathTraversal verifies that upload filenames with path traversal are sanitized.
func TestDropzoneUploadPathTraversal(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	traversalNames := []string{
		"../../etc/passwd",
		"../../../etc/shadow",
		"/etc/passwd",
		"foo/../../../etc/passwd",
	}

	for _, name := range traversalNames {
		t.Run(name, func(t *testing.T) {
			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)
			part, err := writer.CreateFormFile("file", name)
			if err != nil {
				t.Fatalf("create form file: %v", err)
			}
			part.Write([]byte("malicious content"))
			writer.Close()

			req := httptest.NewRequest("POST", testS1Upload, body)
			req.Header.Set("Authorization", testBearerPrefix+token)
			req.Header.Set(testContentType, writer.FormDataContentType())
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)

			// After filepath.Base sanitization, the filename is safe and the request
			// proceeds to agent send (502 = no agent connected).
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("expected 502 (no agent) after sanitization for %q, got %d: %s",
					name, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestHandleListDropzone_NoAgent verifies that listing dropzone without a connected agent returns 502.
func TestHandleListDropzone_NoAgent(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", "/api/servers/s1/dropzone", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf(testExpected502Body, rec.Code, rec.Body.String())
	}
}

// --- Streaming upload tests ---

// buildMultipartBody creates a multipart/form-data body for testing.
func buildMultipartBody(t *testing.T, fieldName, fileName string, content []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile(fieldName, fileName)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("Write part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close writer: %v", err)
	}
	return &buf, w.FormDataContentType()
}

func TestHandleUploadFile_StreamingSuccess(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	fileContent := []byte("hello world, this is test file content for streaming upload")
	body, ct := buildMultipartBody(t, "file", "test-upload.txt", fileContent)

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testUploadSuffix, body)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	req.Header.Set(testContentType, ct)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp model.UploadFileResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}
	if resp.Filename != "test-upload.txt" {
		t.Errorf("expected filename test-upload.txt, got %s", resp.Filename)
	}
	if resp.Size != int64(len(fileContent)) {
		t.Errorf("expected size %d, got %d", len(fileContent), resp.Size)
	}
}

func TestHandleUploadFile_LargeFileMultiChunk(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	// Create a file larger than one chunk (64KB) to verify multi-chunk streaming
	fileContent := bytes.Repeat([]byte("A"), 100*1024) // 100KB
	body, ct := buildMultipartBody(t, "file", "large-file.bin", fileContent)

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testUploadSuffix, body)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	req.Header.Set(testContentType, ct)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp model.UploadFileResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}
	if resp.Size != int64(len(fileContent)) {
		t.Errorf("expected size %d, got %d", len(fileContent), resp.Size)
	}
}

func TestHandleUploadFile_SizeLimitEnforced(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	// Build a multipart body whose file part exceeds maxUploadSize (100MB).
	// Use a piped reader so we don't allocate 100MB in memory.
	pr, pw := io.Pipe()

	mw := multipart.NewWriter(pw)
	ct := mw.FormDataContentType()

	go func() {
		part, err := mw.CreateFormFile("file", "huge-file.bin")
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		// Write slightly more than 100MB: 1601 * 64KB > 100MB
		chunk := bytes.Repeat([]byte("X"), 64*1024)
		for i := 0; i < 1601; i++ {
			if _, err := part.Write(chunk); err != nil {
				// Expected: pipe may be closed by the handler once limit is hit
				break
			}
		}
		mw.Close()
		pw.Close()
	}()

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testUploadSuffix, pr)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	req.Header.Set(testContentType, ct)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized file, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "file too large") {
		t.Errorf("expected 'file too large' in body, got: %s", rec.Body.String())
	}
}

func TestHandleUploadFile_WrongFieldName(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	// Send multipart with a different field name (not "file")
	body, ct := buildMultipartBody(t, "notfile", "test.txt", []byte("data"))

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testUploadSuffix, body)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	req.Header.Set(testContentType, ct)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing file field, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleUploadFile_EmptyFilename(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	body, ct := buildMultipartBody(t, "file", "", []byte("data"))

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testUploadSuffix, body)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	req.Header.Set(testContentType, ct)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty filename, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleUploadFile_FilenameSanitization(t *testing.T) {
	s, adminToken, serverID := testServerWithAgent(t)

	// Path traversal attempt: filepath.Base should strip directory components
	fileContent := []byte("data")
	body, ct := buildMultipartBody(t, "file", "../../../etc/passwd", fileContent)

	req := httptest.NewRequest("POST", testServersPrefix+serverID+testUploadSuffix, body)
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	req.Header.Set(testContentType, ct)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp model.UploadFileResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}
	if resp.Filename != "passwd" {
		t.Errorf("expected sanitized filename 'passwd', got %s", resp.Filename)
	}
}

func TestParseMultipartFileStream_NotMultipart(t *testing.T) {
	req := httptest.NewRequest("POST", testUploadSuffix, strings.NewReader("plain body"))
	req.Header.Set(testContentType, "application/json")

	_, _, err := parseMultipartFileStream(req)
	if err == nil {
		t.Fatal("expected error for non-multipart request")
	}
	if err.statusCode != http.StatusBadRequest {
		t.Errorf(testExpected400, err.statusCode)
	}
}

func TestParseMultipartFileStream_MissingContentType(t *testing.T) {
	req := httptest.NewRequest("POST", testUploadSuffix, strings.NewReader("body"))
	req.Header.Del(testContentType)

	_, _, err := parseMultipartFileStream(req)
	if err == nil {
		t.Fatal("expected error for missing content type")
	}
	if err.statusCode != http.StatusBadRequest {
		t.Errorf(testExpected400, err.statusCode)
	}
}

func TestParseMultipartFileStream_FilenameExtracted(t *testing.T) {
	fileContent := []byte("test content")
	body, ct := buildMultipartBody(t, "file", "my-document.pdf", fileContent)

	req := httptest.NewRequest("POST", testUploadSuffix, body)
	req.Header.Set(testContentType, ct)

	reader, filename, parseErr := parseMultipartFileStream(req)
	if parseErr != nil {
		t.Fatalf("unexpected error: %s", parseErr.message)
	}
	if filename != "my-document.pdf" {
		t.Errorf("expected filename 'my-document.pdf', got %q", filename)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(data, fileContent) {
		t.Errorf("content mismatch: got %q", string(data))
	}
}

func TestParseMultipartFileStream_MissingBoundary(t *testing.T) {
	req := httptest.NewRequest("POST", testUploadSuffix, strings.NewReader("body"))
	req.Header.Set(testContentType, "multipart/form-data") // no boundary param

	_, _, err := parseMultipartFileStream(req)
	if err == nil {
		t.Fatal("expected error for missing boundary")
	}
	if err.statusCode != http.StatusBadRequest {
		t.Errorf(testExpected400, err.statusCode)
	}
	if !strings.Contains(err.message, "boundary") {
		t.Errorf("expected boundary error, got: %s", err.message)
	}
}

func TestParseMultipartFileStream_SkipsNonFileParts(t *testing.T) {
	// Multipart body with a text field before the file field
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	if err := w.WriteField("description", "some metadata"); err != nil {
		t.Fatalf("WriteField: %v", err)
	}

	part, err := w.CreateFormFile("file", "actual-file.txt")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	fmt.Fprint(part, "file content here")
	w.Close()

	req := httptest.NewRequest("POST", testUploadSuffix, &buf)
	req.Header.Set(testContentType, w.FormDataContentType())

	reader, filename, parseErr := parseMultipartFileStream(req)
	if parseErr != nil {
		t.Fatalf("unexpected error: %s", parseErr.message)
	}
	if filename != "actual-file.txt" {
		t.Errorf("expected 'actual-file.txt', got %q", filename)
	}

	data, _ := io.ReadAll(reader)
	if string(data) != "file content here" {
		t.Errorf("unexpected content: %q", string(data))
	}
}

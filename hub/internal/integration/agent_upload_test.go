package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/agentclient"
)

// buildMultipartUpload creates a multipart form body for file upload testing.
func buildMultipartUpload(t *testing.T, filename string, content []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	mw.Close()
	return &buf, mw.FormDataContentType()
}

// doUpload performs a file upload and verifies the response matches expectations.
func doUpload(t *testing.T, h *TestHarness, serverID, token, filename string, content []byte) {
	t.Helper()
	buf, contentType := buildMultipartUpload(t, filename, content)

	uploadURL := fmt.Sprintf("http://%s/api/servers/%s/upload", h.HTTPAddr, serverID)
	req, err := http.NewRequest("POST", uploadURL, buf)
	if err != nil {
		t.Fatalf("create upload request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("upload request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("upload: status=%d body=%s", resp.StatusCode, body)
	}

	var result struct {
		Filename string `json:"filename"`
		Size     int64  `json:"size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}
	if result.Filename != filename {
		t.Fatalf("filename mismatch: got %q, want %q", result.Filename, filename)
	}
	if result.Size != int64(len(content)) {
		t.Fatalf("size mismatch: got %d, want %d", result.Size, len(content))
	}
	t.Logf("upload verified: filename=%s size=%d", result.Filename, result.Size)
}

// assertDropzoneContains verifies the dropzone listing contains the expected filename.
func assertDropzoneContains(t *testing.T, h *TestHarness, serverID, token, filename string) {
	t.Helper()
	resp := h.HTTPGet(t, fmt.Sprintf("/api/servers/%s/dropzone", serverID), token)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("list dropzone: status=%d body=%s", resp.StatusCode, body)
	}

	var result struct {
		Files []struct {
			Name string `json:"name"`
		} `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode dropzone response: %v", err)
	}

	for _, f := range result.Files {
		if f.Name == filename {
			t.Logf("dropzone list verified: %q present", filename)
			return
		}
	}
	t.Fatalf("expected %q in dropzone, got %+v", filename, result.Files)
}

// doDropzoneDelete deletes a file from the dropzone and asserts 204.
func doDropzoneDelete(t *testing.T, h *TestHarness, serverID, token, filename string) {
	t.Helper()
	deleteURL := fmt.Sprintf("http://%s/api/servers/%s/dropzone?filename=%s", h.HTTPAddr, serverID, filename)
	req, err := http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		t.Fatalf("create delete request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("delete dropzone file: status=%d body=%s", resp.StatusCode, body)
	}
	t.Logf("dropzone delete verified: %q removed (204 No Content)", filename)
}

func TestFileUploadThroughGRPC(t *testing.T) {
	h := StartHarness(t)
	token := h.SetupAdmin(t)
	serverID, regToken := h.CreateServer(t, token, "upload-server")

	agentClient := agentclient.New(agentclient.Config{
		HubAddr:      h.GRPCAddr,
		ServerID:     "",
		Token:        regToken,
		CertDir:      t.TempDir(),
		DropzoneDir:  t.TempDir(),
		Hostname:     "test-host",
		IPAddress:    "10.0.0.1",
		OS:           "linux",
		AgentVersion: "0.0.0-test",
		HubCAPin:     h.HubCAPin,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go agentClient.Run(ctx)

	if !waitForAgentConnect(h, serverID, 5*time.Second) {
		t.Fatal("agent did not connect within 5s")
	}

	uploadFilename := "integration-upload.txt"
	fileContent := []byte("upload integration test content")

	doUpload(t, h, serverID, token, uploadFilename, fileContent)
	assertDropzoneContains(t, h, serverID, token, uploadFilename)
	doDropzoneDelete(t, h, serverID, token, uploadFilename)
}

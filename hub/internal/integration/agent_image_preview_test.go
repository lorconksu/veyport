package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/wyiu/veyport/agent/agentclient"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestImagePreviewThroughGRPC(t *testing.T) {
	h := StartHarness(t)
	token := h.SetupAdmin(t)
	node, registration := h.CreateServer(t, token, "image-preview-test")
	root := t.TempDir()
	agent := agentclient.New(agentclient.Config{
		HubAddr: h.GRPCAddr, Token: registration, CertDir: t.TempDir(),
		Hostname: "test-host", OS: "linux", AgentVersion: "0.0.0-test", HubCAPin: h.HubCAPin,
	})
	ctx, cancel := context.WithCancel(context.Background())
	finished := runAgentInBackground(agent, ctx)
	defer func() { cancel(); waitForAgentExit(t, finished, 3*time.Second) }()
	if !waitForAgentConnect(h, node, 5*time.Second) {
		t.Fatal("agent did not connect")
	}

	pixel := image.NewRGBA(image.Rect(0, 0, 1, 1))
	pixel.SetRGBA(0, 0, color.RGBA{R: 128, G: 64, B: 255, A: 255})
	var pngImage, jpegImage bytes.Buffer
	if err := png.Encode(&pngImage, pixel); err != nil {
		t.Fatal(err)
	}
	if err := jpeg.Encode(&jpegImage, pixel, nil); err != nil {
		t.Fatal(err)
	}
	// A synthetic 1x1 lossless WebP generated with libwebp.
	webp, err := base64.StdEncoding.DecodeString("UklGRh4AAABXRUJQVlA4TBEAAAAvAAAAAAdQoAL2v/+BiOh/AAA=")
	if err != nil {
		t.Fatal(err)
	}
	// Two synthetic WebP animation frames generated with libwebp.
	animated, err := base64.StdEncoding.DecodeString("UklGRsAAAABXRUJQVlA4WAoAAAACAAAAAQAAAQAAQU5JTQYAAAD/////AABBTk1GSAAAAAAAAAAAAAEAAAEAAGQAAAJWUDggMAAAANABAJ0BKgIAAgACADQloAJ0ugH4AAOwAP7wxAv/ILlhdcjX/yA/5Af8gP/48gAAAEFOTUZEAAAAAAAAAAAAAQAAAQAAZAAAAFZQOCAsAAAA1AEAnQEqAgACAAAANCWgAnS6AfgAA7AA/vDo9/8guWF1yNf+bArmufmoAAA=")
	if err != nil {
		t.Fatal(err)
	}
	// A valid two-frame APNG with tiny synthetic color samples.
	animatedPNG, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAACGFjVEwAAAACAAAAAPONk3AAAAAaZmNUTAAAAAAAAAACAAAAAgAAAAAAAAAAAAEACgAA6FTcAAAAABRJREFUeJxjbHD4/5+BgYGBiQEKACmZAsIxc9nhAAAAGmZjVEwAAAABAAAAAgAAAAIAAAAAAAAAAAABAAoAAHMnNtQAAAAYZmRBVAAAAAJ4nGN0aPj/n4GBgYGJAQoAKVkCwhkTyIUAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	excessiveCanvas := bytes.Clone(pngImage.Bytes())
	binary.BigEndian.PutUint32(excessiveCanvas[16:20], 16_385)
	binary.BigEndian.PutUint32(excessiveCanvas[29:33], crc32.ChecksumIEEE(excessiveCanvas[12:29]))
	// Preserve container framing while damaging codec data. A browser may
	// otherwise render a blank frame and report that the image loaded.
	badPNG := corruptPreviewPNGData(pngImage.Bytes())
	jpegBytes := jpegImage.Bytes()
	scan := bytes.Index(jpegBytes, []byte{0xff, 0xda}) + 2
	scanData := scan + int(binary.BigEndian.Uint16(jpegBytes[scan:]))
	badJPEG := append(bytes.Clone(jpegBytes[:scanData]), 0xff, 0xd9)
	jpegWithTrailingData := append(bytes.Clone(jpegBytes), []byte("note")...)
	jpegWithTrailingData = append(jpegWithTrailingData, 0xff, 0xd9)
	// APP1's length encompasses the two end-marker bytes in its metadata.
	jpegWithMetadata := append([]byte{0xff, 0xd8, 0xff, 0xe1, 0x00, 0x04, 0xff, 0xd9}, jpegBytes[2:]...)
	badWebP := bytes.Clone(webp)
	clear(badWebP[25:])
	badAnimatedWebP := bytes.Clone(animated)
	lastFrame := bytes.LastIndex(badAnimatedWebP, []byte("VP8 ")) + 8
	// Keep the VP8 key-frame header and dimensions, but make its first
	// entropy partition run beyond the final frame's bitstream.
	badAnimatedWebP[lastFrame] |= 0xe0
	badAnimatedWebP[lastFrame+1], badAnimatedWebP[lastFrame+2] = 0xff, 0xff
	mismatchedFrame := bytes.Clone(animated)
	lastFrameHeader := bytes.LastIndex(mismatchedFrame, []byte("ANMF")) + 8
	mismatchedFrame[lastFrameHeader+6] = 0 // ANMF claims 1 pixel wide, VP8 still declares 2.
	outside := filepath.Join(t.TempDir(), "outside.png")
	if err := os.WriteFile(outside, pngImage.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link.png")); err != nil {
		t.Fatal(err)
	}
	large := sizedPreviewPNG(pngImage.Bytes(), 2<<20)
	boundary := sizedPreviewPNG(pngImage.Bytes(), 10<<20)
	cases := []struct {
		name   string
		file   string
		data   []byte
		mime   string
		status int
	}{
		{"multi-record PNG", "large.PNG", large, "image/png", http.StatusOK},
		{"exact limit", "boundary.png", boundary, "image/png", http.StatusOK},
		{"JPEG", "sample.jpeg", jpegImage.Bytes(), "image/jpeg", http.StatusOK},
		{"JPEG with framed metadata", "metadata.jpg", jpegWithMetadata, "image/jpeg", http.StatusOK},
		{"WebP", "sample.webp", webp, "image/webp", http.StatusOK},
		{"animated WebP", "animated.webp", animated, "image/webp", http.StatusOK},
		{"animated PNG", "animated.png", animatedPNG, "", http.StatusUnsupportedMediaType},
		{"excessive canvas", "canvas.png", excessiveCanvas, "", http.StatusUnsupportedMediaType},
		{"oversized", "oversized.png", sizedPreviewPNG(pngImage.Bytes(), (10<<20)+1), "", http.StatusRequestEntityTooLarge},
		{"corrupt PNG data", "bad-idat.png", badPNG, "", http.StatusUnsupportedMediaType},
		{"corrupt JPEG data", "bad-jpeg.jpg", badJPEG, "", http.StatusUnsupportedMediaType},
		{"bytes after JPEG end", "trailing.jpg", jpegWithTrailingData, "", http.StatusUnsupportedMediaType},
		{"corrupt WebP data", "bad-webp.webp", badWebP, "", http.StatusUnsupportedMediaType},
		{"corrupt animated WebP frame", "bad-animated.webp", badAnimatedWebP, "", http.StatusUnsupportedMediaType},
		{"mismatched animated WebP frame dimensions", "mismatched-frame.webp", mismatchedFrame, "", http.StatusUnsupportedMediaType},
		{"truncated PNG", "truncated.png", large[:len(large)-1], "", http.StatusUnsupportedMediaType},
		{"truncated JPEG", "truncated.jpg", jpegImage.Bytes()[:jpegImage.Len()-2], "", http.StatusUnsupportedMediaType},
		{"truncated WebP", "truncated.webp", webp[:len(webp)-1], "", http.StatusUnsupportedMediaType},
		{"format mismatch", "mismatch.png", jpegImage.Bytes(), "", http.StatusUnsupportedMediaType},
		{"renamed markup", "renamed.png", []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"/>"), "", http.StatusUnsupportedMediaType},
		{"unsupported extension", "markup.svg", []byte("<svg/>"), "", http.StatusUnsupportedMediaType},
		{"agent symlink guard", "link.png", nil, "", http.StatusForbidden},
		{"missing file", "missing.png", nil, "", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.file
			if !filepath.IsAbs(path) {
				path = filepath.Join(root, path)
				if tc.data != nil {
					if err := os.WriteFile(path, tc.data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			resp := h.HTTPGet(t, "/api/servers/"+node+"/files/image?path="+url.QueryEscape(path), token)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d, body length %d", resp.StatusCode, tc.status, len(body))
			}
			if tc.mime == "" {
				if got := resp.Header.Get("Content-Type"); got != "application/json" {
					t.Fatalf("error was exposed as %q", got)
				}
				return
			}
			if resp.Header.Get("Content-Type") != tc.mime || resp.Header.Get("Content-Length") != strconv.Itoa(len(tc.data)) ||
				resp.Header.Get("X-Content-Type-Options") != "nosniff" ||
				resp.Header.Get("Cache-Control") != "no-store, no-cache, must-revalidate" || !bytes.Equal(body, tc.data) {
				t.Fatalf("unexpected image response headers %v or bytes (got %d, want %d)", resp.Header, len(body), len(tc.data))
			}
		})
	}

	t.Run("requires authentication", func(t *testing.T) {
		resp := h.HTTPGet(t, "/api/servers/"+node+"/files/image?path="+url.QueryEscape(filepath.Join(root, "large.PNG")), "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated status %d", resp.StatusCode)
		}
	})

	action := model.AuditFileRead
	entries, total, err := h.Store.ListAuditLogs(model.AuditFilter{Action: &action, Limit: 20})
	if err != nil || total != 6 {
		t.Fatalf("successful previews should write exactly six file.read audit entries, got %d (%v)", total, err)
	}
	for _, entry := range entries {
		if entry.Target == nil || *entry.Target != node || entry.UserID == nil || entry.Detail == nil || filepath.Dir(*entry.Detail) != root {
			t.Fatalf("wrong audit entry: %#v", entry)
		}
	}

	t.Run("viewer path and node permissions", func(t *testing.T) {
		viewer := &model.User{ID: "viewer", Username: "viewer", Email: "viewer@synthetic.invalid", Role: model.RoleViewer, AuthProvider: model.AuthProviderLocal, TOTPEnabled: true}
		if err := h.Store.CreateUser(viewer); err != nil {
			t.Fatal(err)
		}
		viewerToken, hash, prefix, err := auth.GenerateAPIToken()
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Store.CreateAPIToken(&model.APIToken{ID: "preview-token", Name: "preview", UserID: viewer.ID, TokenHash: hash, TokenPrefix: prefix}); err != nil {
			t.Fatal(err)
		}
		other, _ := h.CreateServer(t, token, "other-preview-node")
		allowed := filepath.Join(root, "sample.jpeg")
		if _, err := h.Store.CreatePermission(viewer.ID, node, allowed); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			node, path string
			status     int
		}{
			{node, allowed, http.StatusOK},
			{node, filepath.Join(root, "sample.webp"), http.StatusForbidden},
			{other, allowed, http.StatusForbidden},
		} {
			resp := h.HTTPGet(t, "/api/servers/"+tc.node+"/files/image?path="+url.QueryEscape(tc.path), viewerToken)
			resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("viewer status %d on node %q, path %q, want %d", resp.StatusCode, tc.node, tc.path, tc.status)
			}
		}
	})

	t.Run("normal text tail", func(t *testing.T) {
		tail := bytes.Repeat([]byte("z"), 1<<20)
		full := append([]byte("prefix\n"), tail...)
		path := filepath.Join(root, "app.log")
		if err := os.WriteFile(path, full, 0600); err != nil {
			t.Fatal(err)
		}
		resp := h.HTTPGet(t, "/api/servers/"+node+"/files/read?path="+url.QueryEscape(path), token)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("text tail status %d", resp.StatusCode)
		}
		var result model.FileReadResult
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		data, err := base64.StdEncoding.DecodeString(result.Data)
		if err != nil || !bytes.Equal(data, tail) || result.TotalSize != int64(len(full)) || result.MimeType != "text/plain" {
			t.Fatalf("wrong text tail, size %d of %d, mime %q, error %v", len(data), result.TotalSize, result.MimeType, err)
		}
	})
}

// Put a CRC-valid private ancillary chunk before IEND without changing the raster.
func sizedPreviewPNG(original []byte, size int) []byte {
	chunkStart := len(original) - 12
	result := make([]byte, size)
	copy(result, original[:chunkStart])
	copy(result[size-12:], original[chunkStart:])
	binary.BigEndian.PutUint32(result[chunkStart:], uint32(size-len(original)-12))
	copy(result[chunkStart+4:], "vpAg")
	binary.BigEndian.PutUint32(result[size-16:], crc32.ChecksumIEEE(result[chunkStart+4:size-16]))
	return result
}

func corruptPreviewPNGData(original []byte) []byte {
	result := bytes.Clone(original)
	for offset := 8; offset < len(result)-12; {
		size := int(binary.BigEndian.Uint32(result[offset:]))
		end := offset + 8 + size
		if string(result[offset+4:offset+8]) == "IDAT" {
			clear(result[offset+8 : end])
			binary.BigEndian.PutUint32(result[end:], crc32.ChecksumIEEE(result[offset+4:end]))
			return result
		}
		offset = end + 4
	}
	panic("PNG fixture lacked image data")
}

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/wyiu/veyport/proto/fileview"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"golang.org/x/image/webp"
)

const (
	// Entropy decoding of a compact input can require large allocations.
	// These bounds also apply when a WebP frame is decoded independently.
	maxPreviewPixels          = 16 << 20
	maxPreviewAxis            = 16_384
	maxPreviewAnimationPixels = 64 << 20
	maxPreviewAnimationFrames = 256
	maxPreviewContainerChunks = 4096
	maxPreviewJPEGScans       = 32
	maxPreviewJPEGScanPixels  = 256 << 20
	imageDecoderWait          = 10 * time.Second
)

func (s *Server) handleImagePreview(w http.ResponseWriter, r *http.Request) {
	setup, cancel := context.WithTimeout(r.Context(), agentTimeoutDuration)
	defer cancel()
	path := r.URL.Query().Get("path")
	node := r.PathValue("id")
	if !s.checkFileRead(w, r, node, path, setup) {
		return
	}
	imageType := previewMIME(path)
	if imageType == "" {
		respondError(w, http.StatusUnsupportedMediaType, "only PNG, JPEG and WebP images can be previewed")
		return
	}
	select {
	case s.imagePreviewSlots <- struct{}{}:
		defer func() { <-s.imagePreviewSlots }()
	default:
		respondError(w, http.StatusServiceUnavailable, "image preview is busy; try again")
		return
	}

	// Bound the HTTP write window separately from the decoder's work limits.
	deadline := fileview.ImageTransferTimeout + agentTimeoutDuration + imageDecoderWait + 15*time.Second
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(deadline))

	resp := s.readFile(w, r, node, path, pb.FileReadMode_FILE_READ_MODE_IMAGE, setup)
	if resp == nil {
		return
	}
	if resp.ChunkOffset == nil {
		respondError(w, http.StatusConflict, "update the agent to preview images")
		return
	}
	data := resp.GetData()
	if !resp.GetDone() || resp.GetTotalSize() != int64(len(data)) || len(data) > fileview.MaxFileSize {
		respondError(w, http.StatusBadGateway, "incomplete or invalid agent response")
		return
	}
	valid, decodeErr := s.validatePreview(r.Context(), data, imageType)
	if r.Context().Err() != nil {
		return
	}
	if decodeErr != nil {
		respondError(w, http.StatusServiceUnavailable, "image preview validator is busy; try again")
		return
	}
	if !valid {
		respondError(w, http.StatusUnsupportedMediaType, "image is corrupt, unsupported, or exceeds the preview limits")
		return
	}
	s.auditFileRead(r, node, path)
	w.Header().Set("Content-Type", imageType)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(path)}))
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	_, _ = w.Write(data)
}

func previewMIME(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	default:
		return ""
	}
}

// Only slot admission is timed. In-process codecs can work between reads, so
// a request retains its slot until the bounded raster validation returns.
func (s *Server) validatePreview(ctx context.Context, data []byte, imageType string) (bool, error) {
	wait, cancel := context.WithTimeout(ctx, imageDecoderWait)
	defer cancel()
	select {
	case <-wait.Done():
		return false, wait.Err()
	case s.imageDecodeSlot <- struct{}{}:
		defer func() { <-s.imageDecodeSlot }()
	}
	if err := wait.Err(); err != nil {
		return false, err
	}
	cancel()
	valid := validImage(ctx, data, imageType)
	return valid, ctx.Err()
}

type previewReader struct {
	ctx context.Context
	io.Reader
}

func (r previewReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

func validImage(ctx context.Context, data []byte, imageType string) bool {
	if ctx.Err() != nil || len(data) > fileview.MaxFileSize || http.DetectContentType(data) != imageType {
		return false
	}
	reader := previewReader{ctx: ctx, Reader: bytes.NewReader(data)}
	switch imageType {
	case "image/png":
		if !completeStillPNG(ctx, data[8:]) {
			return false
		}
		cfg, err := png.DecodeConfig(reader)
		if err != nil || !previewDimensions(cfg.Width, cfg.Height) {
			return false
		}
		decoded, err := png.Decode(previewReader{ctx: ctx, Reader: bytes.NewReader(data)})
		return err == nil && decoded.Bounds().Size() == image.Pt(cfg.Width, cfg.Height)
	case "image/jpeg":
		return completeJPEG(ctx, data)
	case "image/webp":
		return completeWebP(ctx, data)
	default:
		return false
	}
}

func completeJPEG(ctx context.Context, data []byte) bool {
	input := previewReader{ctx: ctx, Reader: bytes.NewReader(data)}
	cfg, err := jpeg.DecodeConfig(input)
	if err != nil || !previewDimensions(cfg.Width, cfg.Height) {
		return false
	}
	scanLimit := min(maxPreviewJPEGScans, maxPreviewJPEGScanPixels/(cfg.Width*cfg.Height))
	if !completeJPEGEnvelope(ctx, data[2:], scanLimit) {
		return false
	}
	decoded, err := jpeg.Decode(previewReader{ctx: ctx, Reader: bytes.NewReader(data)})
	return err == nil && decoded.Bounds().Size() == image.Pt(cfg.Width, cfg.Height)
}

// Each JPEG scan can visit the entire raster, including progressive
// refinement requiring little compressed input. Count those passes before
// starting the codec, and require the actual end marker to end the file.
func completeJPEGEnvelope(ctx context.Context, data []byte, scanLimit int) bool {
	scans := 0
	for len(data) > 0 && ctx.Err() == nil {
		marker, rest := nextJPEGMarker(ctx, data)
		data = rest
		switch marker {
		case 0xd9:
			return scans > 0 && len(data) == 0
		case 0xd8:
			return false
		case 0xda:
			scans++
			if scans > scanLimit {
				return false
			}
		}
		if len(data) < 2 {
			break
		}
		segment := int(binary.BigEndian.Uint16(data[:2]))
		if segment < 2 || segment > len(data) {
			break
		}
		data = data[segment:]
	}
	return false
}

// Skip entropy-coded bytes, stuffed FF bytes, restart markers and FF fill.
// The caller skips length-delimited segments so metadata cannot add scans or
// mask the end of the actual codestream.
func nextJPEGMarker(ctx context.Context, data []byte) (byte, []byte) {
	for ctx.Err() == nil {
		at := bytes.IndexByte(data, 0xff)
		if at < 0 {
			return 0, nil
		}
		data = data[at+1:]
		for len(data) > 0 && data[0] == 0xff {
			data = data[1:]
		}
		if len(data) == 0 {
			return 0, nil
		}
		marker := data[0]
		data = data[1:]
		if marker != 0 && (marker < 0xd0 || marker > 0xd7) {
			return marker, data
		}
	}
	return 0, nil
}

func previewDimensions(width, height int) bool {
	return width > 0 && height > 0 && width <= maxPreviewAxis && height <= maxPreviewAxis && width*height <= maxPreviewPixels
}

func completeStillPNG(ctx context.Context, chunks []byte) bool {
	hasData := false
	for i := 0; i < maxPreviewContainerChunks && len(chunks) >= 12; i++ {
		if ctx.Err() != nil {
			return false
		}
		size := uint64(binary.BigEndian.Uint32(chunks))
		if size > uint64(len(chunks)-12) {
			return false
		}
		end := int(size) + 8
		if crc32.ChecksumIEEE(chunks[4:end]) != binary.BigEndian.Uint32(chunks[end:]) {
			return false
		}
		kind := string(chunks[4:8])
		switch kind {
		case "acTL", "fcTL", "fdAT":
			// The standard PNG decoder validates only the default image.
			// Refuse animation so every admitted raster is fully validated.
			return false
		case "IEND":
			return hasData && size == 0 && len(chunks) == 12
		}
		hasData = hasData || (kind == "IDAT" && size > 0)
		chunks = chunks[end+4:]
	}
	return false
}

// Validate the entire RIFF envelope and all coded rasters before exposing
// bytes. The browser gets the original container and playback metadata.
func completeWebP(ctx context.Context, data []byte) bool {
	if len(data) < 12 || uint64(binary.LittleEndian.Uint32(data[4:8]))+8 != uint64(len(data)) {
		return false
	}
	kind, payload, rest, ok := webPChunk(data[12:])
	if !ok {
		return false
	}
	layout := webPLayout{extended: kind == "VP8X"}
	if layout.extended {
		if len(payload) != 10 {
			return false
		}
		layout.width, layout.height = webPUint24(payload[4:])+1, webPUint24(payload[7:])+1
		if !previewDimensions(layout.width, layout.height) {
			return false
		}
		layout.animated = payload[0]&0x02 != 0
	} else {
		layout.width, layout.height = webPBitstreamDimensions(kind, payload)
		if !previewDimensions(layout.width, layout.height) {
			return false
		}
		layout.hasRaster = true
	}
	if !layout.complete(ctx, rest) {
		return false
	}
	if layout.animated {
		return true
	}
	decoded, err := webp.Decode(previewReader{ctx: ctx, Reader: bytes.NewReader(data)})
	return err == nil && decoded.Bounds().Size() == image.Pt(layout.width, layout.height)
}

type webPLayout struct {
	extended     bool
	animated     bool
	hasAnimation bool
	hasRaster    bool
	width        int
	height       int
	frames       int
	framePixels  int
}

func (layout webPLayout) complete(ctx context.Context, chunks []byte) bool {
	for count := 1; len(chunks) > 0; count++ {
		if count >= maxPreviewContainerChunks || ctx.Err() != nil {
			return false
		}
		kind, payload, rest, ok := webPChunk(chunks)
		if !ok || !layout.add(ctx, kind, payload) {
			return false
		}
		chunks = rest
	}
	return layout.hasRaster
}

func (layout *webPLayout) add(ctx context.Context, kind string, payload []byte) bool {
	switch kind {
	case "VP8X":
		return false
	case "ANIM":
		if !layout.animated || layout.hasAnimation || len(payload) != 6 {
			return false
		}
		layout.hasAnimation = true
	case "ANMF":
		return layout.addFrame(ctx, payload)
	case "VP8 ", "VP8L":
		width, height := webPBitstreamDimensions(kind, payload)
		if layout.hasRaster || layout.animated || !layout.extended || width != layout.width || height != layout.height {
			return false
		}
		layout.hasRaster = true
	}
	return true
}

func webPChunk(chunks []byte) (string, []byte, []byte, bool) {
	if len(chunks) < 8 {
		return "", nil, nil, false
	}
	size := uint64(binary.LittleEndian.Uint32(chunks[4:8]))
	end := uint64(8) + size
	padded := end + size%2
	if padded > uint64(len(chunks)) || (padded > end && chunks[end] != 0) {
		return "", nil, nil, false
	}
	return string(chunks[:4]), chunks[8:end], chunks[padded:], true
}

func (layout *webPLayout) addFrame(ctx context.Context, frame []byte) bool {
	if !layout.hasAnimation || len(frame) < 16 || layout.frames >= maxPreviewAnimationFrames {
		return false
	}
	x, y := 2*webPUint24(frame), 2*webPUint24(frame[3:])
	width, height := webPUint24(frame[6:])+1, webPUint24(frame[9:])+1
	if x+width > layout.width || y+height > layout.height {
		return false
	}
	pixels := width * height
	if pixels > maxPreviewAnimationPixels-layout.framePixels || !decodeWebPFrame(ctx, frame[16:], width, height) {
		return false
	}
	layout.frames++
	layout.framePixels += pixels
	layout.hasRaster = true
	return true
}

func decodeWebPFrame(ctx context.Context, chunks []byte, width, height int) bool {
	kind, data, rest, ok := webPChunk(chunks)
	alpha := kind == "ALPH"
	if ok && alpha {
		kind, data, rest, ok = webPChunk(rest)
	}
	codedWidth, codedHeight := webPBitstreamDimensions(kind, data)
	if !ok || codedWidth != width || codedHeight != height || !validWebPFrameExtras(ctx, rest, alpha) {
		return false
	}
	// The library accepts a still WebP. Wrap the original frame chunks in a
	// temporary RIFF header so its decoder also checks alpha and dimensions.
	var header [30]byte
	copy(header[:4], "RIFF")
	binary.LittleEndian.PutUint32(header[4:8], uint32(len(header)+len(chunks)-8))
	copy(header[8:16], "WEBPVP8X")
	binary.LittleEndian.PutUint32(header[16:20], 10)
	if alpha {
		header[20] = 0x10
	}
	putWebPUint24(header[24:27], width-1)
	putWebPUint24(header[27:30], height-1)
	input := io.MultiReader(bytes.NewReader(header[:]), bytes.NewReader(chunks))
	decoded, err := webp.Decode(previewReader{ctx: ctx, Reader: input})
	return err == nil && decoded.Bounds().Size() == image.Pt(width, height)
}

func validWebPFrameExtras(ctx context.Context, chunks []byte, hasAlpha bool) bool {
	count := 1
	if hasAlpha {
		count++
	}
	for ; len(chunks) > 0; count++ {
		if count >= maxPreviewContainerChunks || ctx.Err() != nil {
			return false
		}
		kind, _, rest, ok := webPChunk(chunks)
		if !ok || kind == "VP8 " || kind == "VP8L" || kind == "ALPH" || kind == "VP8X" {
			return false
		}
		chunks = rest
	}
	return true
}

func putWebPUint24(dst []byte, value int) {
	dst[0], dst[1], dst[2] = byte(value), byte(value>>8), byte(value>>16)
}

func webPUint24(data []byte) int {
	return int(data[0]) | int(data[1])<<8 | int(data[2])<<16
}

func webPBitstreamDimensions(kind string, data []byte) (int, int) {
	switch kind {
	case "VP8 ":
		if len(data) > 10 && data[0]&1 == 0 && bytes.Equal(data[3:6], []byte{0x9d, 0x01, 0x2a}) {
			width := int(binary.LittleEndian.Uint16(data[6:]) & 0x3fff)
			height := int(binary.LittleEndian.Uint16(data[8:]) & 0x3fff)
			return width, height
		}
	case "VP8L":
		if len(data) > 5 && data[0] == 0x2f {
			header := binary.LittleEndian.Uint32(data[1:5])
			if header>>29 == 0 {
				return int(header&0x3fff) + 1, int((header>>14)&0x3fff) + 1
			}
		}
	}
	return 0, 0
}

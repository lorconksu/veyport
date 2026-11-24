package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"image"
	"image/jpeg"
	"image/png"
	"testing"
)

// Pillow/libwebp encodings of 2 × 2 solid colors with translucency. The
// animation uses two frames of different colors, alpha and durations.
const translucentStillWebP = "UklGRloAAABXRUJQVlA4WAoAAAAQAAAAAQAAAQAAQUxQSAUAAAAAgICAgABWUDggLgAAANABAJ0BKgIAAgABQCYloAJ0ugH4AAOwAP7wG9//MEr8g3ah/9cB+cB+cB/KwAA="
const translucentAnimatedWebP = "UklGRuAAAABXRUJQVlA4WAoAAAASAAAAAQAAAQAAQU5JTQYAAAAAAAAAAABBTk1GVgAAAAAAAAAAAAEAAAEAAHgAAAJBTFBIBQAAAACAgICAAFZQOCAwAAAAMAEAnQEqAgACAAFAJiWgAANwAP7wG9///ME/9/v+/3m9//+uA//5wH//OA/lYAAAQU5NRlYAAAAAAAAAAAABAAABAAC0AAACQUxQSAUAAAAAwMDAwABWUDggMAAAADABAJ0BKgIAAgABQCYloAADcAD+34A//+LQ/t5/wa3Nf//taH/+1of/7Wh/JIAAAA=="

func decodePreviewFixture(t *testing.T, fixture string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(fixture)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPreviewRejectsIncompleteStillImages(t *testing.T) {
	img := image.NewGray(image.Rect(0, 0, 2, 2))
	var pngData, jpegData bytes.Buffer
	if err := png.Encode(&pngData, img); err != nil {
		t.Fatal(err)
	}
	if err := jpeg.Encode(&jpegData, img, nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mime string
		data []byte
	}{
		{"image/png", pngData.Bytes()},
		{"image/jpeg", jpegData.Bytes()},
		{"image/webp", decodePreviewFixture(t, translucentStillWebP)},
	} {
		t.Run(tc.mime, func(t *testing.T) {
			if !validImage(t.Context(), tc.data, tc.mime) {
				t.Fatal("complete still image was rejected")
			}
			for end := range len(tc.data) {
				if validImage(t.Context(), tc.data[:end], tc.mime) {
					t.Fatalf("accepted an incomplete file of %d out of %d bytes", end, len(tc.data))
				}
			}
		})
	}
}

func TestPreviewWebPContainerConformance(t *testing.T) {
	still := decodePreviewFixture(t, translucentStillWebP)
	animated := decodePreviewFixture(t, translucentAnimatedWebP)
	// RIFF header is 12 bytes, VP8X occupies 18 bytes including its
	// header, and ANIM occupies 14 bytes. Each ANMF starts with a
	// 16-byte frame descriptor followed by a complete raster.
	const headerEnd = 12
	const canvasEnd = 30
	const animationHeaderEnd = 44
	const firstFrameEnd = 138
	firstFrame := animated[animationHeaderEnd:firstFrameEnd]

	// WebP readers must ignore unknown chunks, including optional data
	// at the end of an animation frame. This odd-length chunk is padded.
	note := []byte("note\x03\x00\x00\x00abc\x00")
	frameWithNote := append(bytes.Clone(firstFrame), note...)
	binary.LittleEndian.PutUint32(frameWithNote[4:8], uint32(len(frameWithNote)-8))

	// Simulate files whose RIFF writer finalized the outer size even
	// though a part of the image or its metadata was missing.
	wrap := func(chunks ...[]byte) []byte {
		result := bytes.Clone(still[:headerEnd])
		for _, chunk := range chunks {
			result = append(result, chunk...)
		}
		binary.LittleEndian.PutUint32(result[4:8], uint32(len(result)-8))
		return result
	}
	for _, tc := range []struct {
		name string
		data []byte
		want bool
	}{
		{"extended still", still, true},
		{"animation with translucency", animated, true},
		{"unknown frame metadata", wrap(animated[headerEnd:animationHeaderEnd], frameWithNote, animated[firstFrameEnd:]), true},
		{"missing first chunk", wrap(), false},
		{"incomplete canvas chunk", wrap(still[headerEnd : canvasEnd-1]), false},
		{"incomplete raster chunk", wrap(still[headerEnd : len(still)-1]), false},
		{"incomplete metadata header", wrap(still[headerEnd:], note[:4]), false},
		{"missing metadata padding", wrap(still[headerEnd:], note[:len(note)-1]), false},
		{"animation header without frames", wrap(animated[headerEnd:animationHeaderEnd]), false},
		{"animation frame without animation header", wrap(animated[headerEnd:canvasEnd], firstFrame), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validImage(t.Context(), tc.data, "image/webp"); got != tc.want {
				t.Fatalf("WebP accepted = %v, want %v", got, tc.want)
			}
		})
	}
}

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/png"
	"testing"
)

func TestImageJPEGEnvelopeScanBudget(t *testing.T) {
	// The APP segment contains an EOI byte pair in its payload. Entropy
	// contains a stuffed FF and a restart marker. Only SOS counts as a pass.
	data := []byte{0xff, 0xe1, 0x00, 0x04, 0xff, 0xd9,
		0xff, 0xda, 0x00, 0x02, 0x10, 0xff, 0x00, 0xda, 0xff, 0xd0,
		0xff, 0xda, 0x00, 0x02, 0xff, 0xff, 0xd9}
	if !completeJPEGEnvelope(t.Context(), data, 2) {
		t.Fatal("JPEG envelope within scan budget was rejected")
	}
	if completeJPEGEnvelope(t.Context(), data, 1) {
		t.Fatal("JPEG envelope exceeding the scan budget was accepted")
	}
	if completeJPEGEnvelope(t.Context(), append(data, 0x00), 2) {
		t.Fatal("JPEG envelope with data after EOI was accepted")
	}
}

func TestImagePNGEnvelopeChunkLimit(t *testing.T) {
	var original bytes.Buffer
	if err := png.Encode(&original, image.NewGray(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	// The encoder emits IHDR, IDAT and IEND. A safe-to-copy private
	// ancillary chunk before IEND leaves the raster and CRCs unchanged.
	var metadata [12]byte
	copy(metadata[4:], "vpAg")
	binary.BigEndian.PutUint32(metadata[8:], crc32.ChecksumIEEE(metadata[4:8]))
	base := original.Bytes()
	for _, tc := range []struct {
		n     int
		valid bool
	}{{4096 - 3, true}, {4096 - 2, false}} {
		prefix := append([]byte(nil), base[:len(base)-12]...)
		data := append(prefix, bytes.Repeat(metadata[:], tc.n)...)
		data = append(data, base[len(base)-12:]...)
		if got := validImage(t.Context(), data, "image/png"); got != tc.valid {
			t.Errorf("metadata chunks=%d valid=%t, want %t", tc.n, got, tc.valid)
		}
	}
}

func TestImageNormalProgressiveJPEG(t *testing.T) {
	// A 12 × 12 grayscale gradient encoded by ImageMagick -interlace Plane.
	const fixture = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkI" +
		"CQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/wgALCAAMAAwBAREA/8QAFgABAQEAAAAA" +
		"AAAAAAAAAAAAAAYI/9oACAEBAAAAAYBtF//EABcQAQADAAAAAAAAAAAAAAAAAAAEFRb/2gAIAQEA" +
		"AQUCxbFqqEqoT//EABUQAQEAAAAAAAAAAAAAAAAAAAAz/9oACAEBAAY/ApJJpv/EABcQAAMBAAAA" +
		"AAAAAAAAAAAAAAAR8BD/2gAIAQEAAT8htFrSf//aAAgBAQAAABDP/8QAGBAAAgMAAAAAAAAAAAAA" +
		"AAAAAAER0fD/2gAIAQEAAT8QiMR1ao1ao//Z"
	data, err := base64.StdEncoding.DecodeString(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if !validImage(t.Context(), data, "image/jpeg") {
		t.Fatal("valid progressive JPEG was rejected")
	}
}

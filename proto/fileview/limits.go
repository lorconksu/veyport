// Package fileview defines the shared file-read transport limits.
package fileview

import "time"

const (
	// Small records let the agent serve shared control traffic between file writes.
	MaxChunkSize = 16 << 10
	MaxTailSize  = 1 << 20
	MaxFileSize  = 10 << 20

	FileDataIdleTimeout  = 15 * time.Second
	ImageTransferTimeout = 2 * time.Minute
)

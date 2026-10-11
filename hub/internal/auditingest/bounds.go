package auditingest

import "io"

// At most four ingest requests each hold a 16MiB body, one archive copy and one
// verification read, plus small envelopes. Fixed allocations keep the combined
// worst-case attachment budget below 192MiB, within a 256MiB application budget.
// The hub client streams attachments and does not use this ingestor budget.
func readExact(r io.Reader, n int64) ([]byte, error) {
	if n < 0 || n > 16<<20 {
		return nil, ErrUnavailable
	}
	b := make([]byte, n+1)
	read, err := io.ReadFull(r, b)
	if int64(read) != n || err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, ErrUnavailable
	}
	return b[:n], nil
}

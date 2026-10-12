package updateutil

import (
	"encoding/hex"
	"errors"
	"strings"
)

// BootstrapOriginal is an operator assertion about one exact unstamped binary.
// It is never release provenance or authority to replace a stamped build.
type BootstrapOriginal struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

func (o BootstrapOriginal) Present() bool { return o.Version != "" || o.SHA256 != "" }

func (o BootstrapOriginal) Validate() error {
	if !o.Present() {
		return nil
	}
	digest, err := hex.DecodeString(o.SHA256)
	if o.Version == "" || len(o.Version) >= 128 || ValidateVersion(o.Version) != nil || err != nil || len(digest) != 32 || o.SHA256 != strings.ToLower(o.SHA256) {
		return errors.New("bootstrap original assertion requires a comparable version and exact lowercase SHA256")
	}
	return nil
}

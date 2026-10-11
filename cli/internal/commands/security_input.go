package commands

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

const maxSecurityChangeBytes = 48 << 10

type securityInput struct {
	stdin      io.Reader
	terminal   *os.File
	readHidden func(int) ([]byte, error)
}

func (in securityInput) read(path string, limit int, private bool) ([]byte, error) {
	var reader io.Reader
	if path == "-" {
		reader = in.stdin
	} else {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, cmdutil.NewUsageError(errors.New("security input requires a regular file"))
		}
		// Nonblocking/no-follow open closes the replacement race after Lstat:
		// a swapped-in FIFO cannot block and a symlink cannot redirect a secret.
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, cmdutil.NewUsageError(errors.New("cannot open security input file"))
		}
		defer file.Close()
		info, err = file.Stat()
		if err != nil || !info.Mode().IsRegular() || (private && info.Mode().Perm()&0o077 != 0) {
			return nil, cmdutil.NewUsageError(errors.New("security input requires a regular file; secret files must have mode 0600 or stricter"))
		}
		reader = file
	}
	if reader == nil {
		return nil, cmdutil.NewUsageError(errors.New("security stdin is unavailable"))
	}
	raw, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil || len(raw) > limit || len(raw) == 0 {
		clear(raw)
		return nil, cmdutil.NewUsageError(errors.New("security input is empty, unreadable or exceeds its size limit"))
	}
	return raw, nil
}

func (in securityInput) secret(path string, limit int, label string, printer *cmdutil.Printer) (string, error) {
	var raw []byte
	var err error
	if path != "" {
		raw, err = in.read(path, limit, true)
	} else {
		if in.terminal == nil || !term.IsTerminal(int(in.terminal.Fd())) {
			return "", cmdutil.NewAuthError(errors.New("fresh MFA/secret input requires a terminal or an explicit private file/stdin input"))
		}
		printer.Errorf("%s (hidden): ", label)
		raw, err = in.readHidden(int(in.terminal.Fd()))
		printer.Errorf("\n")
		if err != nil || len(raw) == 0 || len(raw) > limit {
			clear(raw)
			return "", cmdutil.NewUsageError(errors.New("hidden security input failed or exceeds its size limit"))
		}
	}
	if err != nil {
		return "", err
	}
	defer clear(raw)
	return string(raw), nil
}

func (in securityInput) totp(path string, printer *cmdutil.Printer) (string, error) {
	code, err := in.secret(path, 64, "Fresh one-time MFA code", printer)
	if err != nil {
		return "", err
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return "", cmdutil.NewUsageError(errors.New("one-time MFA code must contain six digits"))
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return "", cmdutil.NewUsageError(errors.New("one-time MFA code must contain six digits"))
		}
	}
	return code, nil
}

func validSecurityDigest(digest string) bool {
	if len(digest) != 64 || strings.ToLower(digest) != digest {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

// Strict typed decoding prevents credentials accidentally placed in a payload
// from being echoed by a preview. Duplicate keys are refused at every depth.
func validateSecurityPayload(raw []byte) error {
	if len(raw) == 0 || len(raw) > maxSecurityChangeBytes || validateSecurityJSON(raw) != nil {
		return errors.New("invalid or oversized security change JSON")
	}
	var payload api.SecurityPayload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil {
		return errors.New("security change must use known typed fields and secret references; secret values are never accepted here")
	}
	canonical, _ := json.Marshal(payload)
	if bytes.Contains(canonical, []byte("PRIVATE KEY-----")) {
		return errors.New("private key material must use the write-only secret endpoint")
	}
	if payload.Policy != nil && !safeSecurityURL(payload.Policy.Destination) || payload.LDAP != nil && !safeSecurityURL(payload.LDAP.URL) {
		return errors.New("security endpoint URLs cannot contain credentials, query parameters or fragments")
	}
	switch payload.Kind {
	case "bootstrap", "policy", "role", "person", "recovery", "audit-settings", "ldap":
		return nil
	default:
		return errors.New("unsupported security change kind")
	}
}

func safeSecurityURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func securityCanonicalPayload(raw []byte) json.RawMessage {
	var payload api.SecurityPayload
	_ = json.Unmarshal(raw, &payload)
	canonical, _ := json.Marshal(payload)
	return canonical
}

func validateSecurityJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON nesting exceeds limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, nested := token.(json.Delim)
		if !nested {
			return nil
		}
		keys := map[string]bool{}
		for decoder.More() {
			if delim == '{' {
				key, err := decoder.Token()
				name, ok := key.(string)
				name = strings.ToLower(name)
				if err != nil || !ok || keys[name] {
					return errors.New("invalid or duplicate JSON key")
				}
				keys[name] = true
			}
			if err := value(depth + 1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func securityProposalDigest(proposal api.SecurityProposal) (string, error) {
	if strings.TrimSpace(proposal.Reason) == "" || len(proposal.Reason) > 2048 || proposal.ExpectedVersion == 0 {
		return "", errors.New("backend proposal omitted reason or expected version")
	}
	if err := validateSecurityPayload(proposal.Change); err != nil {
		return "", err
	}
	raw, _ := json.Marshal(proposal) // The validated raw change is valid JSON.
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func securityError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		message = strings.ReplaceAll(message, secret, "[redacted]")
		encoded, _ := json.Marshal(secret)
		message = strings.ReplaceAll(message, string(encoded[1:len(encoded)-1]), "[redacted]")
	}
	if len(message) > 2048 {
		message = "security operation failed; response diagnostic exceeded its size limit"
	}
	return cmdutil.NewCodedError(cmdutil.Code(err), fmt.Errorf("%s", message))
}

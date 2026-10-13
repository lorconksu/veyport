// Package executionidentity resolves the actual operating-system execution
// identity without launching the submitted command.
package executionidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const Path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

type Identity struct {
	Username      string
	UID           uint32
	GID           uint32
	Groups        []uint32
	Home          string
	Shell         string
	Cwd           string
	SetCredential bool `json:"-"`
}

type Resolver struct {
	LookupUser      func(string) (*osuser.User, error)
	LookupGroups    func(*osuser.User) ([]string, error)
	LookupNSSUser   func(string) (*osuser.User, error)
	LookupNSSGroups func(string) ([]string, error)
}

func DefaultResolver() Resolver {
	return Resolver{osuser.Lookup, func(u *osuser.User) ([]string, error) { return u.GroupIds() }, LookupUserWithGetent, LookupGroupIDsWithID}
}

// ResolveNamed preserves terminal NSS fallback behavior and numeric validation.
func (r Resolver) ResolveNamed(username string) (*Identity, error) {
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	u, err := r.LookupUser(username)
	var groups []string
	if err == nil {
		groups, err = r.LookupGroups(u)
		if err != nil {
			groups, err = r.LookupNSSGroups(username)
		}
	} else {
		u, err = r.LookupNSSUser(username)
		if err != nil {
			return nil, fmt.Errorf("execution user not available")
		}
		groups, err = r.LookupNSSGroups(username)
	}
	if err != nil {
		return nil, fmt.Errorf("execution user groups not available")
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("execution user has invalid uid")
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("execution user has invalid gid")
	}
	result := &Identity{Username: u.Username, UID: uint32(uid), GID: uint32(gid), Home: u.HomeDir, SetCredential: true}
	for _, g := range groups {
		parsed, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("execution user has invalid group")
		}
		result.Groups = append(result.Groups, uint32(parsed))
	}
	return result, nil
}

func Resolve(username, cwd string) (*Identity, error) {
	var identity *Identity
	var err error
	if username != "" {
		resolver := Resolver{LookupUser: LookupUserWithGetent, LookupGroups: func(u *osuser.User) ([]string, error) { return LookupGroupIDsWithID(u.Username) }, LookupNSSUser: LookupUserWithGetent, LookupNSSGroups: LookupGroupIDsWithID}
		identity, err = resolver.ResolveNamed(username)
	} else {
		u, lookupErr := LookupUserWithGetent(strconv.Itoa(os.Geteuid()))
		if lookupErr != nil {
			return nil, fmt.Errorf("current execution user not available")
		}
		groups, groupErr := os.Getgroups()
		if groupErr != nil {
			return nil, fmt.Errorf("current execution groups not available")
		}
		identity = &Identity{Username: u.Username, UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), Home: u.HomeDir}
		for _, g := range groups {
			identity.Groups = append(identity.Groups, uint32(g))
		}
	}
	if err != nil {
		return nil, err
	}
	identity.Shell, err = ResolveShell()
	if err != nil {
		return nil, err
	}
	if cwd == "" {
		cwd = identity.Home
	}
	if cwd == "" {
		return nil, fmt.Errorf("execution home not available")
	}
	identity.Cwd, err = WorkingDirectory(cwd)
	if err != nil {
		return nil, err
	}
	return identity, nil
}

func (i *Identity) Credential() *syscall.Credential {
	if !i.SetCredential {
		return nil
	}
	return &syscall.Credential{Uid: i.UID, Gid: i.GID, Groups: append([]uint32(nil), i.Groups...)}
}

// CredentialForExecution can inherit an identical effective identity. A
// non-root agent cannot call setgroups even to restore its existing groups.
// Interactive terminals continue using Credential and their established behavior.
func (i *Identity) CredentialForExecution() *syscall.Credential {
	if i.UID != uint32(os.Geteuid()) || i.GID != uint32(os.Getegid()) {
		return i.Credential()
	}
	current, err := os.Getgroups()
	if err != nil {
		return i.Credential()
	}
	actual := make([]uint32, len(current))
	for index, group := range current {
		actual[index] = uint32(group)
	}
	planned := append([]uint32(nil), i.Groups...)
	sort.Slice(actual, func(a, b int) bool { return actual[a] < actual[b] })
	sort.Slice(planned, func(a, b int) bool { return planned[a] < planned[b] })
	if len(actual) != len(planned) {
		return i.Credential()
	}
	for index, group := range actual {
		if planned[index] != group {
			return i.Credential()
		}
	}
	return nil
}
func (i *Identity) Digest() []byte {
	copyIdentity := *i
	copyIdentity.Groups = append([]uint32(nil), i.Groups...)
	sort.Slice(copyIdentity.Groups, func(a, b int) bool { return copyIdentity.Groups[a] < copyIdentity.Groups[b] })
	data, _ := json.Marshal(copyIdentity)
	hash := sha256.Sum256(data)
	return hash[:]
}
func (i *Identity) GroupsDigest() []byte {
	groups := append([]uint32(nil), i.Groups...)
	sort.Slice(groups, func(a, b int) bool { return groups[a] < groups[b] })
	data, _ := json.Marshal(groups)
	hash := sha256.Sum256(data)
	return hash[:]
}
func (i *Identity) Env() []string {
	return []string{"PATH=" + Path, "SHELL=" + i.Shell, "LANG=C.UTF-8", "USER=" + i.Username, "LOGNAME=" + i.Username, "HOME=" + i.Home}
}
func ResolveShell() (string, error) {
	for _, candidate := range []string{os.Getenv("SHELL"), "/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh"} {
		if candidate == "" || !filepath.IsAbs(candidate) {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no supported shell found on agent")
}
func WorkingDirectory(cwd string) (string, error) {
	cleaned := filepath.Clean(cwd)
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("execution cwd must be absolute")
	}
	info, err := os.Stat(cleaned)
	if err != nil {
		return "", fmt.Errorf("execution cwd not available")
	}
	if !info.IsDir() {
		return "", fmt.Errorf("execution cwd must be a directory")
	}
	return cleaned, nil
}
func LookupUserWithGetent(username string) (*osuser.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := boundedCommandOutput(ctx, "/usr/bin/getent", "passwd", username)
	if err != nil {
		return nil, err
	}
	line := strings.TrimSpace(string(output))
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	return ParsePasswd(line)
}
func ParsePasswd(line string) (*osuser.User, error) {
	fields := strings.Split(line, ":")
	if len(fields) < 7 || fields[0] == "" || fields[2] == "" || fields[3] == "" {
		return nil, fmt.Errorf("invalid passwd entry")
	}
	return &osuser.User{Username: fields[0], Uid: fields[2], Gid: fields[3], Name: fields[4], HomeDir: fields[5]}, nil
}
func LookupGroupIDsWithID(username string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := boundedCommandOutput(ctx, "/usr/bin/id", "-G", "--", username)
	if err != nil {
		return nil, err
	}
	return ParseGroups(string(output))
}

// NSS tools can fail or stall; neither their output nor their wait is unbounded.
type limitedOutput struct{ buffer bytes.Buffer }

func (b *limitedOutput) Write(data []byte) (int, error) {
	if b.buffer.Len()+len(data) > 64*1024 {
		return 0, fmt.Errorf("identity lookup output limit exceeded")
	}
	return b.buffer.Write(data)
}
func boundedCommandOutput(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	var output limitedOutput
	cmd.Stdout = &output
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return output.buffer.Bytes(), nil
}
func ParseGroups(output string) ([]string, error) {
	groups := strings.Fields(output)
	if len(groups) == 0 {
		return nil, fmt.Errorf("no groups found")
	}
	return groups, nil
}
func ValidateUsername(username string) error {
	if username == "" || len(username) > 128 || username[0] == '-' {
		return fmt.Errorf("invalid execution user")
	}
	for _, r := range username {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' || r == '@') {
			return fmt.Errorf("invalid execution user")
		}
	}
	return nil
}

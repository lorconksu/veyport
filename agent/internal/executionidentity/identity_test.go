package executionidentity

import (
	"bytes"
	"context"
	"errors"
	"os"
	osuser "os/user"
	"strings"
	"testing"
	"time"
)

func TestActualIdentityAndEnvironment(t *testing.T) {
	t.Setenv("VEYPORT_SECRET", "never-export")
	identity, err := Resolve("", "")
	if err != nil {
		t.Fatal(err)
	}
	if identity.UID != uint32(os.Geteuid()) || identity.GID != uint32(os.Getegid()) || identity.Username == "" || identity.Home == "" || identity.Cwd == "" || identity.Shell == "" || identity.Credential() != nil {
		t.Fatalf("actual identity: %+v", identity)
	}
	for _, entry := range identity.Env() {
		if strings.Contains(entry, "VEYPORT_SECRET") || strings.Contains(entry, "never-export") {
			t.Fatal("process secret inherited")
		}
	}
	if len(identity.Digest()) != 32 || len(identity.GroupsDigest()) != 32 {
		t.Fatal("missing digest")
	}
	copyIdentity := *identity
	copyIdentity.Groups = append([]uint32(nil), identity.Groups...)
	for i, j := 0, len(copyIdentity.Groups)-1; i < j; i, j = i+1, j-1 {
		copyIdentity.Groups[i], copyIdentity.Groups[j] = copyIdentity.Groups[j], copyIdentity.Groups[i]
	}
	if !bytes.Equal(identity.Digest(), copyIdentity.Digest()) {
		t.Fatal("group order changed identity digest")
	}
}
func TestNamedNSSFallbackAndNumericFailures(t *testing.T) {
	user := &osuser.User{Username: "ldap", Uid: "123", Gid: "456", HomeDir: "/home/ldap"}
	lookupError := errors.New("not found")
	resolver := Resolver{LookupUser: func(string) (*osuser.User, error) { return nil, lookupError }, LookupGroups: func(*osuser.User) ([]string, error) { return nil, lookupError }, LookupNSSUser: func(string) (*osuser.User, error) { return user, nil }, LookupNSSGroups: func(string) ([]string, error) { return []string{"456", "789"}, nil }}
	identity, err := resolver.ResolveNamed("ldap")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Credential().Uid != 123 || identity.Credential().Gid != 456 || len(identity.Credential().Groups) != 2 {
		t.Fatalf("credential: %+v", identity)
	}
	resolver.LookupUser = func(string) (*osuser.User, error) { return user, nil }
	if _, err = resolver.ResolveNamed("ldap"); err != nil {
		t.Fatal(err)
	}
	user.Uid = "bad"
	if _, err = resolver.ResolveNamed("ldap"); err == nil {
		t.Fatal("bad uid accepted")
	}
	user.Uid = "123"
	user.Gid = "bad"
	if _, err = resolver.ResolveNamed("ldap"); err == nil {
		t.Fatal("bad gid accepted")
	}
	user.Gid = "456"
	resolver.LookupNSSGroups = func(string) ([]string, error) { return []string{"bad"}, nil }
	if _, err = resolver.ResolveNamed("ldap"); err == nil {
		t.Fatal("bad groups accepted")
	}
	resolver.LookupNSSGroups = func(string) ([]string, error) { return nil, lookupError }
	if _, err = resolver.ResolveNamed("ldap"); err == nil {
		t.Fatal("missing groups accepted")
	}
	resolver.LookupUser = func(string) (*osuser.User, error) { return nil, lookupError }
	resolver.LookupNSSUser = func(string) (*osuser.User, error) { return nil, lookupError }
	if _, err = resolver.ResolveNamed("ldap"); err == nil {
		t.Fatal("missing user accepted")
	}
}
func TestIdentityValidationAndFixedNSSPaths(t *testing.T) {
	for _, username := range []string{"", "-bad", "bad:group", "bad user", "bad/user", strings.Repeat("x", 129)} {
		if err := ValidateUsername(username); err == nil {
			t.Fatalf("unsafe username %q accepted", username)
		}
	}
	if err := ValidateUsername("alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePasswd("bad"); err == nil {
		t.Fatal("bad passwd accepted")
	}
	if _, err := ParseGroups("  \n"); err == nil {
		t.Fatal("empty groups accepted")
	}
	user, err := ParsePasswd("ldap:*:123:456:LDAP:/home/ldap:/bin/bash")
	if err != nil || user.HomeDir != "/home/ldap" {
		t.Fatalf("passwd: %+v %v", user, err)
	}
	if _, err := LookupGroupIDsWithID("veyport-definitely-missing-user"); err == nil {
		t.Fatal("missing id accepted")
	}
	if _, err := LookupUserWithGetent("veyport-definitely-missing-user"); err == nil {
		t.Fatal("missing getent user accepted")
	}
	current, err := Resolve("", "")
	if err != nil {
		t.Fatal(err)
	}
	named, err := Resolve(current.Username, t.TempDir())
	if err != nil || named.Credential() == nil {
		t.Fatalf("named: %+v %v", named, err)
	}
}
func TestWorkingDirectoryAndShellValidation(t *testing.T) {
	if _, err := WorkingDirectory("relative"); err == nil {
		t.Fatal("relative cwd accepted")
	}
	if _, err := WorkingDirectory("/veyport-definitely-missing-dir"); err == nil {
		t.Fatal("missing cwd accepted")
	}
	file := t.TempDir() + "/file"
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := WorkingDirectory(file); err == nil {
		t.Fatal("file cwd accepted")
	}
	t.Setenv("SHELL", file)
	shell, err := ResolveShell()
	if err != nil || shell == file {
		t.Fatal("nonexecutable shell accepted")
	}
	if _, err := Resolve("", "relative"); err == nil {
		t.Fatal("bad cwd resolved")
	}
}
func TestNSSCommandOutputAndDeadlineAreBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := boundedCommandOutput(ctx, "/bin/sh", "-c", "sleep 30"); err == nil {
		t.Fatal("unbounded lookup succeeded")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("lookup deadline did not bound wait")
	}
	if _, err := boundedCommandOutput(context.Background(), "/bin/sh", "-c", "head -c 100000 /dev/zero"); err == nil {
		t.Fatal("oversized lookup output accepted")
	}
}

func TestExecutionInheritsOnlyExactlyMatchingCredentials(t *testing.T) {
	identity, err := Resolve("", "")
	if err != nil {
		t.Fatal(err)
	}
	identity.SetCredential = true
	if identity.Credential() == nil {
		t.Fatal("terminal credential behavior changed")
	}
	if identity.CredentialForExecution() != nil {
		t.Fatal("matching execution identity attempted setgroups")
	}
	identity.Groups = append(identity.Groups, 987654)
	if identity.CredentialForExecution() == nil {
		t.Fatal("different groups silently inherited")
	}
	identity.UID++
	if identity.CredentialForExecution() == nil {
		t.Fatal("different uid silently inherited")
	}
}

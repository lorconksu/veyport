package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"golang.org/x/sys/unix"
)

// ValidateBootstrapConfig rejects alternate identities and Hub destinations.
// The public HTTPS source must be the configured enrolled Hub host.
func ValidateBootstrapConfig(publicHub, enrolledHub string) error {
	if err := ValidateHelperFiles(); err != nil {
		return err
	}
	return validateBootstrapSource(publicHub, enrolledHub)
}

func validateBootstrapSource(publicHub, enrolledHub string) error {
	u, err := url.Parse(publicHub)
	host, _, hostErr := net.SplitHostPort(enrolledHub)
	if hostErr != nil {
		return errors.New("invalid enrolled Hub address")
	}
	if err != nil || u.Scheme != "https" || u.Hostname() != host || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("bootstrap source must be the configured HTTPS Hub")
	}
	return nil
}

func ValidateHelperFiles() error {
	return validateHelperFiles(fixedPaths(), os.Geteuid())
}

func validateHelperFiles(p paths, uid int) error {
	if uid != 0 {
		return errors.New("agent update requires sudo")
	}
	if err := p.checkDir(p.journalDir, true); err != nil {
		return errors.New("canonical enrolled TLS directory is not protected")
	}
	for _, path := range []string{p.config, filepath.Join(p.journalDir, "client.key"), filepath.Join(p.journalDir, "client.crt"), filepath.Join(p.journalDir, "ca.crt")} {
		f, err := p.open(path, unix.O_RDONLY, 0, true)
		if err != nil {
			return errors.New("canonical enrolled identity is not protected")
		}
		_ = f.Close()
	}
	return nil
}

// Bootstrap upgrades an old enrolled agent without registration or reenrollment.
// The ticket only selects a Hub-owned operation; all authority is independently
// checked over the existing enrolled mTLS identity.
func Bootstrap(ctx context.Context, ticket, version, revision string, service pb.AgentServiceClient) error {
	if os.Geteuid() != 0 || runtime.GOOS != "linux" || len(ticket) < 32 || len(ticket) > 512 {
		return errors.New("invalid agent update bootstrap")
	}
	p := fixedPaths()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return bootstrap(ctx, p, ticket, version, revision, service, executable, runCommand)
}

func bootstrap(ctx context.Context, p paths, ticket, version, revision string, service pb.AgentServiceClient, executable string, launch func(context.Context, string, ...string) error) error {
	original, err := p.installedMetadata()
	if err != nil {
		return err
	}
	if err := p.checkDir(p.journalDir, true); err != nil {
		return err
	}
	caps := &pb.UpdateCapabilities{ProtocolVersion: 1, Os: "linux", Arch: runtime.GOARCH, Version: original.Version, Revision: original.Revision, Sha256: original.SHA256, BootId: bootID(), Supported: true}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := service.BootstrapUpdate(ctx, &pb.UpdateBootstrapRequest{Ticket: ticket, Capabilities: caps})
	if err != nil {
		return errors.New("Hub refused enrolled update bootstrap")
	}
	entry, err := requestRecord(req, original)
	if err != nil {
		return err
	}
	if entry.Target.Version != version || entry.Target.Revision != revision {
		return errors.New("bootstrap candidate does not match the authorized Hub release")
	}
	// The script's temporary directory must be private, on the canonical binary
	// filesystem. The executable is independently verified against the mTLS RPC.
	if filepath.Dir(filepath.Dir(executable)) != filepath.Dir(p.binary) || filepath.Base(executable) != "candidate" {
		return errors.New("bootstrap candidate must use private canonical staging")
	}
	if err := p.checkDir(filepath.Dir(executable), true); err != nil {
		return err
	}
	if err := p.verify(executable, entry.Target, true); err != nil {
		return err
	}
	owner, err := p.lock("agent-update-supervisor.lock")
	if err != nil {
		return errors.New("another tracked update supervisor is still active")
	}
	defer owner.Close()
	lock, err := p.lock("agent-update.lock")
	if err != nil {
		return err
	}
	previous, err := p.read()
	// A fresh Hub-issued ticket is only available after its explicit recovery
	// acknowledgement. Retire a legacy rollback journal only after its helper's
	// full expiry/cooldown and exact original binary checks; never delete it by
	// treating age alone as authorization.
	recovered := canSupersede(previous, original, entry.Operation)
	if err != nil || (previous != nil && previous.active() && !recovered) {
		_ = lock.Close()
		return errors.New("update journal requires recovery before bootstrap")
	}
	if err := p.write(entry); err != nil {
		_ = lock.Close()
		return err
	}
	_ = lock.Close()
	started := false
	defer func() {
		if started {
			return
		}
		if lock, err := p.lock("agent-update.lock"); err == nil {
			entry.State = "failed"
			_ = p.write(entry)
			_ = lock.Close()
		}
		if p.checkDir(p.stage(entry.Operation), true) == nil {
			_ = os.Remove(p.candidate(entry.Operation))
			_ = os.Remove(p.stage(entry.Operation))
			_ = syncDirectory(filepath.Dir(p.binary))
		}
	}()
	if err := os.Mkdir(p.stage(entry.Operation), 0700); err != nil {
		return err
	}
	destination, err := p.open(p.candidate(entry.Operation), unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0600, true)
	if err != nil {
		return err
	}
	source, err := p.open(executable, unix.O_RDONLY, 0, true)
	if err != nil {
		_ = destination.Close()
		return err
	}
	_, err = io.Copy(destination, io.LimitReader(source, entry.Target.Bytes+1))
	_ = source.Close()
	if err == nil {
		err = destination.Sync()
	}
	_ = destination.Close()
	if err != nil {
		return err
	}
	r := &Runtime{paths: p, launch: runCommand, budget: sessionlimit.New(8), capabilities: caps}
	if err := r.finishStaging(entry); err != nil {
		return err
	}
	_ = owner.Close()
	if err := launch(ctx, "/usr/bin/systemd-run", "--unit=veyport-agent-update-"+entry.Operation, "--collect", "--service-type=exec", "--property=RuntimeMaxSec=180", "--property=TimeoutStopSec=5", "--property=SendSIGKILL=yes", "--property=KillMode=control-group", "--property=UMask=0077", "--property=Restart=no", "--", p.candidate(entry.Operation), "--update-supervisor", entry.Operation); err != nil {
		return err
	}
	started = true
	fmt.Printf("Agent update %s staged; check vey servers update <node> --status for Hub-confirmed reconnection.\n", entry.Operation)
	return nil
}

func canSupersede(previous *record, current Metadata, newOperation string) bool {
	return previous != nil && previous.Operation != newOperation && (previous.State == "rolled_back" || previous.State == "rolling_back" || previous.State == "downloading" || previous.State == "staged") && !previous.Confirmed && time.Now().UnixMilli() > previous.Expires+190000 && sameIdentity(current, previous.Original)
}

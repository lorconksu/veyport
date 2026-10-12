package update

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/wyiu/veyport/agent/internal/sessionlimit"
	"github.com/wyiu/veyport/proto/updateutil"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

type Runtime struct {
	mu              sync.Mutex
	paths           paths
	capabilities    *pb.UpdateCapabilities
	budget          *sessionlimit.Budget
	lease           bool
	launch          func(context.Context, string, ...string) error
	config, certDir string
	insecure        bool
	host            hostEnvironment
}

func bootID() string {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return ""
	}
	return hex.EncodeToString(data)
}

func runCommand(ctx context.Context, program string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/root"}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("update service command failed: %w", err)
	}
	return nil
}

func New(version, revision, config, certDir string, insecure bool, budget *sessionlimit.Budget) *Runtime {
	executable, _ := os.Executable()
	runningExecutable := executable
	if runtime.GOOS == "linux" {
		runningExecutable = "/proc/self/exe"
	}
	return newRuntime(version, revision, config, certDir, insecure, budget, hostEnvironment{paths: fixedPaths(), executable: executable, runningExecutable: runningExecutable, uid: os.Geteuid(), os: runtime.GOOS, arch: runtime.GOARCH})
}

type hostEnvironment struct {
	paths             paths
	executable        string
	runningExecutable string
	uid               int
	os, arch          string
}

func newRuntime(version, revision, config, certDir string, insecure bool, budget *sessionlimit.Budget, host hostEnvironment) *Runtime {
	r := &Runtime{paths: host.paths, budget: budget, launch: runCommand, config: config, certDir: certDir, insecure: insecure, host: host, capabilities: &pb.UpdateCapabilities{ProtocolVersion: 1, ActivityQuiescenceVersion: 1, Os: host.os, Arch: host.arch, Version: version, Revision: revision, BootId: bootID()}}
	actualExecutable := host.runningExecutable
	if actualExecutable == "" {
		actualExecutable = host.executable
	}
	if executable := actualExecutable; executable != "" {
		if f, err := os.Open(executable); err == nil {
			hash, _, err := hashFile(f)
			_ = f.Close()
			if err == nil {
				r.capabilities.Sha256 = hash
			}
		}
	}
	if host.os != "linux" || (host.arch != "amd64" && host.arch != "arm64") {
		r.capabilities.Reason = "update requires Linux amd64 or arm64"
		return r
	}
	if host.uid != 0 {
		r.capabilities.Reason = "update requires a root-owned system service"
		return r
	}
	if config != host.paths.config || filepath.Clean(certDir) != host.paths.journalDir || insecure {
		r.capabilities.Reason = "update requires the canonical enrolled mTLS installation"
		return r
	}
	if host.executable != host.paths.binary {
		r.capabilities.Reason = "agent is not running from the canonical binary path"
		return r
	}
	if err := r.checkInstallation(); err != nil {
		r.capabilities.Reason = err.Error()
		return r
	}
	installed, err := r.paths.installedMetadata()
	if err != nil || installed.Version != version || installed.Revision != revision || installed.SHA256 != r.capabilities.Sha256 || revision == "unknown" || r.capabilities.BootId == "" {
		r.capabilities.Reason = "installed agent build identity cannot be verified"
		return r
	}
	journal, err := r.paths.read()
	if err != nil {
		r.capabilities.Reason = "update journal requires operator recovery"
		return r
	}
	if journal != nil && journal.active() {
		if !budget.TryMaintenance() {
			r.capabilities.Reason = "update maintenance lease unavailable"
			return r
		}
		r.lease = true
	}
	r.capabilities.Supported = true
	return r
}

func (r *Runtime) checkInstallation() error {
	if err := r.paths.checkDir(r.paths.journalDir, true); err != nil {
		return fmt.Errorf("update TLS directory is not protected")
	}
	f, err := r.paths.open(r.paths.config, unix.O_RDONLY, 0, true)
	if err != nil {
		return fmt.Errorf("update configuration is not protected")
	}
	_ = f.Close()
	if info, err := os.Stat(r.paths.systemdDir); err != nil || !info.IsDir() {
		return fmt.Errorf("update requires systemd")
	}
	for _, path := range []string{r.paths.systemdRun, r.paths.systemctl} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return fmt.Errorf("update requires systemd service tools")
		}
	}
	return nil
}

func (r *Runtime) Capabilities() *pb.UpdateCapabilities {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := proto.Clone(r.capabilities).(*pb.UpdateCapabilities)
	c.ActiveActivities = r.budget.ActivityCount()
	return c
}

// Recheck supports the first registration reconnect: configuration and issued
// certificates may not exist when the process initially constructs its client.
// The boot identity stays stable for the entire process, including reconnects.
func (r *Runtime) Recheck() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.capabilities.Supported {
		return
	}
	next := newRuntime(r.capabilities.Version, r.capabilities.Revision, r.config, r.certDir, r.insecure, r.budget, r.host)
	next.capabilities.BootId = r.capabilities.BootId
	r.capabilities = next.capabilities
	r.lease = next.lease
}

func requestRecord(req *pb.AgentUpdateRequest, original Metadata) (record, error) {
	if req == nil {
		return record{}, errors.New("missing update request")
	}
	r := record{Schema: 1, Operation: req.OperationId, Target: Metadata{Version: req.Version, Revision: req.Revision, SHA256: req.Sha256, Bytes: req.Bytes}, Original: original, Expires: req.ExpiresUnixMilli, State: "downloading"}
	if err := r.validate(); err != nil {
		return record{}, err
	}
	if time.Until(time.UnixMilli(r.Expires)) <= 0 || time.Until(time.UnixMilli(r.Expires)) > 15*time.Minute {
		return record{}, errors.New("update operation expired or unbounded")
	}
	comparison, err := updateutil.CompareVersions(r.Target.Version, r.Original.Version)
	if err != nil || comparison <= 0 {
		return record{}, errors.New("update does not advance the installed version")
	}
	return r, nil
}

func (r *Runtime) status(op, state, reason string) *pb.AgentUpdateStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.statusLocked(op, state, reason)
}

func (r *Runtime) statusLocked(op, state, reason string) *pb.AgentUpdateStatus {
	return &pb.AgentUpdateStatus{OperationId: op, State: state, Reason: reason, Version: r.capabilities.Version, Revision: r.capabilities.Revision, Sha256: r.capabilities.Sha256, BootId: r.capabilities.BootId}
}

// Begin downloads and stages one exact Hub operation. Its bounded worker owns
// the admission lease until the supervisor takes over or preparation fails.
func (r *Runtime) Begin(ctx context.Context, req *pb.AgentUpdateRequest, service pb.AgentServiceClient, emit func(*pb.AgentUpdateStatus)) {
	r.mu.Lock()
	op := ""
	if req != nil {
		op = req.OperationId
	}
	failed := func(reason string) { emit(r.status(op, "failed", reason)) }
	if !r.capabilities.Supported {
		reason := r.capabilities.Reason
		r.mu.Unlock()
		failed(reason)
		return
	}
	previousLease := false
	if r.lease {
		previous, err := r.paths.read()
		current := Metadata{Version: r.capabilities.Version, Revision: r.capabilities.Revision, SHA256: r.capabilities.Sha256}
		previousLease = err == nil && canSupersede(previous, current, op)
	}
	if (r.lease && !previousLease) || (!r.lease && !r.budget.TryMaintenance()) {
		r.mu.Unlock()
		failed("agent has active work or another update")
		return
	}
	r.lease = true
	r.mu.Unlock()
	supervised := false
	replacedIntent := false
	defer func() {
		if !supervised {
			if !previousLease || replacedIntent {
				r.releaseLease()
			}
			if replacedIntent && operationPattern.MatchString(op) && r.paths.checkDir(r.paths.stage(op), true) == nil {
				_ = os.Remove(r.paths.candidate(op))
				_ = os.Remove(r.paths.stage(op))
				_ = syncDirectory(filepath.Dir(r.paths.binary))
			}
		}
	}()
	original, err := r.paths.installedMetadata()
	if err != nil {
		failed("installed binary cannot be verified")
		return
	}
	entry, err := requestRecord(req, original)
	if err != nil {
		failed(err.Error())
		return
	}
	owner, err := r.paths.lock("agent-update-supervisor.lock")
	if err != nil {
		failed("another tracked update supervisor is still active")
		return
	}
	defer owner.Close()
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(entry.Expires))
	defer cancel()
	ctx, boundedCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer boundedCancel()
	lock, err := r.paths.lock("agent-update.lock")
	if err != nil {
		failed(err.Error())
		return
	}
	previous, err := r.paths.read()
	if err != nil || (previous != nil && ((previous.active() && !canSupersede(previous, original, op)) || previous.Operation == op)) {
		_ = lock.Close()
		failed("update journal is active, stale, or requires recovery")
		return
	}
	if err = r.paths.write(entry); err != nil {
		_ = lock.Close()
		failed("cannot persist update intent")
		return
	}
	replacedIntent = true
	_ = lock.Close()
	markFailed := func(reason string) {
		lock, lockErr := r.paths.lock("agent-update.lock")
		if lockErr == nil {
			entry.State = "failed"
			_ = r.paths.write(entry)
			_ = lock.Close()
		}
		failed(reason)
	}
	emit(r.status(op, "downloading", ""))
	if err := r.download(ctx, service, entry); err != nil {
		markFailed(err.Error())
		return
	}
	if err := r.finishStaging(entry); err != nil {
		markFailed(err.Error())
		return
	}
	_ = owner.Close()
	// A supervisor is tracked by systemd, with a hard time bound and no restart.
	// It repeats artifact and live Hub authorization checks before stopping us.
	if err := r.launch(ctx, "/usr/bin/systemd-run", "--unit=veyport-agent-update-"+op, "--collect", "--service-type=exec", "--property=RuntimeMaxSec=180", "--property=TimeoutStopSec=5", "--property=SendSIGKILL=yes", "--property=KillMode=control-group", "--property=UMask=0077", "--property=Restart=no", "--", r.paths.candidate(op), "--update-supervisor", op); err != nil {
		markFailed("cannot start tracked update supervisor")
		return
	}
	supervised = true
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		journal, err := r.paths.read()
		if err == nil && journal != nil && journal.Operation == op && journal.State == "failed" {
			r.releaseLease()
			failed("update supervisor refused installation")
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Runtime) releaseLease() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lease {
		r.budget.EndMaintenance()
		r.lease = false
	}
}

func (r *Runtime) download(ctx context.Context, service pb.AgentServiceClient, entry record) error {
	if err := os.Mkdir(r.paths.stage(entry.Operation), 0700); err != nil {
		return fmt.Errorf("cannot create private update staging directory")
	}
	if err := syncDirectory(filepath.Dir(r.paths.binary)); err != nil {
		return err
	}
	f, err := r.paths.open(r.paths.candidate(entry.Operation), unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0600, true)
	if err != nil {
		return err
	}
	defer f.Close()
	stream, err := service.DownloadUpdate(ctx, &pb.UpdateArtifactRequest{OperationId: entry.Operation})
	if err != nil {
		return fmt.Errorf("authenticated update download unavailable")
	}
	var received int64
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("update download interrupted")
		}
		if chunk == nil || len(chunk.Data) == 0 || len(chunk.Data) > 64<<10 || chunk.Offset != received || int64(len(chunk.Data)) > entry.Target.Bytes-received {
			return fmt.Errorf("invalid update artifact stream")
		}
		if _, err := f.Write(chunk.Data); err != nil {
			return err
		}
		received += int64(len(chunk.Data))
	}
	if received != entry.Target.Bytes {
		return fmt.Errorf("update download truncated")
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return r.paths.verify(r.paths.candidate(entry.Operation), entry.Target, true)
}

func (r *Runtime) finishStaging(entry record) error {
	if err := r.paths.verify(r.paths.candidate(entry.Operation), entry.Target, true); err != nil {
		return err
	}
	f, err := r.paths.open(r.paths.candidate(entry.Operation), unix.O_RDONLY, 0, true)
	if err != nil {
		return err
	}
	if err = f.Chmod(0700); err == nil {
		err = f.Sync()
	}
	_ = f.Close()
	if err != nil {
		return err
	}
	if err = syncDirectory(r.paths.stage(entry.Operation)); err != nil {
		return err
	}
	lock, err := r.paths.lock("agent-update.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	entry.State = "staged"
	return r.paths.write(entry)
}

// ResumeStatus only describes the exact installed bytes of this operation.
// An interrupted or unrelated journal can never certify a successful update.
func (r *Runtime) ResumeStatus() *pb.AgentUpdateStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, err := r.paths.read()
	if err != nil || entry == nil {
		return nil
	}
	current := Metadata{Version: r.capabilities.Version, Revision: r.capabilities.Revision, SHA256: r.capabilities.Sha256}
	if entry.State == "failed" && sameIdentity(current, entry.Original) {
		if r.lease {
			r.budget.EndMaintenance()
			r.lease = false
		}
		return r.statusLocked(entry.Operation, "failed", "update preparation or supervisor failed before replacement")
	}
	if entry.Confirmed {
		if entry.State == "succeeded" && sameIdentity(current, entry.Target) {
			return r.statusLocked(entry.Operation, "confirmed", "")
		}
		if entry.State == "rolled_back" && sameIdentity(current, entry.Original) {
			return r.statusLocked(entry.Operation, "rollback_confirmed", "")
		}
		return nil
	}
	if (entry.State == "reconnecting" || entry.State == "installing") && sameIdentity(current, entry.Target) {
		return r.statusLocked(entry.Operation, "reconnecting", "")
	}
	if (entry.State == "rolled_back" || entry.State == "rolling_back") && sameIdentity(current, entry.Original) {
		return r.statusLocked(entry.Operation, "rolled_back", "")
	}
	return nil
}

func sameIdentity(a, b Metadata) bool {
	return a.Version == b.Version && a.Revision == b.Revision && a.SHA256 == b.SHA256
}

func (r *Runtime) Confirm(confirmation *pb.UpdateConfirmation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if confirmation == nil {
		return errors.New("missing update confirmation")
	}
	lock, err := r.paths.lock("agent-update.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	entry, err := r.paths.read()
	if err != nil || entry == nil || entry.Operation != confirmation.OperationId {
		return errors.New("stale update confirmation")
	}
	current := Metadata{Version: r.capabilities.Version, Revision: r.capabilities.Revision, SHA256: r.capabilities.Sha256}
	if entry.Confirmed && ((confirmation.State == "succeeded" && entry.State == "succeeded" && sameIdentity(current, entry.Target)) || (confirmation.State == "rolled_back" && entry.State == "rolled_back" && sameIdentity(current, entry.Original))) {
		return nil
	}
	if confirmation.State == "succeeded" && (entry.State == "reconnecting" || entry.State == "installing") && sameIdentity(current, entry.Target) {
		entry.State = "succeeded"
	} else if confirmation.State == "rolled_back" && (entry.State == "rolling_back" || entry.State == "rolled_back") && sameIdentity(current, entry.Original) {
		entry.State = "rolled_back"
	} else {
		return errors.New("update confirmation does not match running artifact")
	}
	entry.Confirmed = true
	if err := r.paths.write(*entry); err != nil {
		return err
	}
	if r.lease {
		r.budget.EndMaintenance()
		r.lease = false
	}
	return nil
}

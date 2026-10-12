package update

import (
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/wyiu/veyport/proto/updateutil"
	"golang.org/x/sys/unix"
)

const agentPackage = "github.com/wyiu/veyport/agent/cmd/veyport-agent"

func verifyELF(f *os.File, arch string) error {
	e, err := elf.NewFile(f)
	if err != nil {
		return fmt.Errorf("agent artifact is not ELF: %w", err)
	}
	if e.Class != elf.ELFCLASS64 || e.Data != elf.ELFDATA2LSB || (e.Type != elf.ET_EXEC && e.Type != elf.ET_DYN) {
		return fmt.Errorf("unsupported agent ELF format")
	}
	if (arch == "amd64" && e.Machine != elf.EM_X86_64) || (arch == "arm64" && e.Machine != elf.EM_AARCH64) || (arch != "amd64" && arch != "arm64") {
		return fmt.Errorf("agent ELF platform mismatch")
	}
	return nil
}

func (p paths) verify(path string, expected Metadata, strict bool) error {
	f, err := p.open(path, unix.O_RDONLY, 0, false)
	if err != nil {
		return err
	}
	defer f.Close()
	hash, size, err := hashFile(f)
	if err != nil {
		return err
	}
	if hash != expected.SHA256 || size != expected.Bytes {
		return fmt.Errorf("agent artifact checksum or size mismatch")
	}
	if err := verifyELF(f, runtime.GOARCH); err != nil {
		return err
	}
	if strict {
		// Verify the exact descriptor whose bytes were hashed, rather than reopening
		// a possibly replaced path. Privileged staging files are never shared.
		return updateutil.VerifyBuildIdentity(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), agentPackage, "linux", runtime.GOARCH, expected.Version, expected.Revision)
	}
	return nil
}

func (p paths) installedMetadata() (Metadata, error) {
	f, err := p.open(p.binary, unix.O_RDONLY, 0, false)
	if err != nil {
		return Metadata{}, err
	}
	defer f.Close()
	hash, size, err := hashFile(f)
	if err != nil {
		return Metadata{}, err
	}
	if err := verifyELF(f, runtime.GOARCH); err != nil {
		return Metadata{}, err
	}
	info, err := buildinfo.Read(f)
	if err != nil || info.Path != agentPackage {
		return Metadata{}, fmt.Errorf("installed binary is not the agent")
	}
	settings := make(map[string]string)
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != runtime.GOARCH {
		return Metadata{}, fmt.Errorf("installed agent platform mismatch")
	}
	metadata := Metadata{SHA256: hash, Bytes: size, Revision: "unknown"}
	fields := strings.Fields(settings["-ldflags"])
	for i := 0; i < len(fields); i++ {
		value := ""
		if fields[i] == "-X" && i+1 < len(fields) {
			i++
			value = fields[i]
		} else if strings.HasPrefix(fields[i], "-X=") {
			value = strings.TrimPrefix(fields[i], "-X=")
		}
		name, stamp, _ := strings.Cut(strings.Trim(value, "'\""), "=")
		if name == "main.version" {
			if metadata.Version != "" {
				return Metadata{}, fmt.Errorf("duplicate installed version")
			}
			metadata.Version = stamp
		}
		if name == "main.revision" {
			if metadata.Revision != "unknown" {
				return Metadata{}, fmt.Errorf("duplicate installed revision")
			}
			metadata.Revision = stamp
		}
	}
	if metadata.Version == "" {
		return Metadata{}, fmt.Errorf("installed agent has no version stamp")
	}
	return metadata, nil
}

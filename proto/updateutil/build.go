package updateutil

import (
	"debug/buildinfo"
	"fmt"
	"strings"
)

// VerifyBuildIdentity checks the embedded Go package, platform and exact
// linker stamps without executing downloaded code. Callers first authenticate
// the byte digest and size against their trusted distribution metadata.
func VerifyBuildIdentity(path, packagePath, osName, arch, version, revision string) error {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read update binary build information: %w", err)
	}
	if info.Path != packagePath {
		return fmt.Errorf("update binary package differs from the approved component")
	}
	settings := make(map[string]string)
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	if settings["GOOS"] != osName || settings["GOARCH"] != arch {
		return fmt.Errorf("update binary platform differs from approved metadata")
	}
	actualVersion, actualRevision, err := linkerIdentity(settings["-ldflags"])
	if err != nil || actualVersion != version || actualRevision != revision {
		return fmt.Errorf("update binary version or revision differs from approved metadata")
	}
	return nil
}

func linkerIdentity(flags string) (string, string, error) {
	var version, revision string
	fields := strings.Fields(flags)
	for i := 0; i < len(fields); i++ {
		var value string
		if fields[i] == "-X" && i+1 < len(fields) {
			i++
			value = fields[i]
		} else if strings.HasPrefix(fields[i], "-X=") {
			value = strings.TrimPrefix(fields[i], "-X=")
		} else {
			continue
		}
		name, v, ok := strings.Cut(strings.Trim(value, "'\""), "=")
		if !ok {
			continue
		}
		switch name {
		case "main.version":
			if version != "" {
				return "", "", fmt.Errorf("duplicate binary version stamp")
			}
			version = v
		case "main.revision":
			if revision != "" {
				return "", "", fmt.Errorf("duplicate binary revision stamp")
			}
			revision = v
		}
	}
	return version, revision, nil
}

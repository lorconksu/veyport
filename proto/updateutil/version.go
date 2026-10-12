// Package updateutil shares release identity checks across update components.
package updateutil

import (
	"cmp"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var semanticVersion = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$`)
var historicalVersion = regexp.MustCompile(`^(v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))-([1-9][0-9]*)-g[0-9a-f]{7,64}-staging$`)

type parsedVersion struct {
	core  [3]uint64
	pre   []string
	ahead uint64
}

func parseVersion(raw string) (parsedVersion, error) {
	var result parsedVersion
	if len(raw) > 128 || strings.Contains(raw, "dirty") {
		return result, fmt.Errorf("version %q is not a comparable release version", raw)
	}
	if legacy := historicalVersion.FindStringSubmatch(raw); legacy != nil {
		base, err := parseVersion(legacy[1])
		if err != nil {
			return result, err
		}
		base.ahead, err = strconv.ParseUint(legacy[2], 10, 64)
		return base, err
	}
	parts := semanticVersion.FindStringSubmatch(raw)
	if parts == nil {
		return result, fmt.Errorf("version %q is not a comparable release version; install a versioned release explicitly", raw)
	}
	for i := range result.core {
		n, err := strconv.ParseUint(parts[i+1], 10, 64)
		if err != nil {
			return result, fmt.Errorf("version %q exceeds supported numeric bounds", raw)
		}
		result.core[i] = n
	}
	var err error
	result.pre, err = versionIdentifiers(raw, parts[4], true)
	if err != nil {
		return result, err
	}
	_, err = versionIdentifiers(raw, parts[5], false)
	if err != nil {
		return result, err
	}
	return result, nil
}

func versionIdentifiers(raw, group string, prerelease bool) ([]string, error) {
	if group == "" {
		return nil, nil
	}
	ids := strings.Split(group, ".")
	for _, id := range ids {
		if id == "" {
			return nil, fmt.Errorf("version %q contains an empty identifier", raw)
		}
		if prerelease && isNumeric(id) && len(id) > 1 && id[0] == '0' {
			return nil, fmt.Errorf("version %q contains a numeric prerelease with a leading zero", raw)
		}
	}
	return ids, nil
}

func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// ValidateVersion refuses builds whose ordering cannot be established.
func ValidateVersion(version string) error {
	_, err := parseVersion(version)
	return err
}

// CompareVersions compares SemVer releases and the historical staging
// git-describe format. A historical build sorts after its base release and
// before the next patch; dev, dirty and unversioned builds are refused.
func CompareVersions(a, b string) (int, error) {
	x, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	y, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	for i := range x.core {
		if order := cmp.Compare(x.core[i], y.core[i]); order != 0 {
			return order, nil
		}
	}
	if x.ahead != 0 || y.ahead != 0 {
		return cmp.Compare(x.ahead, y.ahead), nil
	}
	return comparePrerelease(x.pre, y.pre), nil
}

func comparePrerelease(x, y []string) int {
	if len(x) == 0 || len(y) == 0 {
		return cmp.Compare(len(y), len(x))
	}
	for i := 0; i < min(len(x), len(y)); i++ {
		if order := compareIdentifier(x[i], y[i]); order != 0 {
			return order
		}
	}
	return cmp.Compare(len(x), len(y))
}

func compareIdentifier(p, q string) int {
	pn, qn := isNumeric(p), isNumeric(q)
	if pn && qn && len(p) != len(q) {
		return cmp.Compare(len(p), len(q))
	}
	if pn != qn {
		if pn {
			return -1
		}
		return 1
	}
	return strings.Compare(p, q)
}

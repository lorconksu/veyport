package updateutil

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v2.0.50-prototype.4", "v2.0.50-prototype.3", 1},
		{"2.0.50-prototype.10", "v2.0.50-prototype.9", 1},
		{"2.0.50-prototype.3", "2.0.50", -1},
		{"2.0.50", "2.0.50-prototype.3", 1},
		{"2.0.50+build.123", "v2.0.50+build.456", 0},
		{"v2.0.28-11-g1234567-staging", "v2.0.50-prototype.4", -1},
		{"v2.0.28-11-g1234567-staging", "v2.0.28", 1},
		{"v2.0.28-11-g1234567-staging", "v2.0.28-12-g1234567-staging", -1},
		{"v2.0.28-11-g1234567-staging", "v2.0.29-alpha.1", -1},
		{"0.1.0", "v2.0.50-prototype.3", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"1.0.0-123456789012345678901234567890", "1.0.0-9", 1},
	}
	for _, c := range cases {
		t.Run(c.a+"_"+c.b, func(t *testing.T) {
			got, err := CompareVersions(c.a, c.b)
			if err != nil || got != c.want {
				t.Fatalf("CompareVersions=%d,%v; want %d", got, err, c.want)
			}
			reverse, err := CompareVersions(c.b, c.a)
			if err != nil || reverse != -c.want {
				t.Fatalf("reverse comparison=%d,%v", reverse, err)
			}
		})
	}
}

func TestRefuseUnknownAndMalformedVersions(t *testing.T) {
	for _, v := range []string{"", "dev", "unknown", "215b560", "v2.0.50-dirty", "v2.0.50-prototype.03", "v02.0.50", "1.0.0-alpha..1", "1.0.0+build..1", "1.2", " 1.2.3", "1.2.18446744073709551616", "1.2.3<script>", "v2.0.28-11-g215b560-staging-dirty"} {
		t.Run(v, func(t *testing.T) {
			if err := ValidateVersion(v); err == nil {
				t.Fatal("accepted invalid version")
			}
			if _, err := CompareVersions("2.0.50", v); err == nil {
				t.Fatal("comparison accepted invalid version")
			}
		})
	}
}

func TestLinkerIdentityRejectsAmbiguousStamps(t *testing.T) {
	for _, flags := range []string{"-X main.version=1.2.3 -X main.version=1.2.4", "-X main.revision=abc -X=main.revision=def"} {
		if _, _, err := linkerIdentity(flags); err == nil {
			t.Fatal("duplicate linker identity accepted")
		}
	}
	v, r, err := linkerIdentity("-s -w -X main.version=1.2.3 -X=main.revision=abc")
	if err != nil || v != "1.2.3" || r != "abc" {
		t.Fatalf("linkerIdentity=%q,%q,%v", v, r, err)
	}
}

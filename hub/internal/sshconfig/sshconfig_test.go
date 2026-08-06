package sshconfig

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name     string
		dbConfig map[string]string
		flagAddr string
		want     Config
	}{
		{
			name:     "all defaults when DB and flag absent",
			dbConfig: nil,
			flagAddr: "",
			want:     Config{Enabled: true, Addr: DefaultAddr, CertTTLHours: 12},
		},
		{
			name:     "flag fallback for addr when DB absent",
			dbConfig: nil,
			flagAddr: ":2223",
			want:     Config{Enabled: true, Addr: ":2223", CertTTLHours: 12},
		},
		{
			name: "DB value wins over flag and defaults",
			dbConfig: map[string]string{
				"ssh_gateway_enabled": "false",
				"ssh_addr":            ":9999",
				"ssh_cert_ttl_hours":  "6",
			},
			flagAddr: ":2223",
			want:     Config{Enabled: false, Addr: ":9999", CertTTLHours: 6},
		},
		{
			name: "DB addr wins even without a flag value",
			dbConfig: map[string]string{
				"ssh_addr": ":9999",
			},
			flagAddr: "",
			want:     Config{Enabled: true, Addr: ":9999", CertTTLHours: 12},
		},
		{
			name: "invalid enabled falls back to default",
			dbConfig: map[string]string{
				"ssh_gateway_enabled": "not-a-bool",
			},
			flagAddr: "",
			want:     Config{Enabled: true, Addr: DefaultAddr, CertTTLHours: 12},
		},
		{
			name: "invalid ttl falls back to default",
			dbConfig: map[string]string{
				"ssh_cert_ttl_hours": "not-a-number",
			},
			flagAddr: "",
			want:     Config{Enabled: true, Addr: DefaultAddr, CertTTLHours: 12},
		},
		{
			name: "zero ttl falls back to default",
			dbConfig: map[string]string{
				"ssh_cert_ttl_hours": "0",
			},
			flagAddr: "",
			want:     Config{Enabled: true, Addr: DefaultAddr, CertTTLHours: 12},
		},
		{
			name: "negative ttl falls back to default",
			dbConfig: map[string]string{
				"ssh_cert_ttl_hours": "-5",
			},
			flagAddr: "",
			want:     Config{Enabled: true, Addr: DefaultAddr, CertTTLHours: 12},
		},
		{
			name: "empty addr in DB falls back to flag",
			dbConfig: map[string]string{
				"ssh_addr": "",
			},
			flagAddr: ":2224",
			want:     Config{Enabled: true, Addr: ":2224", CertTTLHours: 12},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := testStore(t)
			for k, v := range tt.dbConfig {
				if err := st.SetConfig(k, v); err != nil {
					t.Fatalf("seed config %q: %v", k, err)
				}
			}

			got := Load(st, tt.flagAddr)
			if got != tt.want {
				t.Errorf("Load() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

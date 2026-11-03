package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/store"
)

const persistenceStorageKey = "ca-persistence-test-storage-key"

func newCAStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}
func setCAConfig(t *testing.T, st *store.Store, key, value string) {
	t.Helper()
	if err := st.SetConfig(key, value); err != nil {
		t.Fatal(err)
	}
}
func caFixture(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	cert, key, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, der
}
func requireCAFailure(t *testing.T, st *store.Store, contains string) {
	t.Helper()
	cert, key, err := InitCA(st, persistenceStorageKey)
	if err == nil || cert != nil || key != nil || !strings.Contains(err.Error(), contains) {
		t.Fatalf("InitCA = cert present %t, key present %t, error %v; want %q", cert != nil, key != nil, err, contains)
	}
}
func TestInitCAPersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.db")
	st, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := InitCA(st, persistenceStorageKey)
	if err != nil {
		_ = st.Close()
		t.Fatal(err)
	}
	certHex, err := st.GetConfig("ca_cert")
	if err != nil {
		t.Fatal(err)
	}
	keyHex, err := st.GetConfig("ca_key")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := auth.Decrypt(encrypted, auth.DeriveKey(persistenceStorageKey))
	if err != nil {
		t.Fatal(err)
	}
	loadedKey, err := x509.ParseECPrivateKey(raw)
	if err != nil || !loadedKey.Equal(key) {
		t.Fatalf("stored encrypted key mismatch: %v", err)
	}
	if certHex != hex.EncodeToString(cert.Raw) {
		t.Fatal("stored cert mismatch")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	reloadedCert, reloadedKey, err := InitCA(st, persistenceStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reloadedCert.Raw, cert.Raw) || !reloadedKey.Equal(key) {
		t.Fatal("CA identity changed on reload")
	}
}
func TestInitCALegacyMigration(t *testing.T) {
	st := newCAStore(t)
	cert, key, der := caFixture(t)
	setCAConfig(t, st, "ca_cert", hex.EncodeToString(cert.Raw))
	setCAConfig(t, st, "ca_key", hex.EncodeToString(der))
	loadedCert, loadedKey, err := InitCA(st, persistenceStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loadedCert.Raw, cert.Raw) || !loadedKey.Equal(key) {
		t.Fatal("legacy identity changed")
	}
	value, err := st.GetConfig("ca_key")
	if err != nil {
		t.Fatal(err)
	}
	if value == hex.EncodeToString(der) {
		t.Fatal("legacy key remained plaintext")
	}
	encrypted, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := auth.Decrypt(encrypted, auth.DeriveKey(persistenceStorageKey))
	if err != nil || !bytes.Equal(decrypted, der) {
		t.Fatalf("migrated key: %v", err)
	}
	againCert, againKey, err := InitCA(st, persistenceStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(againCert.Raw, cert.Raw) || !againKey.Equal(key) {
		t.Fatal("migration reload changed identity")
	}
}
func TestInitCALegacyMigrationWriteFailure(t *testing.T) {
	st := newCAStore(t)
	cert, _, der := caFixture(t)
	setCAConfig(t, st, "ca_cert", hex.EncodeToString(cert.Raw))
	setCAConfig(t, st, "ca_key", hex.EncodeToString(der))
	_, err := st.DB().Exec(`CREATE TRIGGER reject_ca_key BEFORE INSERT ON _config WHEN NEW.key = 'ca_key' BEGIN SELECT RAISE(ABORT, 'injected key write failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	requireCAFailure(t, st, "store migrated CA key")
	value, err := st.GetConfig("ca_key")
	if err != nil || value != hex.EncodeToString(der) {
		t.Fatalf("legacy value changed on failed migration: %v", err)
	}
}
func TestInitCAReadFailureDoesNotReplaceIdentity(t *testing.T) {
	for _, brokenKey := range []string{"ca_cert", "ca_key"} {
		t.Run(brokenKey, func(t *testing.T) {
			st := newCAStore(t)
			cert, _, err := InitCA(st, persistenceStorageKey)
			if err != nil {
				t.Fatal(err)
			}
			// A nullable replacement table simulates corrupted stored values:
			// reading the selected key fails Scan, while UPSERT remains writable.
			for _, sql := range []string{
				`ALTER TABLE _config RENAME TO original_config`,
				`CREATE TABLE _config (key TEXT PRIMARY KEY, value TEXT)`,
				`INSERT INTO _config SELECT key, value FROM original_config`,
				`UPDATE _config SET value = NULL WHERE key = '` + brokenKey + `'`,
			} {
				if _, err := st.DB().Exec(sql); err != nil {
					t.Fatal(err)
				}
			}
			loaded, key, err := InitCA(st, persistenceStorageKey)
			if err == nil {
				t.Fatalf("read failure returned success; original trust root replaced: %t", !bytes.Equal(cert.Raw, loaded.Raw))
			}
			if loaded != nil || key != nil || !strings.Contains(err.Error(), "load CA "+strings.TrimPrefix(brokenKey, "ca_")) {
				t.Fatalf("read failure = %v", err)
			}
			var untouched bool
			if err := st.DB().QueryRow(`SELECT value IS NULL FROM _config WHERE key = ?`, brokenKey).Scan(&untouched); err != nil || !untouched {
				t.Fatalf("failed read caused stored identity writes: %v", err)
			}
		})
	}
}
func TestInitCARejectsIncompleteIdentity(t *testing.T) {
	for _, values := range []map[string]string{
		{"ca_cert": "cert only"}, {"ca_key": "key only"},
		{"ca_cert": "", "ca_key": ""}, {"ca_cert": "cert", "ca_key": ""}, {"ca_cert": "", "ca_key": "key"},
	} {
		st := newCAStore(t)
		for key, value := range values {
			setCAConfig(t, st, key, value)
		}
		requireCAFailure(t, st, "incomplete stored CA")
		for key, expected := range values {
			actual, err := st.GetConfig(key)
			if err != nil || actual != expected {
				t.Fatalf("incomplete CA overwritten: %v", err)
			}
		}
	}
}
func TestInitCACreationWriteFailureRollsBack(t *testing.T) {
	for _, rejectedKey := range []string{"ca_cert", "ca_key"} {
		t.Run(rejectedKey, func(t *testing.T) {
			st := newCAStore(t)
			_, err := st.DB().Exec(`CREATE TRIGGER reject_ca_write BEFORE INSERT ON _config WHEN NEW.key = '` + rejectedKey + `' BEGIN SELECT RAISE(ABORT, 'injected CA write failure'); END`)
			if err != nil {
				t.Fatal(err)
			}
			requireCAFailure(t, st, "store CA "+strings.TrimPrefix(rejectedKey, "ca_"))
			for _, key := range []string{"ca_cert", "ca_key"} {
				_, present, err := st.LookupConfig(key)
				if err != nil || present {
					t.Fatalf("partial CA persisted for %s: present %t, error %v", key, present, err)
				}
			}
			if _, err := st.DB().Exec(`DROP TRIGGER reject_ca_write`); err != nil {
				t.Fatal(err)
			}
			if _, _, err := InitCA(st, persistenceStorageKey); err != nil {
				t.Fatalf("retry after failed transaction: %v", err)
			}
		})
	}
}
func TestInitCARejectsCorruptOrMismatchedIdentity(t *testing.T) {
	cert, _, der := caFixture(t)
	otherCert, _, _ := caFixture(t)
	encrypted, err := auth.Encrypt(der, auth.DeriveKey(persistenceStorageKey))
	if err != nil {
		t.Fatal(err)
	}
	invalidDER, err := auth.Encrypt([]byte("invalid private key DER"), auth.DeriveKey(persistenceStorageKey))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, cert, key, want string }{
		{"cert hex", "zz", hex.EncodeToString(encrypted), "decode CA cert hex"},
		{"cert DER", "00", hex.EncodeToString(encrypted), "parse CA cert"},
		{"key hex", hex.EncodeToString(cert.Raw), "zz", "decode CA key hex"},
		{"key DER", hex.EncodeToString(cert.Raw), "00", "parse CA key"},
		{"encrypted invalid DER", hex.EncodeToString(cert.Raw), hex.EncodeToString(invalidDER), "parse CA key"},
		{"mismatch encrypted", hex.EncodeToString(otherCert.Raw), hex.EncodeToString(encrypted), "does not match"},
		{"mismatch legacy", hex.EncodeToString(otherCert.Raw), hex.EncodeToString(der), "does not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newCAStore(t)
			setCAConfig(t, st, "ca_cert", tc.cert)
			setCAConfig(t, st, "ca_key", tc.key)
			requireCAFailure(t, st, tc.want)
			actual, err := st.GetConfig("ca_key")
			if err != nil || actual != tc.key {
				t.Fatalf("corrupt/mismatched key mutated: %v", err)
			}
		})
	}
	t.Run("wrong storage secret", func(t *testing.T) {
		st := newCAStore(t)
		setCAConfig(t, st, "ca_cert", hex.EncodeToString(cert.Raw))
		setCAConfig(t, st, "ca_key", hex.EncodeToString(encrypted))
		loadedCert, loadedKey, err := InitCA(st, "incorrect-secret")
		if err == nil || loadedCert != nil || loadedKey != nil {
			t.Fatal("wrong storage secret accepted")
		}
	})
}
func TestCertificateSigningRejectsMismatchedCA(t *testing.T) {
	cert, _, _ := caFixture(t)
	_, otherKey, _ := caFixture(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if signed, err := SignCSR(cert, otherKey, csr, "agent", time.Hour); err == nil || signed != nil {
		t.Fatal("mismatched CA signed CSR")
	}
	if signed, key, err := GenerateServerCert(cert, otherKey, "hub"); err == nil || signed != nil || key != nil {
		t.Fatal("mismatched CA signed server certificate")
	}
}
func TestInitCAConcurrentCreationPreservesWinningIdentity(t *testing.T) {
	st := newCAStore(t)
	const workers = 8
	results := make(chan *x509.Certificate, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			<-start
			cert, _, err := InitCA(st, persistenceStorageKey)
			if err == nil {
				results <- cert
			}
		})
	}
	close(start)
	wg.Wait()
	close(results)
	cert, _, err := InitCA(st, persistenceStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for result := range results {
		count++
		if !bytes.Equal(result.Raw, cert.Raw) {
			t.Fatal("successful concurrent initialization returned a different trust root")
		}
	}
	if count == 0 {
		t.Fatal("no initializer succeeded")
	}
}

func TestInitCAClosedStore(t *testing.T) {
	st := newCAStore(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	requireCAFailure(t, st, "begin CA initialization")
}

func TestInitCACommitFailureRollsBack(t *testing.T) {
	st := newCAStore(t)
	for _, statement := range []string{
		`CREATE TABLE ca_commit_parent (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE ca_commit_child (parent INTEGER REFERENCES ca_commit_parent(id) DEFERRABLE INITIALLY DEFERRED)`,
		`CREATE TRIGGER reject_ca_commit AFTER INSERT ON _config WHEN NEW.key = 'ca_key' BEGIN INSERT INTO ca_commit_child(parent) VALUES (1); END`,
	} {
		if _, err := st.DB().Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	requireCAFailure(t, st, "commit CA initialization")
	for _, key := range []string{"ca_cert", "ca_key"} {
		_, present, err := st.LookupConfig(key)
		if err != nil || present {
			t.Fatalf("CA survived failed commit: %s, %t, %v", key, present, err)
		}
	}
}

type interruptedEntropy struct{ remaining int }

func (r *interruptedEntropy) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := min(len(p), r.remaining)
	for i := range n {
		p[i] = 0x42
	}
	r.remaining -= n
	return n, nil
}
func interruptCARandom(t *testing.T, remaining int) {
	t.Helper()
	// Go 1.26 ECDSA uses its secure implicit reader; the explicit reads in
	// randomSerial and auth.Encrypt remain injectable at their real boundary.
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",cryptocustomrand=0")
	original := rand.Reader
	rand.Reader = &interruptedEntropy{remaining: remaining}
	t.Cleanup(func() { rand.Reader = original })
}
func TestCAExplicitEntropyFailures(t *testing.T) {
	cert, key, der := caFixture(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("CA serial", func(t *testing.T) {
		interruptCARandom(t, 0)
		gotCert, gotKey, err := GenerateCA()
		if err == nil || gotCert != nil || gotKey != nil || !strings.Contains(err.Error(), "generate serial number") {
			t.Fatalf("GenerateCA entropy failure: %v", err)
		}
	})
	t.Run("CSR serial", func(t *testing.T) {
		interruptCARandom(t, 0)
		gotCert, err := SignCSR(cert, key, csr, "agent", time.Hour)
		if err == nil || gotCert != nil || !strings.Contains(err.Error(), "generate serial number") {
			t.Fatalf("SignCSR entropy failure: %v", err)
		}
	})
	t.Run("server serial", func(t *testing.T) {
		interruptCARandom(t, 0)
		gotCert, gotKey, err := GenerateServerCert(cert, key, "hub")
		if err == nil || gotCert != nil || gotKey != nil || !strings.Contains(err.Error(), "generate serial number") {
			t.Fatalf("GenerateServerCert entropy failure: %v", err)
		}
	})
	for _, tc := range []struct {
		name      string
		remaining int
		want      string
	}{
		{"new CA serial", 0, "generate CA: generate serial number"},
		{"new CA nonce", 16, "encrypt CA key"},
		{"migration nonce", 0, "encrypt migrated CA key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newCAStore(t)
			legacy := tc.name == "migration nonce"
			if legacy {
				setCAConfig(t, st, "ca_cert", hex.EncodeToString(cert.Raw))
				setCAConfig(t, st, "ca_key", hex.EncodeToString(der))
			}
			interruptCARandom(t, tc.remaining)
			requireCAFailure(t, st, tc.want)
			stored, present, err := st.LookupConfig("ca_key")
			if err != nil || present != legacy || (legacy && stored != hex.EncodeToString(der)) {
				t.Fatalf("unexpected stored key after entropy failure: present %t, error %v", present, err)
			}
		})
	}
}

func TestGenerateServerCertMixedSANs(t *testing.T) {
	cert, key, _ := caFixture(t)
	server, _, err := GenerateServerCert(cert, key, "hub", "", "localhost", "127.0.0.1", "::1")
	if err != nil {
		t.Fatal(err)
	}
	if len(server.DNSNames) != 1 || server.DNSNames[0] != "localhost" || len(server.IPAddresses) != 2 {
		t.Fatalf("incorrect SANs: %v %v", server.DNSNames, server.IPAddresses)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		if _, err := server.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Fatalf("verify SAN %s: %v", host, err)
		}
	}
}

func TestCAECDSAKeyEntropyFailures(t *testing.T) {
	cert, key, _ := caFixture(t)
	for _, operation := range []string{"CA key", "server key"} {
		t.Run(operation, func(t *testing.T) {
			interruptCARandom(t, 0)
			// Go 1.26 otherwise ignores the explicit GenerateKey reader. Exercise
			// its supported custom-reader compatibility mode without replacing ECDSA.
			t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",cryptocustomrand=1")
			var gotCert *x509.Certificate
			var gotKey *ecdsa.PrivateKey
			var err error
			if operation == "CA key" {
				gotCert, gotKey, err = GenerateCA()
			} else {
				gotCert, gotKey, err = GenerateServerCert(cert, key, "hub")
			}
			if err == nil || gotCert != nil || gotKey != nil || !strings.Contains(err.Error(), "generate "+operation) {
				t.Fatalf("ECDSA entropy failure: %v", err)
			}
		})
	}
}

type failAfterSerialReader struct {
	source     io.Reader
	serialRead bool
}

func (r *failAfterSerialReader) Read(p []byte) (int, error) {
	if r.serialRead {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := r.source.Read(p)
	// randomSerial explicitly reads 16 bytes; P-256 key generation reads a
	// curve scalar of 32 bytes with the pinned Go 1.26 toolchain.
	if len(p) == 16 {
		r.serialRead = true
	}
	return n, err
}
func TestGenerateCACertificateSigningEntropyFailure(t *testing.T) {
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",cryptocustomrand=1")
	original := rand.Reader
	rand.Reader = &failAfterSerialReader{source: original}
	t.Cleanup(func() { rand.Reader = original })
	cert, key, err := GenerateCA()
	if err == nil || cert != nil || key != nil || !strings.Contains(err.Error(), "create CA certificate") {
		t.Fatalf("certificate signing entropy failure: %v", err)
	}
}

func TestInitCARejectsNonSigningCertificate(t *testing.T) {
	original, key, keyDER := caFixture(t)
	encrypted, err := auth.Encrypt(keyDER, auth.DeriveKey(persistenceStorageKey))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name              string
		isCA, constraints bool
		usage             x509.KeyUsage
	}{
		{"leaf", false, true, x509.KeyUsageDigitalSignature},
		{"missing basic constraints", true, false, x509.KeyUsageCertSign},
		{"no certificate signing usage", true, true, x509.KeyUsageCRLSign},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := *original
			template.IsCA = tc.isCA
			template.BasicConstraintsValid = tc.constraints
			template.KeyUsage = tc.usage
			// Build fresh DER so validation covers persisted material, including
			// whether basic constraints were actually encoded in the certificate.
			raw, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			st := newCAStore(t)
			setCAConfig(t, st, "ca_cert", hex.EncodeToString(raw))
			setCAConfig(t, st, "ca_key", hex.EncodeToString(encrypted))
			requireCAFailure(t, st, "stored certificate is not a signing CA")
		})
	}
}

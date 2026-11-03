package store_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestAuditHealthAbsentKeys(t *testing.T) {
	s := testStore(t)
	health, err := s.GetAuditHealth()
	if err != nil || health.Degraded || health.FailureCount != 0 || health.LastFailureAt != nil || health.LastFailureReason != nil || health.LastRecoveredAt != nil {
		t.Fatalf("initial health = %+v, error = %v", health, err)
	}
}

func TestAuditHealthUnavailableDatabase(t *testing.T) {
	s := testStore(t)
	var observed model.AuditHealth
	s.SetAuditObservers(func(health model.AuditHealth) { observed = health }, nil)
	if err := s.DB().Close(); err != nil {
		t.Fatal(err)
	}
	if health, err := s.GetAuditHealth(); err == nil || !health.Degraded {
		t.Fatalf("unavailable health = %+v, error = %v", health, err)
	}
	for range 2 {
		if err := s.LogAudit(model.AuditEntry{Action: model.AuditUserLogin}); err == nil {
			t.Fatal("expected audit write failure")
		}
	}
	health, err := s.GetAuditHealth()
	if err == nil || !health.Degraded || health.FailureCount != 2 || health.LastFailureAt == nil || health.LastFailureReason == nil {
		t.Fatalf("failed audit health = %+v, error = %v", health, err)
	}
	if !observed.Degraded || observed.FailureCount != 1 || observed.LastFailureReason == nil {
		t.Fatalf("failure observer lost unavailable database failure: %+v", observed)
	}
}

func TestAuditHealthRejectsMalformedStatus(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"audit.failure_count", "not-an-int"},
		{"audit.failure_count", "-1"},
		{"audit.failure_count", ""},
		{"audit.degraded", "not-a-bool"},
		{"audit.last_failure_at", "not-a-time"},
		{"audit.last_recovered_at", "not-a-time"},
	} {
		t.Run(fmt.Sprintf("%s/%s", tc.key, tc.value), func(t *testing.T) {
			s := testStore(t)
			if err := s.SetConfig(tc.key, tc.value); err != nil {
				t.Fatal(err)
			}
			health, err := s.GetAuditHealth()
			if err == nil || !health.Degraded || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("malformed health = %+v, error = %v", health, err)
			}
			// Neither failures nor subsequent successful audit writes may silently
			// replace corrupt status with a new healthy snapshot.
			if err := s.LogAudit(model.AuditEntry{ID: "duplicate", Action: model.AuditUserLogin}); err != nil {
				t.Fatal(err)
			}
			if err := s.LogAudit(model.AuditEntry{ID: "duplicate", Action: model.AuditUserLogin}); err == nil {
				t.Fatal("expected duplicate audit failure")
			}
			if err := s.LogAudit(model.AuditEntry{Action: model.AuditUserLogin}); err != nil {
				t.Fatal(err)
			}
			if value, err := s.GetConfig(tc.key); err != nil || value != tc.value {
				t.Fatalf("corrupt status overwritten: value = %q, error = %v", value, err)
			}
			if health, err := s.GetAuditHealth(); err == nil || !health.Degraded {
				t.Fatalf("corrupt status recovered: %+v, error = %v", health, err)
			}
		})
	}
}

func TestAuditHealthFailurePersistenceAndRecovery(t *testing.T) {
	s := testStore(t)
	if _, err := s.DB().Exec(`CREATE TRIGGER reject_health BEFORE INSERT ON _config
		WHEN NEW.key='audit.last_failure_reason' BEGIN SELECT RAISE(ABORT, 'health unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	var failures, recoveries int
	s.SetAuditObservers(func(model.AuditHealth) { failures++ }, func(model.AuditHealth) { recoveries++ })
	if err := s.LogAudit(model.AuditEntry{ID: "duplicate", Action: model.AuditUserLogin}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.LogAudit(model.AuditEntry{ID: "duplicate", Action: model.AuditUserLogin}); err == nil {
			t.Fatal("expected duplicate audit failure")
		}
	}
	health, err := s.GetAuditHealth()
	if err == nil || !health.Degraded || health.FailureCount != 2 || health.LastFailureReason == nil || health.LastFailureAt == nil {
		t.Fatalf("unpersisted failure lost: health = %+v, error = %v", health, err)
	}
	var statusRows int
	if err := s.DB().QueryRow("SELECT count(*) FROM _config WHERE key LIKE 'audit.%' AND key NOT IN ('audit.retention_days', 'audit.review_reminder_days')").Scan(&statusRows); err != nil {
		t.Fatal(err)
	}
	if statusRows != 0 {
		t.Fatalf("health write was partially committed: %d rows", statusRows)
	}
	if _, err := s.DB().Exec("DROP TRIGGER reject_health"); err != nil {
		t.Fatal(err)
	}
	if err := s.LogAudit(model.AuditEntry{Action: model.AuditUserLogin}); err != nil {
		t.Fatal(err)
	}
	recovered, err := s.GetAuditHealth()
	if err != nil || recovered.Degraded || recovered.FailureCount != 2 || recovered.LastRecoveredAt == nil || recovered.LastFailureAt == nil || *recovered.LastFailureAt != *health.LastFailureAt || recovered.LastFailureReason == nil || *recovered.LastFailureReason != *health.LastFailureReason {
		t.Fatalf("recovery lost history: health = %+v, error = %v", recovered, err)
	}
	if failures != 1 || recoveries != 1 {
		t.Fatalf("observer transitions: failures=%d, recoveries=%d", failures, recoveries)
	}
}

func TestAuditHealthRecoveryRequiresPersistence(t *testing.T) {
	s := testStore(t)
	var recoveries int
	s.SetAuditObservers(nil, func(model.AuditHealth) { recoveries++ })
	if err := s.LogAudit(model.AuditEntry{ID: "duplicate", Action: model.AuditUserLogin}); err != nil {
		t.Fatal(err)
	}
	if err := s.LogAudit(model.AuditEntry{ID: "duplicate", Action: model.AuditUserLogin}); err == nil {
		t.Fatal("expected duplicate audit failure")
	}
	if _, err := s.DB().Exec(`CREATE TRIGGER reject_recovery BEFORE INSERT ON _config
		WHEN NEW.key='audit.last_recovered_at' BEGIN SELECT RAISE(ABORT, 'recovery unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.LogAudit(model.AuditEntry{Action: model.AuditUserLogin}); err != nil {
		t.Fatal(err)
	}
	health, err := s.GetAuditHealth()
	if err == nil || !health.Degraded || health.FailureCount != 1 || health.LastRecoveredAt != nil || recoveries != 0 {
		t.Fatalf("unpersisted recovery reported: health = %+v, error = %v, recoveries=%d", health, err, recoveries)
	}
	if value, err := s.GetConfig("audit.degraded"); err != nil || value != "true" {
		t.Fatalf("recovery partially committed: degraded=%q, error=%v", value, err)
	}
	if _, err := s.DB().Exec("DROP TRIGGER reject_recovery"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.LogAudit(model.AuditEntry{Action: model.AuditUserLogin}); err != nil {
			t.Fatal(err)
		}
	}
	if health, err := s.GetAuditHealth(); err != nil || health.Degraded || health.LastRecoveredAt == nil || recoveries != 1 {
		t.Fatalf("recovery not retried: health = %+v, error = %v, recoveries=%d", health, err, recoveries)
	}
}

func TestAuditHealthUnavailableStorageRecovery(t *testing.T) {
	s := testStore(t)
	if err := s.LogAudit(model.AuditEntry{ID: "duplicate", Action: model.AuditUserLogin}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec("ALTER TABLE _config RENAME TO unavailable_config"); err != nil {
		t.Fatal(err)
	}
	if err := s.LogAudit(model.AuditEntry{ID: "duplicate", Action: model.AuditUserLogin}); err == nil {
		t.Fatal("expected duplicate audit failure")
	}
	health, err := s.GetAuditHealth()
	if err == nil || !health.Degraded || health.FailureCount != 1 || health.LastFailureReason == nil {
		t.Fatalf("unavailable storage lost failure: %+v, error=%v", health, err)
	}
	if _, err := s.DB().Exec("ALTER TABLE unavailable_config RENAME TO _config"); err != nil {
		t.Fatal(err)
	}
	// Restoring reads must not hide a failure that could not be persisted.
	if health, err := s.GetAuditHealth(); err == nil || !health.Degraded || health.FailureCount != 1 {
		t.Fatalf("restored reads hid pending failure: %+v, error=%v", health, err)
	}
	if err := s.LogAudit(model.AuditEntry{Action: model.AuditUserLogin}); err != nil {
		t.Fatal(err)
	}
	if health, err := s.GetAuditHealth(); err != nil || health.Degraded || health.FailureCount != 1 || health.LastRecoveredAt == nil || health.LastFailureReason == nil {
		t.Fatalf("restored storage lost failure history: %+v, error=%v", health, err)
	}
}

func TestAuditHealthRecoveredAfterRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	s, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.LogAudit(model.AuditEntry{ID: "duplicate", Action: model.AuditUserLogin}); err != nil {
		t.Fatal(err)
	}
	if err := s.LogAudit(model.AuditEntry{ID: "duplicate", Action: model.AuditUserLogin}); err == nil {
		t.Fatal("expected duplicate audit failure")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var recovered model.AuditHealth
	reopened.SetAuditObservers(nil, func(health model.AuditHealth) { recovered = health })
	if err := reopened.LogAudit(model.AuditEntry{Action: model.AuditUserLogin}); err != nil {
		t.Fatal(err)
	}
	if health, err := reopened.GetAuditHealth(); err != nil || health.Degraded || health.FailureCount != 1 || health.LastRecoveredAt == nil || recovered.LastRecoveredAt == nil {
		t.Fatalf("restart did not recover persisted failure: %+v, error=%v, observer=%+v", health, err, recovered)
	}
}

func TestAuditHealthSnapshotsDoNotExposeCachedState(t *testing.T) {
	s := testStore(t)
	s.SetAuditObservers(func(health model.AuditHealth) {
		*health.LastFailureAt = "observer changed timestamp"
		*health.LastFailureReason = "observer changed reason"
	}, nil)
	if err := s.DB().Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.LogAudit(model.AuditEntry{Action: model.AuditUserLogin}); err == nil {
		t.Fatal("expected closed database audit failure")
	}
	health, err := s.GetAuditHealth()
	if err == nil || health.LastFailureAt == nil || health.LastFailureReason == nil {
		t.Fatalf("missing cached failure: %+v, error=%v", health, err)
	}
	if _, err := time.Parse(time.RFC3339, *health.LastFailureAt); err != nil || !strings.Contains(*health.LastFailureReason, "database is closed") {
		t.Fatalf("observer changed cached failure: %+v", health)
	}
	*health.LastFailureAt = "caller changed timestamp"
	*health.LastFailureReason = "caller changed reason"
	if again, err := s.GetAuditHealth(); err == nil || *again.LastFailureAt == *health.LastFailureAt || *again.LastFailureReason == *health.LastFailureReason {
		t.Fatalf("caller changed cached failure: %+v, error=%v", again, err)
	}
}

func TestAuditHealthConcurrentFailuresAndReentrantObservers(t *testing.T) {
	s := testStore(t)
	var failures, recoveries atomic.Int32
	s.SetAuditObservers(func(model.AuditHealth) {
		failures.Add(1)
		_, _ = s.GetAuditHealth()
		s.SetAuditObservers(nil, func(model.AuditHealth) {
			recoveries.Add(1)
			_, _ = s.GetAuditHealth()
			s.SetAuditObservers(nil, nil)
		})
	}, nil)
	if err := s.LogAudit(model.AuditEntry{ID: "duplicate", Action: model.AuditUserLogin}); err != nil {
		t.Fatal(err)
	}
	const count = 12
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.LogAudit(model.AuditEntry{ID: "duplicate", Action: model.AuditUserLogin}); err == nil {
				t.Error("expected duplicate audit failure")
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		if err := s.LogAudit(model.AuditEntry{Action: model.AuditUserLogin}); err != nil {
			t.Errorf("recovery audit: %v", err)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("audit observer deadlocked")
	}
	if health, err := s.GetAuditHealth(); err != nil || health.Degraded || health.FailureCount != count || failures.Load() != 1 || recoveries.Load() != 1 {
		t.Fatalf("concurrent transitions lost: health = %+v, error = %v, failures=%d, recoveries=%d", health, err, failures.Load(), recoveries.Load())
	}
}

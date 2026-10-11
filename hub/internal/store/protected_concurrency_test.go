package store_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/store"
)

func TestProtectedIndependentFileWALLifecycleEvidence(t *testing.T) {
	for _, phase := range []string{"queue", "confirm"} {
		t.Run(phase, func(t *testing.T) {
			s, err := store.New(filepath.Join(t.TempDir(), "lifecycle.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			const count = 16
			records := make([][]byte, count)
			ids := make([]string, count)
			retain := time.Now().Add(24 * time.Hour)
			for i := range records {
				e := protectedExecution(t, s, fmt.Sprintf("parallel-lifecycle-%d", i))
				if err := s.FinishExecution(e.ID, "admission_failed", nil, "", ""); err != nil {
					t.Fatal(err)
				}
				ids[i], records[i] = e.ID, denialEvidence(t, e)
				if phase == "confirm" {
					if err := s.QueueExecutionEvidence(records[i], retain); err != nil {
						t.Fatal(err)
					}
				}
			}
			begin := make(chan struct{})
			results := make(chan error, count)
			for i := range records {
				go func(i int) {
					<-begin
					if phase == "queue" {
						results <- s.QueueExecutionEvidence(records[i], retain)
					} else {
						results <- s.ConfirmExecutionEvidence(ids[i] + ".completion")
					}
				}(i)
			}
			close(begin)
			for range count {
				if err := <-results; err != nil {
					t.Error(err)
				}
			}
			if phase == "queue" {
				queued, err := s.DueExecutionEvidence(time.Now().Add(time.Second), 32)
				if err != nil || len(queued) != count {
					t.Errorf("independent queue operations lost evidence: count=%d err=%v", len(queued), err)
				}
			} else {
				for _, id := range ids {
					e, err := s.GetExecution(id)
					if err != nil || e.EvidenceState != "confirmed" {
						t.Errorf("independent confirmation lost: id=%s err=%v", id, err)
					}
				}
			}
		})
	}
}

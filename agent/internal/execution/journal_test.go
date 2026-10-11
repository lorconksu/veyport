package execution

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

func TestJournalClaimRefusesDuplicateAndRestartIsUnknown(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	binding := &pb.ExecutionBinding{ExecutionId: "once", NodeId: "node", PreparationId: "prep", BootId: "boot"}
	if _, err = j.Claim(binding, []byte("hash"), []byte("identity"), "standard"); err != nil {
		t.Fatal(err)
	}
	if _, err = j.Claim(binding, nil, nil, ""); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("duplicate: %v", err)
	}
	restarted, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := restarted.Status("once")
	if !ok || record.State != "outcome_unknown" {
		t.Fatalf("restart: %+v", record)
	}
	if _, err = restarted.Claim(binding, nil, nil, ""); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("restart duplicate: %v", err)
	}
}
func TestJournalFsyncFailureDeniesClaim(t *testing.T) {
	j, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	j.syncFile = func(*os.File) error { return errors.New("disk full") }
	binding := &pb.ExecutionBinding{ExecutionId: "never", NodeId: "node", PreparationId: "prep", BootId: "boot"}
	if _, err = j.Claim(binding, nil, nil, ""); err == nil {
		t.Fatal("fsync failure accepted")
	}
	if _, err = j.Claim(binding, nil, nil, ""); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("ambiguous claim retried: %v", err)
	}
}
func TestJournalOnlyMetadataAndResultSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	binding := &pb.ExecutionBinding{ExecutionId: "metadata", NodeId: "node", PreparationId: "prep", BootId: "boot"}
	if _, err = j.Claim(binding, []byte("digest"), []byte("digest"), "standard"); err != nil {
		t.Fatal(err)
	}
	result := &pb.ExecutionResult{Binding: binding, State: "exited", ExitCode: 42, StdoutComplete: true, StderrComplete: true}
	if err = j.RecordResult(result); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		data, _ := os.ReadFile(dir + "/" + entry.Name())
		if bytes.Contains(data, []byte("raw command")) {
			t.Fatal("raw payload journaled")
		}
	}
	restarted, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := restarted.Status("metadata")
	if !ok || record.State != "exited" || record.Result.ExitCode != 42 {
		t.Fatalf("restart: %+v", record)
	}
}

func TestHistoricalClaimsDoNotAccumulateInMemoryAndCorruptionNeverRetries(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	binding := &pb.ExecutionBinding{ExecutionId: "completed", NodeId: "node", PreparationId: "prep", BootId: "boot"}
	if _, err = j.Claim(binding, nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err = j.RecordResult(&pb.ExecutionResult{Binding: binding, State: "exited"}); err != nil {
		t.Fatal(err)
	}
	if len(j.records) != 0 {
		t.Fatal("completed claim retained in memory")
	}
	restarted, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(restarted.records) != 0 {
		t.Fatal("history loaded into memory")
	}
	if err = os.WriteFile(dir+"/"+journalName("corrupt"), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	record, ok := restarted.Status("corrupt")
	if !ok || record.State != "outcome_unknown" {
		t.Fatalf("corrupt uncertainty: %+v", record)
	}
	if _, err = restarted.Claim(&pb.ExecutionBinding{ExecutionId: "corrupt"}, nil, nil, ""); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("corrupt claim retried: %v", err)
	}
}

func TestJournalInitializationRequiresDurableParentDirectoryEntry(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new-service", "execution-journal")
	parent := filepath.Dir(dir)
	visited := make(map[string]bool)
	journal, err := openJournal(dir, func(f *os.File) error {
		visited[f.Name()] = true
		if f.Name() == parent {
			return errors.New("parent fsync failed")
		}
		return f.Sync()
	})
	if err == nil || journal != nil {
		t.Fatal("journal accepted non-durable parent link")
	}
	if !visited[dir] || !visited[parent] {
		t.Fatalf("parent entry was not synchronized: %+v", visited)
	}
	journal, err = OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = journal.Claim(&pb.ExecutionBinding{ExecutionId: "durable-first", NodeId: "node", PreparationId: "prep", BootId: "boot"}, nil, nil, ""); err != nil {
		t.Fatal(err)
	}
}

package execution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

var ErrAlreadyClaimed = errors.New("execution already durably claimed")

// LaunchRecord deliberately contains no submitted command, input, or output.
type LaunchRecord struct {
	Binding        *pb.ExecutionBinding `json:"binding"`
	CommandSHA256  []byte               `json:"command_sha256"`
	IdentitySHA256 []byte               `json:"identity_sha256"`
	PolicyVersion  string               `json:"policy_version"`
	State          string               `json:"state"`
	Result         *pb.ExecutionResult  `json:"result,omitempty"`
}
type Journal struct {
	mu       sync.Mutex
	dir      string
	records  map[string]*LaunchRecord
	syncFile func(*os.File) error
}

func OpenJournal(dir string) (*Journal, error) {
	return openJournal(dir, func(f *os.File) error { return f.Sync() })
}
func openJournal(dir string, syncFile func(*os.File) error) (*Journal, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	dir = absDir
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create execution journal: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	// Fsyncing the journal itself does not persist the directory entry that
	// links it from its parent. Sync the complete path so a newly created service
	// directory or ancestor cannot disappear after a successful first launch.
	for path := dir; ; path = filepath.Dir(path) {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open execution journal directory: %w", err)
		}
		syncErr := syncFile(f)
		closeErr := f.Close()
		if syncErr != nil {
			return nil, fmt.Errorf("execution journal directory not durable: %w", syncErr)
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	j := &Journal{dir: dir, records: make(map[string]*LaunchRecord), syncFile: syncFile}
	// Historical IDs are retained on disk and loaded lazily. Only active claims
	// live in memory, bounded by the shared node session budget.
	return j, nil
}
func journalName(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:]) + ".json"
}
func (j *Journal) Status(id string) (*LaunchRecord, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	r, ok := j.records[id]
	if !ok {
		r, ok = j.readRecord(id)
	}
	if !ok {
		return nil, false
	}
	data, _ := json.Marshal(r)
	var result LaunchRecord
	_ = json.Unmarshal(data, &result)
	return &result, true
}
func (j *Journal) readRecord(id string) (*LaunchRecord, bool) {
	f, err := os.Open(filepath.Join(j.dir, journalName(id)))
	if os.IsNotExist(err) {
		return nil, false
	}
	unknown := &LaunchRecord{Binding: &pb.ExecutionBinding{ExecutionId: id}, State: "outcome_unknown"}
	if err != nil {
		return unknown, true
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) > 65536 {
		return unknown, true
	}
	var record LaunchRecord
	if json.Unmarshal(data, &record) != nil || record.Binding == nil || record.Binding.ExecutionId != id {
		return unknown, true
	}
	if record.State == "claimed" || record.State == "running" {
		record.State = "outcome_unknown"
	}
	return &record, true
}
func (j *Journal) Claim(binding *pb.ExecutionBinding, commandHash, identityHash []byte, policy string) (*LaunchRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, ok := j.records[binding.ExecutionId]; ok {
		return nil, ErrAlreadyClaimed
	}
	record := &LaunchRecord{Binding: proto.Clone(binding).(*pb.ExecutionBinding), CommandSHA256: append([]byte(nil), commandHash...), IdentitySHA256: append([]byte(nil), identityHash...), PolicyVersion: policy, State: "claimed"}
	f, err := os.OpenFile(filepath.Join(j.dir, journalName(binding.ExecutionId)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		return nil, ErrAlreadyClaimed
	}
	if err != nil {
		return nil, fmt.Errorf("claim execution journal: %w", err)
	}
	// Even an uncertain write consumes the ID; never erase it to permit retry.
	j.records[binding.ExecutionId] = record
	err = j.writeSync(f, record)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = j.syncDirectory()
	}
	if err != nil {
		delete(j.records, binding.ExecutionId)
		return nil, fmt.Errorf("execution claim not durable: %w", err)
	}
	return record, nil
}
func (j *Journal) writeSync(f *os.File, record *LaunchRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	return j.syncFile(f)
}
func (j *Journal) syncDirectory() error {
	f, err := os.Open(j.dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return j.syncFile(f)
}
func (j *Journal) RecordRunning(id string) error { return j.update(id, "running", nil) }
func (j *Journal) RecordResult(result *pb.ExecutionResult) error {
	return j.update(result.Binding.ExecutionId, result.State, result)
}
func (j *Journal) update(id, state string, result *pb.ExecutionResult) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	old, ok := j.records[id]
	if !ok {
		old, ok = j.readRecord(id)
	}
	if !ok {
		return fmt.Errorf("execution not claimed")
	}
	next := *old
	next.State = state
	next.Result = result
	f, err := os.CreateTemp(j.dir, ".journal-")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	if err = f.Chmod(0600); err == nil {
		err = j.writeSync(f, &next)
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(path, filepath.Join(j.dir, journalName(id)))
	}
	if err == nil {
		err = j.syncDirectory()
	}
	if err != nil {
		delete(j.records, id)
		return fmt.Errorf("execution journal update not durable: %w", err)
	}
	if state == "running" {
		j.records[id] = &next
	} else {
		delete(j.records, id)
	}
	return nil
}

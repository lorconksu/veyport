package dropzone

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wyiu/veyport/agent/internal/sessionlimit"
)

func TestUploadActivitySpansEveryChunkAndEndsOnlyAtCommitAbortOrCleanup(t *testing.T) {
	for _, finish := range []string{"commit", "abort", "cleanup", "size", "write", "rename"} {
		t.Run(finish, func(t *testing.T) {
			b := sessionlimit.New(8)
			d := NewWithBudget(t.TempDir(), b)
			if ack := d.HandleChunk("live", "data.txt", []byte("first"), false); ack != nil {
				t.Fatal(ack)
			}
			if ack := d.HandleChunk("live", "", []byte("second"), false); ack != nil {
				t.Fatal(ack)
			}
			if b.ActivityCount() != 1 || b.TryMaintenance() {
				t.Fatal("partial upload reported idle")
			}
			tmp := filepath.Join(d.Dir(), ".upload-live")
			switch finish {
			case "commit":
				ack := d.HandleChunk("live", "", nil, true)
				if !ack.Success {
					t.Fatal(ack)
				}
				data, err := os.ReadFile(filepath.Join(d.Dir(), "data.txt"))
				if err != nil || string(data) != "firstsecond" {
					t.Fatal(string(data), err)
				}
			case "abort":
				ack := d.Abort("live")
				if ack.Success || ack.Error != "upload aborted" {
					t.Fatal(ack)
				}
				d.Abort("live")
			case "cleanup":
				d.Cleanup()
				d.Cleanup()
			case "size":
				d.uploads["live"].bytes = MaxUploadSize
				if ack := d.HandleChunk("live", "", []byte("x"), false); ack == nil || ack.Success {
					t.Fatal(ack)
				}
			case "write":
				d.uploads["live"].file.Close()
				if ack := d.HandleChunk("live", "", []byte("x"), false); ack == nil || ack.Success {
					t.Fatal(ack)
				}
			case "rename":
				os.Mkdir(filepath.Join(d.Dir(), "data.txt"), 0700)
				if ack := d.HandleChunk("live", "", nil, true); ack == nil || ack.Success {
					t.Fatal(ack)
				}
			}
			if _, err := os.Stat(tmp); !os.IsNotExist(err) {
				t.Fatal("partial remains", err)
			}
			if b.ActivityCount() != 0 || !b.TryMaintenance() {
				t.Fatal("upload reservation leaked")
			}
		})
	}
}

func TestUploadRefusalAndUnknownAbortNeverCreateOrCommitData(t *testing.T) {
	b := sessionlimit.New(8)
	d := NewWithBudget(t.TempDir(), b)
	if !b.TryMaintenance() {
		t.Fatal("maintenance")
	}
	if ack := d.HandleChunk("blocked", "data.txt", []byte("data"), true); ack == nil || ack.Success {
		t.Fatal(ack)
	}
	if ack := d.Abort("unknown"); ack.Success {
		t.Fatal(ack)
	}
	entries, _ := os.ReadDir(d.Dir())
	if len(entries) != 0 || b.ActivityCount() != 0 {
		t.Fatal("refusal mutated dropzone")
	}
	b.EndMaintenance()
	os.Remove(d.Dir())
	if ack := d.HandleChunk("bad-dir", "data.txt", nil, false); ack == nil || ack.Success {
		t.Fatal(ack)
	}
	if b.ActivityCount() != 0 || !b.TryMaintenance() {
		t.Fatal("failed open leaked reservation")
	}
}

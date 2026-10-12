package grpcserver

import (
	"context"
	"database/sql/driver"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
	"modernc.org/sqlite"
)

type activitySQLCallback struct{ run func() }

var activitySQLCallbackSlot atomic.Pointer[activitySQLCallback]
var activitySQLRegister sync.Once
var activitySQLRegisterError error

func registerActivityInterleave(t *testing.T) {
	t.Helper()
	activitySQLRegister.Do(func() {
		activitySQLRegisterError = sqlite.RegisterScalarFunction("veyport_activity_interleave", 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) {
			if callback := activitySQLCallbackSlot.Load(); callback != nil {
				callback.run()
			}
			return int64(1), nil
		})
	})
	if activitySQLRegisterError != nil {
		t.Fatal(activitySQLRegisterError)
	}
	t.Cleanup(func() { activitySQLCallbackSlot.Store(nil) })
}
func TestManualUpdateGenerationReplacementRetiresOnlyCreatedPreinstallAuthority(t *testing.T) {
	registerActivityInterleave(t)
	f := newUpdateFixture(t)
	f.u.EndConnection("node", f.stream)
	old := f.h.connMgr.GetConn("node")
	a, err := f.h.connMgr.BeginActivity(old, "abandoned", connmgr.ActivityRead)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Send(context.Background(), &pb.HubMessage{Payload: &pb.HubMessage_FileReadRequest{FileReadRequest: &pb.FileReadRequest{RequestId: "abandoned"}}}); err != nil {
		t.Fatal(err)
	}
	a.Abandon()
	replacement := &mockStream{}
	activitySQLCallbackSlot.Store(&activitySQLCallback{func() { f.h.connMgr.Register("node", replacement) }})
	if _, err = f.st.DB().Exec(`CREATE TRIGGER change_update_generation AFTER INSERT ON agent_updates BEGIN SELECT veyport_activity_interleave(); END`); err != nil {
		t.Fatal(err)
	}
	op, ticket, err := f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision, BootstrapIdleAssertion{Confirmed: true, ConnectionID: old.GenerationID})
	if err == nil || ticket != "" {
		t.Fatal("replaced manual generation issued authority", op, err)
	}
	persisted, err := f.st.GetAgentUpdate(op.ID)
	if err != nil || persisted.State != "failed" {
		t.Fatal("created authority not retired", persisted, err)
	}
	f.u.mu.Lock()
	origins := len(f.u.origins)
	f.u.mu.Unlock()
	if origins != 0 {
		t.Fatal("refused generation leaked update capacity")
	}
	if _, ok := f.u.terminals.Register("node", "after-refusal", "admin", ""); !ok {
		t.Fatal("refused operation kept terminal lease")
	}
	f.u.terminals.Remove("node", "after-refusal")
	current := f.h.connMgr.GetConn("node")
	if err = f.h.connMgr.ReserveMaintenance(current, "unsafe", func() error { return nil }); !errors.Is(err, connmgr.ErrActivityBusy) {
		t.Fatal("old assertion erased replacement uncertainty", err)
	}
	if err = f.u.ObserveCapabilities("node", replacement, f.old); err != nil {
		t.Fatal(err)
	}
	if _, err = f.st.DB().Exec("DROP TRIGGER change_update_generation"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.u.Start(context.Background(), "admin", "session", "node", f.target.Version, f.target.Revision); err != nil {
		t.Fatal("safe fresh native operation could not follow cleanup", err)
	}
}
func TestBlockedOldCapabilityCannotOverwriteReplacementCacheOrObservedVersion(t *testing.T) {
	registerActivityInterleave(t)
	f := newUpdateFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	activitySQLCallbackSlot.Store(&activitySQLCallback{func() { first.Do(func() { close(entered); <-release }) }})
	if _, err := f.st.DB().Exec(`CREATE TRIGGER interleave_observed_version BEFORE UPDATE OF agent_version ON servers BEGIN SELECT veyport_activity_interleave(); END`); err != nil {
		t.Fatal(err)
	}
	old := proto.Clone(f.old).(*pb.UpdateCapabilities)
	old.Version = "0.2.0"
	oldDone := make(chan error, 1)
	go func() { oldDone <- f.u.ObserveCapabilities("node", f.stream, old) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("old version write did not block")
	}
	replacement := &mockStream{}
	f.h.connMgr.Register("node", replacement)
	current := proto.Clone(f.old).(*pb.UpdateCapabilities)
	current.Version = "0.3.0"
	current.Supported = false
	current.Reason = "noncanonical"
	newDone := make(chan error, 1)
	go func() { newDone <- f.u.ObserveCapabilities("node", replacement, current) }()
	close(release)
	select {
	case err := <-oldDone:
		if err == nil {
			t.Fatal("old observation published after replacement")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("old observation did not join")
	}
	select {
	case err := <-newDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("replacement observation did not join")
	}
	if c := f.u.Capabilities("node"); c == nil || c.Version != "0.3.0" || c.Supported {
		t.Fatal("old cache displaced replacement", c)
	}
	check, err := f.u.Check("admin", "session", "node")
	if err != nil || check.BootstrapRequired || check.Supported {
		t.Fatal("replacement safety refusal became manual fallback", check, err)
	}
	if err = f.u.ObserveCapabilities("node", f.stream, old); err == nil {
		t.Fatal("late old observer accepted")
	}
	server, err := f.st.GetServerByID("node")
	if err != nil || server.AgentVersion == nil || *server.AgentVersion != "0.3.0" {
		t.Fatal("observed version regressed", server, err)
	}
}

package grpcserver

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

func preparedForTest(id, node string, command []byte) *pb.ExecutionPrepared {
	hash := sha256.Sum256(command)
	return &pb.ExecutionPrepared{ExecutionId: id, Binding: &pb.ExecutionBinding{ExecutionId: id, NodeId: node, PreparationId: "prep", BootId: "boot", ExpiresUnixMilli: time.Now().Add(30 * time.Second).UnixMilli()}, Identity: &pb.ExecutionIdentity{Username: "root", Shell: "/bin/sh", Cwd: "/root", IdentitySha256: bytes.Repeat([]byte{1}, 32), GroupsSha256: bytes.Repeat([]byte{2}, 32)}, CommandSha256: hash[:], Limits: DefaultExecutionLimits()}
}

func TestExecutionTicketOwnershipReplayAndGeneration(t *testing.T) {
	cm := connmgr.New()
	control := &mockStream{}
	cm.Register("node", control)
	registry := NewExecutionSessions(NewTerminalSessions(), cm)
	registry.SetCapabilities("node", control, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "boot"})
	session, err := registry.Register("node", "exec", "actor", "", []byte("id"))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Remove("node", "exec")
	p := preparedForTest("exec", "node", []byte("id"))
	if !registry.DeliverPrepared("node", control, p) {
		t.Fatal("preparation rejected")
	}
	attach, err := session.IssueAttach()
	if err != nil {
		t.Fatal(err)
	}
	wrong := proto.Clone(attach).(*pb.ExecutionAttachRequest)
	wrong.Ticket = bytes.Repeat([]byte{3}, 32)
	if _, err = registry.Attach("node", wrong); err == nil {
		t.Fatal("wrong ticket admitted")
	}
	if _, err = registry.Attach("other", attach); err == nil {
		t.Fatal("wrong node admitted")
	}
	if _, err = registry.Attach("node", attach); err != nil {
		t.Fatal(err)
	}
	if _, err = registry.Attach("node", attach); err == nil {
		t.Fatal("replay admitted")
	}
	cm.Register("node", &mockStream{})
	if registry.Supports("node") {
		t.Fatal("capability survived connection replacement")
	}
}

func TestExecutionRejectsChangedAndExpiredPreparedBindings(t *testing.T) {
	cm := connmgr.New()
	control := &mockStream{}
	cm.Register("node", control)
	registry := NewExecutionSessions(NewTerminalSessions(), cm)
	registry.SetCapabilities("node", control, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "boot"})
	for _, test := range []struct {
		name   string
		change func(*pb.ExecutionPrepared)
	}{
		{"command", func(p *pb.ExecutionPrepared) { p.CommandSha256[0] ^= 1 }},
		{"boot", func(p *pb.ExecutionPrepared) { p.Binding.BootId = "other" }},
		{"expired", func(p *pb.ExecutionPrepared) { p.Binding.ExpiresUnixMilli = time.Now().Add(-time.Second).UnixMilli() }},
		{"identity", func(p *pb.ExecutionPrepared) { p.Identity.IdentitySha256 = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, err := registry.Register("node", test.name, "actor", "", []byte("id"))
			if err != nil {
				t.Fatal(err)
			}
			defer registry.Remove("node", test.name)
			p := preparedForTest(test.name, "node", []byte("id"))
			test.change(p)
			if registry.DeliverPrepared("node", control, p) {
				t.Fatal("invalid preparation accepted")
			}
			if _, err = s.IssueAttach(); err == nil {
				t.Fatal("invalid preparation issued ticket")
			}
		})
	}
}

func TestSharedTerminalExecutionCapacityAndRevocation(t *testing.T) {
	cm := connmgr.New()
	control := &mockStream{}
	cm.Register("node", control)
	terminals := NewTerminalSessions()
	registry := NewExecutionSessions(terminals, cm)
	registry.SetCapabilities("node", control, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "boot"})
	if _, ok := terminals.Register("node", "shell", "actor", "root"); !ok {
		t.Fatal("shell registration failed")
	}
	for _, id := range []string{"e1", "e2", "e3", "e4"} {
		if _, err := registry.Register("node", id, "actor", "", []byte("id")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := registry.Register("node", "e5", "actor", "", []byte("id")); err == nil {
		t.Fatal("actor capacity exceeded")
	}
	if n := terminals.EndByUser("actor", -1, "revoked"); n != 5 {
		t.Fatalf("closed %d, want5", n)
	}
	registry.Remove("node", "e1")
	registry.Remove("node", "e2")
	registry.Remove("node", "e3")
	registry.Remove("node", "e4")
}

func TestExecutionBootChangeCancelsUnusedPreparation(t *testing.T) {
	cm := connmgr.New()
	control := &mockStream{}
	cm.Register("node", control)
	es := NewExecutionSessions(NewTerminalSessions(), cm)
	es.SetCapabilities("node", control, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "boot"})
	s, err := es.Register("node", "exec", "actor", "", []byte("id"))
	if err != nil {
		t.Fatal(err)
	}
	defer es.Remove("node", "exec")
	es.SetCapabilities("node", control, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "new-boot"})
	select {
	case <-s.Done:
	default:
		t.Fatal("boot change retained preparation")
	}
}

func TestSharedNodeLimitIsAtomicAcrossExecutionsAndShells(t *testing.T) {
	cm := connmgr.New()
	control := &mockStream{}
	cm.Register("node", control)
	terminals := NewTerminalSessions()
	es := NewExecutionSessions(terminals, cm)
	es.SetCapabilities("node", control, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, BootId: "boot"})
	var wg sync.WaitGroup
	accepted := make(chan bool, 32)
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := fmt.Sprintf("session-%d", n)
			actor := fmt.Sprintf("actor-%d", n)
			if n%2 == 0 {
				_, err := es.Register("node", id, actor, "", []byte("id"))
				accepted <- err == nil
			} else {
				_, ok := terminals.Register("node", id, actor, "")
				accepted <- ok
			}
		}(n)
	}
	wg.Wait()
	close(accepted)
	count := 0
	for ok := range accepted {
		if ok {
			count++
		}
	}
	if count != 8 {
		t.Fatalf("shared node admissions=%d, want8", count)
	}
	for n := 0; n < 32; n++ {
		id := fmt.Sprintf("session-%d", n)
		es.Remove("node", id)
		terminals.Remove("node", id)
	}
}

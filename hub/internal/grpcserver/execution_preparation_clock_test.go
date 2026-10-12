package grpcserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"math"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/connmgr"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func preparationClockSession(t *testing.T) (*ExecutionSessions, *ExecutionSession, *mockStream, *pb.ExecutionPrepared) {
	t.Helper()
	control := &mockStream{}
	connections := connmgr.New()
	connections.Register("node", control)
	es := NewExecutionSessions(NewTerminalSessions(), connections)
	es.SetCapabilities("node", control, &pb.ExecutionCapabilities{ProtocolVersion: 1, StandardExec: true, ProtectedScript: true, BootId: "boot"})
	s, err := es.Register("node", "exec", "actor", "", []byte("id"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { es.Remove(s.NodeID, s.ID) })
	return es, s, control, preparedForTest(s.ID, s.NodeID, []byte("id"))
}

func TestExecutionPreparationAcceptsSmallPositiveClockSkew(t *testing.T) {
	// Preparation TTL is measured on the agent. Its clock may be ahead of
	// the Hub even when both hosts are synchronized and network latency is low.
	for _, skew := range []time.Duration{time.Millisecond, 2 * time.Millisecond} {
		t.Run(skew.String(), func(t *testing.T) {
			_, s, _, p := preparationClockSession(t)
			now := time.Unix(1_800_000_000, 0)
			p.Binding.ExpiresUnixMilli = now.Add(ExecutionAttachTimeout + skew).UnixMilli()
			if err := s.validatePrepared(p, now); err != nil {
				t.Fatalf("valid preparation from clock ahead by %s rejected: %v", skew, err)
			}
		})
	}
}

func TestExecutionPreparationClockSkewPreservesExactBindingAndSingleUse(t *testing.T) {
	es, s, control, p := preparationClockSession(t)
	p.Binding.ExpiresUnixMilli = time.Now().Add(ExecutionAttachTimeout + 2*time.Second).UnixMilli()
	if !es.DeliverPrepared(s.NodeID, control, p) {
		t.Fatal("valid separate-clock preparation rejected")
	}
	prepared, err := s.WaitPrepared(context.Background())
	if err != nil || !proto.Equal(prepared, p) {
		t.Fatalf("accepted preparation changed: %v", err)
	}
	attach, err := s.IssueAttach()
	if err != nil || !proto.Equal(attach.Binding, p.Binding) {
		t.Fatalf("attachment changed original agent binding: %v", err)
	}
	altered := proto.Clone(attach).(*pb.ExecutionAttachRequest)
	altered.Binding.ExpiresUnixMilli--
	if _, err := es.Attach(s.NodeID, altered); err == nil {
		t.Fatal("changed preparation expiry admitted")
	}
	if _, err := es.Attach(s.NodeID, attach); err != nil {
		t.Fatal(err)
	}
	if _, err := es.Attach(s.NodeID, attach); err == nil {
		t.Fatal("attachment replay admitted")
	}
	if err := s.Dispatch(); err != nil {
		t.Fatal(err)
	}
	start := (<-s.start).start
	if !proto.Equal(start.Binding, p.Binding) {
		t.Fatal("launch changed original agent binding")
	}
}

func TestExecutionPreparationExpiryWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, test := range []struct {
		name    string
		expires int64
		wantErr string
	}{
		{"expired", now.Add(-time.Millisecond).UnixMilli(), "execution preparation expired"},
		{"exact-expiry", now.UnixMilli(), "execution preparation expired"},
		{"one-millisecond-left", now.Add(time.Millisecond).UnixMilli(), ""},
		{"negative-expiry", math.MinInt64, "execution preparation expired"},
		{"unbounded-future", math.MaxInt64, "execution preparation expiry exceeds allowed clock skew"},
		{"maximum-skew", now.Add(65 * time.Second).UnixMilli(), ""},
		{"past-maximum-skew", now.Add(65*time.Second + time.Millisecond).UnixMilli(), "execution preparation expiry exceeds allowed clock skew"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, s, _, p := preparationClockSession(t)
			p.Binding.ExpiresUnixMilli = test.expires
			err := s.validatePrepared(p, now)
			if test.wantErr == "" && err != nil || test.wantErr != "" && (err == nil || err.Error() != test.wantErr) {
				t.Fatalf("expiry validation got %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestExecutionPreparationSkewCannotChangeOwnershipOrContent(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*pb.ExecutionPrepared)
	}{
		{"execution", func(p *pb.ExecutionPrepared) { p.Binding.ExecutionId = "other" }},
		{"node", func(p *pb.ExecutionPrepared) { p.Binding.NodeId = "other" }},
		{"boot", func(p *pb.ExecutionPrepared) { p.Binding.BootId = "other" }},
		{"missing-preparation", func(p *pb.ExecutionPrepared) { p.Binding.PreparationId = "" }},
		{"command", func(p *pb.ExecutionPrepared) { p.CommandSha256[0] ^= 1 }},
		{"limits", func(p *pb.ExecutionPrepared) { p.Limits.RuntimeSeconds++ }},
		{"identity", func(p *pb.ExecutionPrepared) { p.Identity.IdentitySha256 = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, s, _, p := preparationClockSession(t)
			now := time.Unix(1_800_000_000, 0)
			p.Binding.ExpiresUnixMilli = now.Add(ExecutionAttachTimeout + 2*time.Millisecond).UnixMilli()
			test.change(p)
			if err := s.validatePrepared(p, now); err == nil {
				t.Fatal("clock skew admitted an invalid preparation")
			}
		})
	}
}

func TestExecutionPreparationHubDeadlineCapsSkewAndHonorsEarlierAgentExpiry(t *testing.T) {
	for _, lifetime := range []time.Duration{10 * time.Second, 62 * time.Second} {
		t.Run(lifetime.String(), func(t *testing.T) {
			es, s, control, p := preparationClockSession(t)
			p.Binding.ExpiresUnixMilli = time.Now().Add(lifetime).UnixMilli()
			before := time.Now()
			if !es.DeliverPrepared(s.NodeID, control, p) {
				t.Fatal("valid preparation rejected")
			}
			after := time.Now()
			s.mu.Lock()
			defer s.mu.Unlock()
			deadline := s.preparationDeadline
			if lifetime < ExecutionAttachTimeout {
				if deadline.UnixMilli() != p.Binding.ExpiresUnixMilli {
					t.Fatal("Hub extended an earlier agent expiry")
				}
			} else if deadline.Before(before.Add(ExecutionAttachTimeout)) || deadline.After(after.Add(ExecutionAttachTimeout)) {
				t.Fatal("clock skew extended the 60-second Hub deadline")
			}
			if !s.preparationExpiredLocked(deadline) {
				t.Fatal("exact local deadline still grants authority")
			}
			if s.preparationExpiredLocked(deadline.Add(-time.Millisecond)) {
				t.Fatal("live preparation expired before its earlier deadline")
			}
			// A wall-clock expiry stays a refusal even while the separately
			// recorded local deadline would still permit attachment.
			s.prepared.Binding.ExpiresUnixMilli = before.UnixMilli()
			if !s.preparationExpiredLocked(before) {
				t.Fatal("local deadline renewed an expired agent binding")
			}
		})
	}
}

func expirePreparationHubDeadline(s *ExecutionSession) {
	s.mu.Lock()
	s.preparationDeadline = time.Now().Add(-time.Second)
	s.mu.Unlock()
}

func TestExecutionPreparationLocalExpiryRejectsAttachmentAndDispatch(t *testing.T) {
	for _, phase := range []string{"issue-ticket", "attach", "standard-dispatch", "protected-dispatch"} {
		t.Run(phase, func(t *testing.T) {
			es, s, control, p := preparationClockSession(t)
			if phase == "protected-dispatch" {
				if err := s.Configure(true, nil, 0, DefaultExecutionLimits()); err != nil {
					t.Fatal(err)
				}
			}
			p.Binding.ExpiresUnixMilli = time.Now().Add(ExecutionAttachTimeout + 2*time.Second).UnixMilli()
			if !es.DeliverPrepared(s.NodeID, control, p) {
				t.Fatal("valid preparation rejected")
			}
			if phase == "issue-ticket" {
				expirePreparationHubDeadline(s)
				if _, err := s.IssueAttach(); err == nil || s.ticketIssued {
					t.Fatal("local expiry issued an attachment ticket")
				}
				return
			}
			attach, err := s.IssueAttach()
			if err != nil {
				t.Fatal(err)
			}
			if phase == "attach" {
				expirePreparationHubDeadline(s)
				if _, err := es.Attach(s.NodeID, attach); err == nil || s.ticketUsed {
					t.Fatal("local expiry consumed attachment authority")
				}
				return
			}
			if _, err := es.Attach(s.NodeID, attach); err != nil {
				t.Fatal(err)
			}
			expirePreparationHubDeadline(s)
			if phase == "standard-dispatch" {
				err = s.Dispatch()
			} else {
				err = s.DispatchProtected([]byte("verified fixture"), p.Binding.ExpiresUnixMilli, "2", nil, func() error { return nil })
			}
			if err == nil || s.dispatch || len(s.start) != 0 {
				t.Fatal("local expiry consumed dispatch authority")
			}
		})
	}
}

func TestExecutionPreparationLocalExpiryPreventsQueuedAndAuthorizedStart(t *testing.T) {
	for _, mode := range []string{"standard", "protected"} {
		for _, phase := range []string{"before-transfer", "after-authorization"} {
			t.Run(mode+"/"+phase, func(t *testing.T) {
				es, s, control, p := preparationClockSession(t)
				script := []byte("synthetic protected input")
				if mode == "protected" {
					hash := sha256.Sum256(script)
					if err := s.Configure(true, hash[:], uint64(len(script)), DefaultExecutionLimits()); err != nil {
						t.Fatal(err)
					}
				}
				p.Binding.ExpiresUnixMilli = time.Now().Add(ExecutionAttachTimeout + 2*time.Second).UnixMilli()
				if !es.DeliverPrepared(s.NodeID, control, p) {
					t.Fatal("valid preparation rejected")
				}
				attach, err := s.IssueAttach()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := es.Attach(s.NodeID, attach); err != nil {
					t.Fatal(err)
				}
				checked := false
				check := func() error {
					checked = true
					if phase == "after-authorization" {
						expirePreparationHubDeadline(s)
					}
					return nil
				}
				if mode == "standard" {
					err = s.DispatchChecked(check)
				} else {
					err = s.DispatchProtected([]byte("verified fixture"), p.Binding.ExpiresUnixMilli, "2", bytes.NewReader(script), check)
				}
				if err != nil {
					t.Fatal(err)
				}
				if phase == "before-transfer" {
					expirePreparationHubDeadline(s)
				}
				stream := &failingProtectedStream{executionTestStream: executionTestStream{sent: make(chan *pb.ExecutionHubMessage, 8)}}
				stream.afterSend = func(msg *pb.ExecutionHubMessage) {
					if msg.GetStart() != nil {
						s.Cancel("bound a failing implementation")
					}
				}
				if err := sendExecution(stream, s); status.Code(err) != codes.DeadlineExceeded {
					t.Fatalf("expired local authority got %v", err)
				}
				if s.StartAttempted() || checked != (phase == "after-authorization") {
					t.Fatal("expired preparation reached launch authority")
				}
				close(stream.sent)
				for msg := range stream.sent {
					if msg.GetStart() != nil || msg.GetInput() != nil || phase == "before-transfer" && (msg.GetScriptChunk() != nil || msg.GetScriptEof() != nil) {
						t.Fatal("expired preparation transferred input or launched a command")
					}
				}
			})
		}
	}
}

type preparationExpiryReader struct {
	reader io.Reader
	expire func()
}

func (r *preparationExpiryReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	r.expire()
	return n, err
}

func TestExecutionPreparationLocalExpiryDuringProtectedReadCannotTransferInput(t *testing.T) {
	script := []byte("synthetic protected input")
	s := protectedSession(t, script)
	reader := &preparationExpiryReader{reader: bytes.NewReader(script), expire: func() { expirePreparationHubDeadline(s) }}
	if err := s.DispatchProtected([]byte("verified fixture"), s.Binding().ExpiresUnixMilli, "2", reader, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	stream := &failingProtectedStream{executionTestStream: executionTestStream{sent: make(chan *pb.ExecutionHubMessage, 8)}}
	stream.afterSend = func(msg *pb.ExecutionHubMessage) {
		if msg.GetStart() != nil {
			s.Cancel("bound a failing implementation")
		}
	}
	if err := sendExecution(stream, s); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("expiry while reading protected input got %v", err)
	}
	if s.StartAttempted() || len(stream.sent) != 1 || (<-stream.sent).GetAttached() == nil {
		t.Fatal("read crossed local expiry and transferred protected input")
	}
}

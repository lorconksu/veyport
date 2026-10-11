package execution

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/wyiu/veyport/agent/internal/executionidentity"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

func ScriptInterpreter(command string) string {
	switch command {
	case "bash -s", "/bin/bash -s":
		return "/bin/bash"
	case "sh -s", "/bin/sh -s":
		return "/bin/sh"
	default:
		return ""
	}
}
func withInterpreter(identity *executionidentity.Identity, interpreter string) (*executionidentity.Identity, error) {
	info, err := os.Stat(interpreter)
	if err != nil || info.IsDir() || info.Mode()&0111 == 0 {
		return nil, fmt.Errorf("protected interpreter unavailable")
	}
	copyIdentity := *identity
	copyIdentity.Shell = interpreter
	return &copyIdentity, nil
}
func (m *Manager) scriptPreparation(binding *pb.ExecutionBinding) (*preparation, error) {
	if m.closed || binding == nil {
		return nil, fmt.Errorf("invalid script ownership")
	}
	p := m.prepared[binding.ExecutionId]
	if p == nil || !p.attached || !proto.Equal(p.response.Binding, binding) || time.Now().UnixMilli() >= binding.ExpiresUnixMilli || !p.enhanced || p.script == nil || p.scriptComplete {
		return nil, fmt.Errorf("invalid or completed protected script preparation")
	}
	return p, nil
}

// ScriptChunk stores bytes only. No command can start until ScriptEOF has
// durably sealed the complete input and verified both its exact length/hash.
func (m *Manager) ScriptChunk(binding *pb.ExecutionBinding, chunk *pb.ExecutionScriptChunk) (returnErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() {
		if returnErr != nil {
			m.invalidateScript(binding)
		}
	}()
	p, err := m.scriptPreparation(binding)
	if err != nil {
		return err
	}
	if chunk == nil || len(chunk.Data) == 0 || len(chunk.Data) > MaxFrameBytes || chunk.Offset != p.scriptOffset || uint64(len(chunk.Data)) > p.scriptLength-p.scriptOffset {
		return fmt.Errorf("invalid protected script offset or length")
	}
	n, err := p.script.Write(chunk.Data)
	if err != nil || n != len(chunk.Data) {
		return fmt.Errorf("protected script storage unavailable")
	}
	_, _ = p.scriptDigest.Write(chunk.Data)
	p.scriptOffset += uint64(n)
	return nil
}
func (m *Manager) ScriptEOF(binding *pb.ExecutionBinding, eof *pb.ExecutionScriptEOF) (returnErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() {
		if returnErr != nil {
			m.invalidateScript(binding)
		}
	}()
	p, err := m.scriptPreparation(binding)
	if err != nil {
		return err
	}
	if eof == nil || eof.Length != p.scriptLength || p.scriptOffset != p.scriptLength || !bytes.Equal(eof.Sha256, p.scriptHash) || !bytes.Equal(p.scriptDigest.Sum(nil), p.scriptHash) {
		return fmt.Errorf("protected script content mismatch")
	}
	if err := p.script.Seal(); err != nil {
		return fmt.Errorf("protected script storage unavailable")
	}
	p.scriptComplete = true
	return nil
}

// Invalid framing terminates this preparation, rather than allowing a caller
// to repair/reinterpret a previously invalid raw submission and launch it.
func (m *Manager) invalidateScript(binding *pb.ExecutionBinding) {
	if binding == nil {
		return
	}
	p := m.prepared[binding.ExecutionId]
	if p == nil || !proto.Equal(p.response.Binding, binding) {
		return
	}
	p.timer.Stop()
	delete(m.prepared, binding.ExecutionId)
	if p.script != nil {
		_ = p.script.Close()
	}
	m.budget.Release()
}

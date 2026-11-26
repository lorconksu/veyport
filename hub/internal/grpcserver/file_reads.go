package grpcserver

import (
	"sync"
	"time"

	"github.com/wyiu/veyport/proto/fileview"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

type pendingFileRead struct {
	mu        sync.Mutex
	stream    pb.AgentService_ConnectServer
	mode      pb.FileReadMode
	reply     chan proto.Message
	progress  chan time.Time
	data      []byte
	totalSize int64
	shortData bool
	finished  bool
}

func (p *PendingRequests) RegisterFileRead(serverID string, stream pb.AgentService_ConnectServer, req *pb.FileReadRequest) (chan proto.Message, <-chan time.Time) {
	read := &pendingFileRead{stream: stream, mode: req.GetMode(), reply: make(chan proto.Message, 1)}
	if read.mode == pb.FileReadMode_FILE_READ_MODE_IMAGE {
		read.progress = make(chan time.Time, 1)
	}
	key := makeKey(serverID, req.GetRequestId())
	p.mu.Lock()
	p.channels[key] = read.reply
	p.fileReads[key] = read
	p.mu.Unlock()
	return read.reply, read.progress
}

func (p *PendingRequests) DeliverFileRead(serverID string, stream pb.AgentService_ConnectServer, record *pb.FileReadResponse) {
	key := makeKey(serverID, record.GetRequestId())
	p.mu.Lock()
	read := p.fileReads[key]
	p.mu.Unlock()
	if read == nil {
		if record.ChunkOffset == nil {
			p.Deliver(serverID, record.GetRequestId(), record)
		}
		return
	}
	if read.stream == stream {
		read.accept(record)
	}
}

func (r *pendingFileRead) accept(record *pb.FileReadResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished {
		return
	}
	if record.ChunkOffset != nil && record.GetError() == "" {
		r.acceptChunk(record)
		return
	}
	// A one-shot legacy answer may start a reply but cannot be mixed with
	// streamed bytes. A terminal error can end a reply without exposing data.
	legacy := record.ChunkOffset == nil && r.data == nil
	terminalError := record.ChunkOffset != nil && record.GetDone() && len(record.GetData()) == 0
	if legacy || terminalError {
		r.finish(record)
	} else {
		r.finish(nil)
	}
}

func (r *pendingFileRead) acceptChunk(record *pb.FileReadResponse) {
	size := record.GetTotalSize()
	if size < 0 || size > fileview.MaxFileSize || record.GetFailure() != pb.FileReadFailure_FILE_READ_FAILURE_UNSPECIFIED {
		r.finish(nil)
		return
	}
	imageRead := r.mode == pb.FileReadMode_FILE_READ_MODE_IMAGE
	maximum := size
	if !imageRead {
		// ReadFile's tail is relative to the agent's initial stat. A log
		// that grows or rotates while being read can return a different
		// amount; only images require all bytes of the initial file size.
		maximum = fileview.MaxTailSize
	}
	if record.GetChunkOffset() != int64(len(r.data)) || (r.data != nil && r.totalSize != size) {
		r.finish(nil)
		return
	}
	if record.GetDone() {
		if len(record.GetData()) != 0 || (imageRead && int64(len(r.data)) != size) {
			r.finish(nil)
			return
		}
		r.finish(&pb.FileReadResponse{
			RequestId: record.GetRequestId(), ChunkOffset: record.ChunkOffset, Done: true,
			TotalSize: size, MimeType: record.GetMimeType(), Data: r.data,
		})
		return
	}

	r.appendChunk(record.GetData(), size, maximum, imageRead)
}

func (r *pendingFileRead) appendChunk(data []byte, size, maximum int64, imageRead bool) {
	// Require full-size records except at the end, bounding both memory and
	// the number of records a single authorized request can consume.
	length := int64(len(data))
	allowed := min(int64(fileview.MaxChunkSize), maximum-int64(len(r.data)))
	if r.shortData || length <= 0 || length > allowed || (imageRead && length != allowed) {
		r.finish(nil)
		return
	}
	r.shortData = length < fileview.MaxChunkSize
	if r.data == nil {
		r.data = make([]byte, 0, min(maximum, max(length, size)))
		r.totalSize = size
	}
	if int64(len(r.data))+length > int64(cap(r.data)) {
		// Under a growing tail the allocation stays within the same 1 MiB
		// maximum, even if the size reported by the initial stat was small.
		expanded := make([]byte, len(r.data), maximum)
		copy(expanded, r.data)
		r.data = expanded
	}
	r.data = append(r.data, data...)
	r.signalProgress()
}

func (r *pendingFileRead) signalProgress() {
	if r.progress == nil {
		return
	}
	// Keep only the most recent accepted chunk time. The collector lock
	// serializes writers; the HTTP waiter can only remove notifications.
	select {
	case <-r.progress:
	default:
	}
	r.progress <- time.Now()
}

func (r *pendingFileRead) finish(response proto.Message) {
	r.finished = true
	r.data = nil
	select {
	case r.reply <- response:
	default:
	}
}

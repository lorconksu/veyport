package grpcserver

import (
	"testing"

	"github.com/wyiu/veyport/proto/fileview"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
	"google.golang.org/protobuf/proto"
)

func TestPendingImageReadRejectsIncompleteAndOutOfSequenceRecords(t *testing.T) {
	const node = "node"
	request := &pb.FileReadRequest{RequestId: "read", Mode: pb.FileReadMode_FILE_READ_MODE_IMAGE}
	stream := &mockStream{}
	write := func(offset, totalSize int64, data []byte, done bool) *pb.FileReadResponse {
		return &pb.FileReadResponse{RequestId: request.RequestId, ChunkOffset: proto.Int64(offset), TotalSize: totalSize, Data: data, Done: done}
	}
	chunk := make([]byte, fileview.MaxChunkSize)
	for _, tc := range []struct {
		name    string
		records []*pb.FileReadResponse
	}{
		{"short final", []*pb.FileReadResponse{write(0, 2, nil, true)}},
		{"out of order", []*pb.FileReadResponse{write(1, 2, []byte{1, 2}, false)}},
		{"oversized", []*pb.FileReadResponse{write(0, (10<<20)+1, chunk, false)}},
		{"duplicate", []*pb.FileReadResponse{write(0, 2<<20, chunk, false), write(0, 2<<20, chunk, false)}},
		{"changed size", []*pb.FileReadResponse{write(0, 2<<20, chunk, false), write(int64(len(chunk)), 3<<20, chunk, false)}},
		{"unexpected legacy", []*pb.FileReadResponse{write(0, 2<<20, chunk, false), {RequestId: request.RequestId, Data: chunk}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPendingRequests()
			reply, _ := p.RegisterFileRead(node, stream, request)
			for _, record := range tc.records {
				p.DeliverFileRead(node, stream, record)
			}
			select {
			case response := <-reply:
				if response != nil {
					t.Fatal("malformed record yielded usable bytes")
				}
			default:
				t.Fatal("malformed record was silently accepted")
			}
		})
	}

	p := NewPendingRequests()
	reply, _ := p.RegisterFileRead(node, stream, request)
	p.DeliverFileRead(node, &mockStream{}, write(0, 0, nil, true))
	p.DeliverFileRead("other-node", stream, write(0, 0, nil, true))
	p.DeliverFileRead(node, stream, write(0, 3, []byte("png"), false))
	select {
	case <-reply:
		t.Fatal("stale, cross-node, or pre-terminal records finished the read")
	default:
	}
	p.DeliverFileRead(node, stream, write(3, 3, nil, true))
	if resp := (<-reply).(*pb.FileReadResponse); string(resp.GetData()) != "png" || !resp.GetDone() {
		t.Fatal("complete response lost bytes", resp)
	}
}

func TestPendingTailReadPreservesConcurrentChangesInLength(t *testing.T) {
	for _, size := range []int64{0, 9} {
		p := NewPendingRequests()
		req := &pb.FileReadRequest{RequestId: "tail", Mode: pb.FileReadMode_FILE_READ_MODE_CHUNKED_TAIL}
		stream := &mockStream{}
		ch, _ := p.RegisterFileRead("node", stream, req)
		p.DeliverFileRead("node", stream, &pb.FileReadResponse{RequestId: "tail", ChunkOffset: proto.Int64(0), TotalSize: size, Data: []byte("log")})
		p.DeliverFileRead("node", stream, &pb.FileReadResponse{RequestId: "tail", ChunkOffset: proto.Int64(3), TotalSize: size, Done: true, MimeType: "text/plain"})
		select {
		case reply := <-ch:
			resp, _ := reply.(*pb.FileReadResponse)
			if string(resp.GetData()) != "log" || resp.GetTotalSize() != size || resp.GetMimeType() != "text/plain" {
				t.Fatal("log growth or shrinkage changed existing tail result", reply)
			}
		default:
			t.Fatal("missing complete tail")
		}
	}
}

module github.com/wyiu/veyport/agent

go 1.26.6

replace github.com/wyiu/veyport/proto => ../proto

require (
	github.com/creack/pty v1.1.24
	github.com/wyiu/veyport/proto v0.0.0-00010101000000-000000000000
	golang.org/x/sys v0.47.0
	google.golang.org/grpc v1.83.2
)

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

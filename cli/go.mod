module github.com/wyiu/veyport/cli

go 1.26.10

require (
	github.com/wyiu/veyport/proto v0.0.0
	github.com/zalando/go-keyring v0.2.8
	golang.org/x/crypto v0.56.0
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.45.0
)

replace github.com/wyiu/veyport/proto => ../proto

require (
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
)

module github.com/wyiu/veyport/hub

go 1.26.3

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/pquerna/otp v1.5.0
	golang.org/x/crypto v0.50.0
	modernc.org/sqlite v1.47.0
)

require (
	github.com/go-ldap/ldap/v3 v3.4.13
	github.com/wyiu/veyport/agent v0.0.0-00010101000000-000000000000
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
)

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/wyiu/veyport/proto v0.0.0
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.11
	modernc.org/libc v1.70.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/wyiu/veyport/proto => ../proto

replace github.com/wyiu/veyport/agent => ../agent

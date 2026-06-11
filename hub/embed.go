package hub

import "embed"

//go:embed all:web/dist
var FrontendFS embed.FS

//go:embed static/install.sh
var InstallScript []byte

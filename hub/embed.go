package hub

import "embed"

//go:embed all:web/dist
var FrontendFS embed.FS

//go:embed static/install.sh
var InstallScript []byte

//go:embed static/install-cli.sh
var InstallCLIScript []byte

//go:embed static/agent-update.sh
var AgentUpdateScript []byte

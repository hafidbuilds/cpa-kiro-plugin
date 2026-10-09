module github.com/hafidbuilds/cpa-kiro-plugin

go 1.26.0

require (
	github.com/router-for-me/CLIProxyAPI/v8 v8.0.0
	gopkg.in/yaml.v3 v3.0.1
)

// Build against the local CPA fork so plugin ABI additions (for example the
// retry_after_ms/credential_scoped error hints) are available before release.
replace github.com/router-for-me/CLIProxyAPI/v8 => ../CLIProxyAPI

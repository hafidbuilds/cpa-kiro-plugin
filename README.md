# Kiro provider plugin for CLIProxyAPI

This repository builds the Kiro provider plugin for
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI). The plugin adds Kiro
models and Kiro OAuth login to CLIProxyAPI.

The plugin uses CLIProxyAPI's standard native plugin ABI. You do not need a
CLIProxyAPI source checkout.

## Build

Install Go 1.26 or later, then run:

```bash
git clone https://github.com/hafidbuilds/cpa-kiro-plugin.git
cd cpa-kiro-plugin
./build.sh
```

The default output is:

```text
plugins/<goos>/<goarch>/kiro-go.<extension>
```

To build directly into the directory used by CLIProxyAPI, set
`CPA_PLUGIN_DIR`:

```bash
CPA_PLUGIN_DIR=/path/to/plugins ./build.sh
```

Build on the same operating system and architecture that runs CLIProxyAPI.

## Enable the plugin

Set `plugins.dir` to the directory passed to `CPA_PLUGIN_DIR`:

```yaml
plugins:
  enabled: true
  dir: "/path/to/plugins"
  configs:
    kiro-go:
      enabled: true
      models:
        - "*"
```

The plugin ID is `kiro-go`. The provider ID remains `kiro`.

Use exact model IDs instead of `"*"` when you do not want model discovery:

```yaml
      models:
        - "claude-sonnet-4.5"
        - "claude-haiku-4.5"
```

Restart CLIProxyAPI after you add or rebuild the plugin.

## Sign in

Run:

```bash
cliproxyapi --config /path/to/config.yaml --kiro-login
```

The command opens Kiro's browser login page, waits for the callback on
`127.0.0.1:3128`, and saves the credential in CLIProxyAPI's configured auth
directory. Kiro's page handles the available login methods. Keep port `3128`
free.

The CLIProxyAPI client key and the Kiro credential are separate:

- `access.api-keys` authenticates clients such as Claude Code and Codex CLI.
- The Kiro OAuth credential authenticates requests sent to Kiro.

## Use Kiro models

Check the model list:

```bash
curl -fsS http://127.0.0.1:8317/v1/models \
  -H "Authorization: Bearer $CLIPROXY_API_KEY"
```

Use a returned model ID in Claude Code, Codex CLI, or another CLIProxyAPI
client.

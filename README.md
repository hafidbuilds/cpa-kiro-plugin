# Kiro provider plugin for CLIProxyAPI

This repository builds a Kiro provider plugin for [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI). The plugin adds Kiro models to CLIProxyAPI's OpenAI-compatible and Anthropic-compatible endpoints.

Use OAuth for interactive sign-in. Use a Kiro API key for non-interactive setups.

## Install the plugin

Install CLIProxyAPI before you install this plugin. CLIProxyAPI loads the plugin as a compiled library from its `plugins.dir` directory.

Clone this repository anywhere:

```bash
git clone https://github.com/hafidbuilds/cpa-kiro-plugin.git
cd cpa-kiro-plugin
```

You need Go 1.26 or later to build the plugin. The build uses the released CLIProxyAPI SDK, so you do not need a CLIProxyAPI source checkout.

Build the plugin:

```bash
./build.sh
```

By default, `build.sh` writes the library to `plugins/<goos>/<goarch>/kiro-go.<extension>`. If your CLIProxyAPI config uses another plugin directory, set `CPA_PLUGIN_DIR`:

```bash
CPA_PLUGIN_DIR=/path/to/plugins ./build.sh
```

Build for the operating system and architecture where CLIProxyAPI runs. If CLIProxyAPI runs in Podman, build the plugin inside a matching Linux container.

## Configure CLIProxyAPI

Add a client key and enable the plugin in `config.yaml`:

```yaml
access:
  api-keys:
    - "local-dev-key"

plugins:
  enabled: true
  dir: "plugins"
  configs:
    kiro-go:
      enabled: true
      priority: 1
      models:
        - "*"
```

Set `plugins.dir` to the same directory that you pass to `CPA_PLUGIN_DIR`. With `dir: "plugins"`, run CLIProxyAPI from this repository or use an absolute plugin path.

`access.api-keys` authenticates Claude Code, Codex CLI, and other clients to CLIProxyAPI. It is separate from the Kiro credential.

Use `"*"` to let the plugin discover the models available to each Kiro account. To restrict the list, use exact model IDs:

```yaml
      models:
        - "claude-sonnet-4.5"
        - "claude-haiku-4.5"
```

The plugin falls back to Claude Sonnet 4.5 and Claude Haiku 4.5 when discovery has no cached result and the config uses `"*"`.

## Sign in to Kiro

After you enable the plugin, run:

```bash
cliproxyapi --kiro-login
```

If CLIProxyAPI uses a non-default config file, pass it with `--config`:

```bash
cliproxyapi --config /path/to/cliproxyapi.conf --kiro-login
```

The command opens Kiro's browser login page, waits for sign-in, and saves the credential in CLIProxyAPI's configured auth directory. Kiro's page handles the available login methods. The browser callback uses `127.0.0.1:3128`, so keep that port free.

The plugin must be enabled before CLIProxyAPI can register `--kiro-login`. Restart CLIProxyAPI after you add or rebuild the plugin.

## Start CLIProxyAPI and check the models

Start CLIProxyAPI with the config that enables the plugin:

```bash
cliproxyapi --config /path/to/cliproxyapi.conf
```

Set the client key in the shell that runs the checks:

```bash
export CLIPROXY_API_KEY="local-dev-key"
```

Check the server and list the models:

```bash
curl -fsS http://127.0.0.1:8317/healthz

curl -fsS http://127.0.0.1:8317/v1/models \
  -H "Authorization: Bearer $CLIPROXY_API_KEY"
```

Use a model ID from the response in your client configuration.

## Use Claude Code

Run Claude Code with CLIProxyAPI as its gateway:

```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:8317"
export ANTHROPIC_AUTH_TOKEN="$CLIPROXY_API_KEY"
export ANTHROPIC_MODEL="claude-sonnet-4.5"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="claude-haiku-4.5"

claude --model "$ANTHROPIC_MODEL"
```

Do not add `/v1` to `ANTHROPIC_BASE_URL`. Claude Code adds `/v1/messages`.

## Use Codex CLI

Create `~/.codex/kiro.config.toml`:

```toml
model = "claude-sonnet-4.5"
model_provider = "cliproxy_kiro"

[model_providers.cliproxy_kiro]
name = "CLIProxyAPI Kiro"
base_url = "http://127.0.0.1:8317/v1"
wire_api = "responses"
env_key = "CLIPROXY_API_KEY"
```

Set the client key and start Codex with the profile:

```bash
export CLIPROXY_API_KEY="local-dev-key"
codex --profile kiro
```

Do not set `requires_openai_auth = true`. That setting makes Codex use OpenAI authentication instead of `env_key`.

## Use a Kiro API key instead

Use an API key when the login command cannot open a browser or when you need a non-interactive setup.

Create `.env` in the directory where CLIProxyAPI starts:

```dotenv
KIRO_API_KEY=replace-with-your-kiro-key
```

Create `~/.cli-proxy-api/kiro-pro.json`:

```json
{
  "type": "kiro",
  "label": "kiro-pro",
  "region": "us-east-1",
  "api_key_env": "KIRO_API_KEY"
}
```

CLIProxyAPI reads `KIRO_API_KEY` when the plugin sends a request. The auth file stores the variable name, not the key. Do not commit `.env` or the auth file.

If CLIProxyAPI runs in Podman, pass the variable into the container with `--env-file .env`, `--env KIRO_API_KEY`, or a Podman secret.

## Troubleshoot login and startup

- If `--kiro-login` does not appear in `cliproxyapi --help`, enable the plugin and check `plugins.dir`.
- If the plugin does not load, check the library's operating system, architecture, filename, and config path.
- If CLIProxyAPI returns `401`, check `CLIPROXY_API_KEY` and `access.api-keys`.
- If Kiro returns `401` or `403`, check the Kiro credential, region, and the environment seen by the CLIProxyAPI process.
- If browser login cannot return to the terminal, free port `3128` and run the command again.

The Kiro runtime protocol is not a public model API. Kiro may change it without notice.

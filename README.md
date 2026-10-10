# Kiro provider plugin for CLIProxyAPI

This repository contains the source code for a Kiro provider plugin. CLIProxyAPI loads the plugin as a compiled dynamic library and exposes Kiro models through its OpenAI-compatible and Anthropic-compatible endpoints.

Use the built-in Kiro OAuth flow for interactive sign-in. The plugin also accepts a Kiro API key for non-interactive setups.

## Why the plugin has its own repository

CLIProxyAPI loads compiled libraries from its `plugins` directory. It does not load Go source files from that directory.

Keep the two repositories beside each other:

```text
parent-directory/
├── CLIProxyAPI/
│   └── plugins/
│       └── <goos>/<goarch>/kiro-go.<extension>
└── cpa-kiro-plugin/
    ├── *.go
    └── go.mod
```

`cpa-kiro-plugin` contains the source code. The `CLIProxyAPI/plugins` directory contains the compiled library that the server loads at runtime.

This layout keeps Kiro protocol code out of the CLIProxyAPI core. You can update or remove the plugin without changing the main server binary.

The `replace` directive in `go.mod` points to `../CLIProxyAPI`, so the two checkouts must be siblings unless you change that directive:

```go
replace github.com/router-for-me/CLIProxyAPI/v8 => ../CLIProxyAPI
```

## Before you start

You need:

- a CLIProxyAPI checkout beside this repository;
- Go 1.26 or later;
- a Kiro account, or a Kiro API key for non-interactive setup;
- a client key for CLIProxyAPI, such as `local-dev-key`; and
- Claude Code or Codex CLI if you want to test a client.

The two keys have different jobs:

- `KIRO_API_KEY` authenticates CLIProxyAPI to Kiro. Keep it on the server side.
- `local-dev-key` authenticates Claude Code or Codex CLI to CLIProxyAPI. Configure it under `access.api-keys` in `config.yaml`.

## Build and install the plugin

Run the build from the root of this repository. The command writes the library into the sibling CLIProxyAPI checkout.

```bash
plugin_os="$(go env GOOS)"
plugin_arch="$(go env GOARCH)"

case "$plugin_os" in
  darwin) plugin_ext="dylib" ;;
  windows) plugin_ext="dll" ;;
  *) plugin_ext="so" ;;
esac

mkdir -p "../CLIProxyAPI/plugins/$plugin_os/$plugin_arch"

CGO_ENABLED=1 go build -buildmode=c-shared \
  -o "../CLIProxyAPI/plugins/$plugin_os/$plugin_arch/kiro-go.$plugin_ext" .

rm -f "../CLIProxyAPI/plugins/$plugin_os/$plugin_arch/kiro-go.h"
```

The output name `kiro-go.dylib`, `kiro-go.so`, or `kiro-go.dll` gives the plugin its configuration ID: `kiro-go`.

Build for the operating system and architecture where CLIProxyAPI runs. Your source checkout's platform does not matter if you cross-compile the library for the server.

For CLIProxyAPI in a Podman Linux ARM64 container on an Apple Silicon Mac, run this command from the plugin repository:

```bash
podman run --rm \
  -v "$PWD/..:/src" \
  -w /src/cpa-kiro-plugin \
  docker.io/library/golang:1.26 \
  sh -c 'mkdir -p /src/CLIProxyAPI/plugins/linux/arm64 && CGO_ENABLED=1 go build -buildmode=c-shared -o /src/CLIProxyAPI/plugins/linux/arm64/kiro-go.so . && rm -f /src/CLIProxyAPI/plugins/linux/arm64/kiro-go.h'
```

The container mount includes both repositories, so the `replace` directive can resolve `../CLIProxyAPI` during the build. Podman uses the `docker.io/library/golang:1.26` OCI image and does not require a Docker daemon.

## Configure CLIProxyAPI

Add a client key and enable the plugin in CLIProxyAPI's `config.yaml`:

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

The current CLIProxyAPI v8 configuration uses `access.api-keys`. CLIProxyAPI also accepts the legacy top-level `api-keys` field.

The plugin ID is `kiro-go` because that is the compiled library's basename. The provider ID used by auth records and model ownership is `kiro`.

`"*"` enables account-specific model discovery. To restrict the list, use exact model IDs:

```yaml
      models:
        - "claude-sonnet-4.5"
        - "claude-haiku-4.5"
```

The plugin caches discovery results for five minutes. If a refresh fails, it keeps the last successful result. On a cold start, it falls back to the configured models. If the configuration contains `"*"`, the fallback is Claude Sonnet 4.5 and Claude Haiku 4.5.

The plugin also accepts these optional compatibility settings:

```yaml
    kiro-go:
      enabled: true
      priority: 1
      models:
        - "*"
      kiro_version: "0.11.107"
      node_version: "22.22.0"
      system_version: "linux#6.6.87"
```

These values become compatibility headers in requests to Kiro. Use the defaults unless Kiro requires different values.

## Sign in to Kiro

After you enable the plugin, run:

```bash
cliproxyapi --kiro-login
```

The command opens Kiro's browser login page, waits for sign-in, and saves the resulting credential in CLIProxyAPI's configured auth directory. Kiro's page handles the available login methods. The browser callback uses `127.0.0.1:3128`, so keep that port free. If the browser does not open, copy the `Login URL` printed by the command.

If CLIProxyAPI uses a non-default configuration file, add `--config`:

```bash
cliproxyapi --config /path/to/cliproxyapi.conf --kiro-login
```

The plugin must be enabled before CLIProxyAPI can register `--kiro-login`. See [Configure CLIProxyAPI](#configure-cliproxyapi).

## Use an API key instead

Create `.env` in the directory from which CLIProxyAPI starts:

```dotenv
KIRO_API_KEY=replace-with-your-kiro-key
```

CLIProxyAPI loads this file at startup. Do not commit it.

If CLIProxyAPI runs in Podman, pass the variable into the container with `--env-file .env`, `--env KIRO_API_KEY`, or a Podman secret. The container does not inherit the host shell environment or the host `.env` file automatically.

Create an auth record in CLIProxyAPI's configured auth directory. The default directory is `~/.cli-proxy-api`:

```text
~/.cli-proxy-api/kiro-pro.json
```

Use this file content:

```json
{
  "type": "kiro",
  "label": "kiro-pro",
  "region": "us-east-1",
  "api_key_env": "KIRO_API_KEY"
}
```

For the repository's Podman bind mount, create `auths/kiro-pro.json` on the host if that directory maps to `/root/.cli-proxy-api` in the container.

Protect the file:

```bash
chmod 600 ~/.cli-proxy-api/kiro-pro.json
```

Use the bind-mounted host path when the file lives in `auths/`:

```bash
chmod 600 auths/kiro-pro.json
```

`api_key_env` stores the environment-variable name. The plugin resolves the key when it sends a request and does not write the key into the auth record.

You can also provide the key inline:

```json
{
  "type": "kiro",
  "label": "kiro-pro",
  "region": "us-east-1",
  "api_key": "replace-with-your-kiro-key"
}
```

Use `api_key_env` or a Podman secret when possible.

Restart CLIProxyAPI after you add or change the plugin library, the plugin configuration, or the auth record.

## Verify the server

Set the client key in the shell that runs the checks:

```bash
export CLIPROXY_API_KEY="local-dev-key"
```

Check the server:

```bash
curl -fsS http://127.0.0.1:8317/healthz
```

List the models:

```bash
curl -fsS http://127.0.0.1:8317/v1/models \
  -H "Authorization: Bearer $CLIPROXY_API_KEY"
```

Use a model ID from this response in the client configuration. To print only Kiro-owned models:

```bash
curl -fsS http://127.0.0.1:8317/v1/models \
  -H "Authorization: Bearer $CLIPROXY_API_KEY" \
  | jq -r '.data[] | select(.owned_by == "kiro") | .id'
```

## Use the plugin with Claude Code

Claude Code uses the plugin's native Anthropic Messages format.

Run these commands in the shell that starts Claude Code:

```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:8317"
export ANTHROPIC_AUTH_TOKEN="$CLIPROXY_API_KEY"
export ANTHROPIC_MODEL="claude-sonnet-4.5"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="claude-haiku-4.5"
export CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1
```

Do not add `/v1` to `ANTHROPIC_BASE_URL`. Claude Code adds `/v1/messages`.

`ANTHROPIC_AUTH_TOKEN` must contain the CLIProxyAPI client key. It must not contain `KIRO_API_KEY`.

Set `ANTHROPIC_MODEL` and `ANTHROPIC_DEFAULT_HAIKU_MODEL` to model IDs returned by `/v1/models`.

Gateway model discovery requires Claude Code 2.1.129 or later. It adds the proxy's models to the `/model` picker.

For persistent settings, put the same variables in the `env` object of `~/.claude/settings.json` or in a gitignored `.claude/settings.local.json`. Do not commit credentials in `.claude/settings.json`.

Start an interactive session:

```bash
claude --model "$ANTHROPIC_MODEL"
```

Run a non-interactive test:

```bash
claude -p --model "$ANTHROPIC_MODEL" \
  "Find the main entry point and name its file."
```

Run `/status` inside Claude Code. The status must show `http://127.0.0.1:8317` as the Anthropic base URL and `ANTHROPIC_AUTH_TOKEN` as the credential source.

CLIProxyAPI logs should show `/v1/messages`, the `kiro` provider, and a request to `https://runtime.<region>.kiro.dev/`.

See Anthropic's [gateway connection guide](https://code.claude.com/docs/en/llm-gateway-connect) for Claude Code's configuration precedence.

## Use the plugin with Codex CLI

Codex CLI sends OpenAI Responses API requests. Configure a custom provider with `wire_api = "responses"`.

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

Keep the client key in the shell that starts Codex:

```bash
export CLIPROXY_API_KEY="local-dev-key"
```

Use a user profile at `~/.codex/kiro.config.toml`. Current Codex versions ignore provider and auth settings in project configuration files.

Do not set `requires_openai_auth = true`. That setting makes Codex use OpenAI authentication instead of `env_key`.

Start an interactive session:

```bash
codex --profile kiro
```

Run a read-only, non-interactive test:

```bash
codex exec --profile kiro \
  "Find the main entry point and name its file."
```

Override the model for one session:

```bash
codex --profile kiro --model claude-haiku-4.5
```

CLIProxyAPI logs should show `/v1/responses`, the `kiro` provider, and a request to `https://runtime.<region>.kiro.dev/`.

See OpenAI's [custom model provider documentation](https://developers.openai.com/codex/config-advanced/#custom-model-providers) for the full provider configuration reference.

## Use Kiro OAuth instead of an API key

The plugin registers Kiro login handlers with CLIProxyAPI. Start a login session through the shared v8 Management API:

```http
GET /v8/management/oauth/auth-url?provider=kiro
Authorization: Bearer <management-key>
```

The response contains a login URL and a `state` value. Poll the login state until the response reports `ok` or `error`:

```http
GET /v8/management/oauth/status?state=<state>
Authorization: Bearer <management-key>
```

The implementation supports Builder ID, IAM Identity Center, and Kiro social login flows. The API-key setup above does not require a Management API key.

## Troubleshoot common failures

| Symptom | Check |
| --- | --- |
| `connection refused` or `/healthz` fails | Confirm that CLIProxyAPI runs on port 8317. For Podman, publish the port and check `podman ps`. |
| The plugin does not load | Confirm `plugins.enabled` and `kiro-go.enabled` are `true`. Confirm that the library matches CLIProxyAPI's operating system and architecture. Check the startup log for `kiro-go`. |
| CLIProxyAPI returns `401` | Confirm that the client sends a key listed under `access.api-keys`. Check `CLIPROXY_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, or the Codex provider's `env_key`. |
| Kiro returns `401` or `403` | Confirm that `KIRO_API_KEY` is visible to the CLIProxyAPI process or container. Confirm that the auth record uses the Kiro account's region. |
| `auth_unavailable: no auth available` | Confirm that the model appears in `/v1/models`, the auth JSON contains `"type": "kiro"`, and the plugin model list contains the exact model ID. Restart CLIProxyAPI after changing the credential. |
| Claude Code starts its normal login | Start Claude Code from the shell that contains the gateway variables. Check `/status`. `ANTHROPIC_AUTH_TOKEN` takes precedence over a saved Claude login. |
| Kiro models do not appear in Claude Code's `/model` picker | Set `CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1`. Use Claude Code 2.1.129 or later. Make sure that `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` is not set. |
| Codex uses OpenAI auth or the wrong endpoint | Put the provider in `~/.codex/kiro.config.toml`. Select it with `--profile kiro`. Leave `requires_openai_auth` unset. Confirm that `base_url` ends in `/v1`. |
| Claude Code works but Codex output or usage is incomplete | Use a CLIProxyAPI build that contains the OpenAI-to-Claude translator changes tracked in [issue #4815](https://github.com/router-for-me/CLIProxyAPI/issues/4815). |

## Request flow

1. CLIProxyAPI reads an auth file whose `type` is `kiro`.
2. The plugin discovers and allow-lists the models for that Kiro account.
3. CLIProxyAPI selects a compatible Kiro credential with its normal routing logic.
4. CLIProxyAPI translates the client request to the plugin's Claude format when needed.
5. The plugin converts messages, tools, tool results, images, system instructions, and generation settings to Kiro conversation-state JSON.
6. The plugin asks CLIProxyAPI's host HTTP bridge to send a request to `https://runtime.<region>.kiro.dev/`.
7. The plugin decodes Kiro's AWS EventStream response.
8. The plugin returns Claude JSON or Claude SSE. CLIProxyAPI translates the response back to the client protocol when needed.

## Limitations

- Kiro documents the subscription API key, but Kiro's runtime protocol is not a public model API and may change.
- Complete non-streaming OpenAI-compatible support depends on the translator changes tracked in [issue #4815](https://github.com/router-for-me/CLIProxyAPI/issues/4815).
- Model discovery uses Kiro's internal `ListAvailableModels` service. Kiro may change that service.
- The plugin refreshes discovery when CLIProxyAPI registers an auth. The five-minute cache prevents repeated calls, but the plugin does not run a background refresh.
- CLIProxyAPI's model registry has no credit-multiplier field. The plugin does not expose Kiro's per-model credit multiplier.
- `/v1/messages/count_tokens` returns a local estimate marked as such.
- The initial implementation does not forward web search server tools.
- The plugin rejects assistant-prefill requests because Kiro requires the current message to be a user message.
- Kiro compatibility header versions are configurable because Kiro may change its header requirements.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for implementation provenance.

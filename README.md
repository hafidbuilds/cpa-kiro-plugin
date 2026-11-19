# Kiro provider plugin for CLIProxyAPI

This repository builds a native Rust plugin for
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI). The plugin adds Kiro
models and Kiro login without a Go runtime or a CLIProxyAPI source checkout.

The plugin ID is `kiro-go`. The provider ID is `kiro`.

## Build the plugin

Install Rust with [rustup](https://rustup.rs/), then run:

```bash
git clone https://github.com/hafidbuilds/cpa-kiro-plugin.git
cd cpa-kiro-plugin
./build.sh
```

The build writes the plugin to:

```text
plugins/<goos>/<goarch>/kiro-go.<extension>
```

Set `CPA_PLUGIN_DIR` to write directly to the directory that CLIProxyAPI uses:

```bash
CPA_PLUGIN_DIR=/path/to/plugins ./build.sh
```

Build on the same operating system and architecture that runs CLIProxyAPI. The
macOS artifact and macOS CPA load have been verified. A Linux artifact has been
cross-built with MacPorts Zig, but Linux CPA load has not been verified.

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

Use exact model IDs instead of `"*"` to disable account model discovery:

```yaml
      models:
        - "claude-sonnet-4.5"
        - "claude-haiku-4.5"
```

Restart CLIProxyAPI after you add or rebuild the plugin.

The plugin emits data-only Claude SSE chunks for CPA's translator input contract.
This keeps streaming output compatible with Responses clients such as Pi; an
`event:` prefix on each plugin chunk would cause that translator to drop it.

### Multiple accounts and pacing

Kiro throttles bursts on one account with `USER_REQUEST_RATE_EXCEEDED`, even
when CPA rotates between accounts. When several coding agents share the
gateway, the plugin spaces requests per account. A request that would wait
longer than `max_token_interval` is refused with a short 429, so CPA moves it
to another account:

```yaml
    kiro-go:
      enabled: true
      min_token_interval: 1s   # minimum gap between two requests of one account
      max_token_interval: 2s   # upper bound of the gap and of the queue wait
      suspend_cooldown: 1h     # how long a suspended account stays out of rotation
```

The plugin also handles these account conditions:

- An account that reports its monthly limit is skipped until the next UTC
  midnight, then checked again.
- An account Kiro answers with `403 User is not authorized to make this call`
  is disabled in its auth file with a note. Re-enable it in the management
  panel once the block is lifted.
- When Kiro rejects an access token, the plugin refreshes it once, saves it to
  the auth file, and retries the request.
- Set `"disable_cooling": true` in one auth file to opt that account out of
  pacing and benching.

## Sign in

Run:

```bash
cliproxyapi --config /path/to/config.yaml --kiro-login
```

The command opens Kiro's login page and waits for the callback on
`127.0.0.1:3128`. Kiro's page provides the available login methods. Keep port
`3128` free.

The credential is saved as `kiro-<method>-<email>.json`. Signing in to the
same account again replaces that file; signing in to another account adds a
new one.

CLIProxyAPI uses two separate credentials:

- `access.api-keys` authenticates clients such as Claude Code and Codex CLI.
- The Kiro credential authenticates requests sent to Kiro.

## Use Kiro models

Query the model list:

```bash
curl -fsS http://127.0.0.1:8317/v1/models \
  -H "Authorization: Bearer $CLIPROXY_API_KEY"
```

Send requests with a model ID from the response. With `models: ["*"]`, each
account lists the models Kiro offers it.

## Check account quota

The plugin reports each account's Kiro credits to CPA's management API:

```bash
curl -fsS "http://127.0.0.1:8317/v0/management/plugins/kiro-go/quota?auth_index=<auth-index>" \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY"
```

Get `auth_index` from `GET /v0/management/auth-files`.

## Run an end-to-end smoke test

Use a disposable CPA configuration, a disposable client key, and a Kiro account.
The test needs network access to Kiro.

1. Build the plugin into a temporary directory:

   ```bash
   CPA_PLUGIN_DIR=/tmp/cpa-kiro-smoke/plugins ./build.sh
   ```

2. Create `/tmp/cpa-kiro-smoke/config.yaml`:

   ```yaml
   config-version: 8
   server:
     host: "127.0.0.1"
     port: 8317
   oauth:
     auth-dir: "/tmp/cpa-kiro-smoke/auth"
   access:
     api-keys:
       - "REPLACE_WITH_A_DISPOSABLE_CPA_CLIENT_KEY"
   plugins:
     enabled: true
     dir: "/tmp/cpa-kiro-smoke/plugins"
     configs:
       kiro-go:
         enabled: true
         models:
           - "*"
   ```

3. Start CPA:

   ```bash
   cliproxyapi --config /tmp/cpa-kiro-smoke/config.yaml
   ```

4. In another terminal, start login:

   ```bash
   cliproxyapi --config /tmp/cpa-kiro-smoke/config.yaml --kiro-login
   ```

   Complete the browser flow. Confirm that CPA writes a credential under
   `/tmp/cpa-kiro-smoke/auth`.

5. Set the client key and query models:

   ```bash
   export CPA_URL=http://127.0.0.1:8317
   export CPA_CLIENT_API_KEY=REPLACE_WITH_A_DISPOSABLE_CPA_CLIENT_KEY
   curl -fsS "$CPA_URL/v1/models" \
     -H "Authorization: Bearer $CPA_CLIENT_API_KEY"
   ```

6. Send a non-streaming request:

   ```bash
   curl -fsS "$CPA_URL/v1/messages" \
     -H "Authorization: Bearer $CPA_CLIENT_API_KEY" \
     -H "Content-Type: application/json" \
     -H "anthropic-version: 2023-06-01" \
     -d '{"model":"REPLACE_WITH_A_LISTED_KIRO_MODEL","max_tokens":32,"messages":[{"role":"user","content":"Reply with one word: hello"}]}'
   ```

7. Send a streaming request:

   ```bash
   curl -fsS -N "$CPA_URL/v1/messages" \
     -H "Authorization: Bearer $CPA_CLIENT_API_KEY" \
     -H "Content-Type: application/json" \
     -H "anthropic-version: 2023-06-01" \
     -d '{"model":"REPLACE_WITH_A_LISTED_KIRO_MODEL","max_tokens":32,"stream":true,"messages":[{"role":"user","content":"Reply with one word: hello"}]}'
   ```

8. Send a tool request:

   ```bash
   curl -fsS "$CPA_URL/v1/messages" \
     -H "Authorization: Bearer $CPA_CLIENT_API_KEY" \
     -H "Content-Type: application/json" \
     -H "anthropic-version: 2023-06-01" \
     -d '{"model":"REPLACE_WITH_A_LISTED_KIRO_MODEL","max_tokens":64,"tools":[{"name":"lookup","description":"Look up a value","input_schema":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}}],"tool_choice":{"type":"auto"},"messages":[{"role":"user","content":"Use the lookup tool for q=hello. Do not answer with normal text."}]}'
   ```

9. Send an image request only if the selected model and account support images:

   ```bash
   export IMAGE_BASE64=REPLACE_WITH_BASE64_IMAGE_BYTES
   curl -fsS "$CPA_URL/v1/messages" \
     -H "Authorization: Bearer $CPA_CLIENT_API_KEY" \
     -H "Content-Type: application/json" \
     -H "anthropic-version: 2023-06-01" \
     -d "{\"model\":\"REPLACE_WITH_A_LISTED_KIRO_MODEL\",\"max_tokens\":32,\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"image\",\"source\":{\"type\":\"base64\",\"media_type\":\"image/png\",\"data\":\"$IMAGE_BASE64\"}},{\"type\":\"text\",\"text\":\"Describe this image briefly.\"}]}]}"
   ```

10. Use disposable credentials to test expired-token refresh, invalid-token
    handling, quota errors, and normal CPA shutdown. Do not expose credential
    contents in logs or bug reports.

## Deferred work

- TODO: sign in from the management panel (a plugin login page). Use
  `--kiro-login` until then.
- TODO: load the Linux plugin artifact with a Linux CPA runtime.
- TODO: add cancellation-driven upstream stream cleanup when CPA exposes a
  cancellation signal in its plugin ABI.

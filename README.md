# Kiro provider plugin for CLIProxyAPI

This repository builds the native Rust Kiro provider plugin for
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI). The plugin adds Kiro
models and Kiro OAuth login to CLIProxyAPI without starting a second runtime or
requiring a CLIProxyAPI source checkout.

The native Rust implementation is the production implementation. Compatibility fixtures and the rewrite plan preserve the former Go behavior as historical reference material; the removed Go sources are no longer required to build or run the plugin.

## Build

Install Rust through [rustup](https://rustup.rs/), then run:

```bash
git clone https://github.com/hafidbuilds/cpa-kiro-plugin.git
cd cpa-kiro-plugin
./build.sh
```

The default output is:

```text
plugins/<goos>/<goarch>/kiro-go.<extension>
```

To build directly into the directory used by CLIProxyAPI, set `CPA_PLUGIN_DIR`:

```bash
CPA_PLUGIN_DIR=/path/to/plugins ./build.sh
```

Build on the same operating system and architecture that runs CLIProxyAPI. macOS builds are verified locally. Linux cross-build and CPA load verification are intentionally deferred to a Linux CI or host; run the Linux target build and CPA smoke before publishing a Linux artifact.

## Deferred TODOs

- TODO: build and validate the Linux plugin artifact on a Linux host.
- TODO: load the Linux artifact with CPA and run the Linux integration smoke test.
- TODO: add cancellation-driven upstream stream cleanup when CPA exposes a cancellation signal in its plugin ABI.

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

## Manual end-to-end smoke

The following checks require an installed CLIProxyAPI binary, a disposable
CLIProxyAPI configuration, a Kiro account, and network access to Kiro. They are
manual checks only; this repository does not include credentials, a CPA binary,
or a fake upstream.

1. Build the plugin into the directory used by the test configuration:

   ```bash
   CPA_PLUGIN_DIR=/tmp/cpa-kiro-smoke/plugins ./build.sh
   ```

2. Create a test configuration that enables the plugin and points CPA at that
   directory. Replace the client key, auth directory, and model as needed:

   ```yaml
   plugins:
     enabled: true
     dir: "/tmp/cpa-kiro-smoke/plugins"
     configs:
       kiro-go:
         enabled: true
         models:
           - "*"
   access:
     api-keys:
       - "REPLACE_WITH_A_DISPOSABLE_CPA_CLIENT_KEY"
   ```

   The auth directory is selected by the CPA configuration. Keep it disposable
   and record its path as `CPA_AUTH_DIR`; do not paste credential contents into
   logs or bug reports.

3. Start CPA with the test configuration, then sign in in a separate terminal:

   ```bash
   cliproxyapi --config /tmp/cpa-kiro-smoke/config.yaml
   cliproxyapi --config /tmp/cpa-kiro-smoke/config.yaml --kiro-login
   ```

   Keep `127.0.0.1:3128` available. Complete the browser flow and verify that
   CPA writes a Kiro credential under `CPA_AUTH_DIR` using the host's normal
   auth-file naming and permissions. The login and persistence checks cannot be
   completed without browser interaction and a real Kiro account.

4. Use the client API key to query models and send requests through CPA:

   ```bash
   export CPA_URL=http://127.0.0.1:8317
   export CPA_CLIENT_API_KEY=REPLACE_WITH_THE_DISPOSABLE_CPA_CLIENT_KEY
   curl -fsS "$CPA_URL/v1/models" \
     -H "Authorization: Bearer $CPA_CLIENT_API_KEY"

   curl -fsS "$CPA_URL/v1/messages" \
     -H "Authorization: Bearer $CPA_CLIENT_API_KEY" \
     -H "Content-Type: application/json" \
     -H "anthropic-version: 2023-06-01" \
     -d '{"model":"REPLACE_WITH_A_LISTED_KIRO_MODEL","max_tokens":32,"messages":[{"role":"user","content":"Reply with one word: hello"}]}'

   curl -fsS -N "$CPA_URL/v1/messages" \
     -H "Authorization: Bearer $CPA_CLIENT_API_KEY" \
     -H "Content-Type: application/json" \
     -H "anthropic-version: 2023-06-01" \
     -d '{"model":"REPLACE_WITH_A_LISTED_KIRO_MODEL","max_tokens":32,"stream":true,"messages":[{"role":"user","content":"Reply with one word: hello"}]}'
   curl -fsS "$CPA_URL/v1/messages" \
     -H "Authorization: Bearer $CPA_CLIENT_API_KEY" \
     -H "Content-Type: application/json" \
     -H "anthropic-version: 2023-06-01" \
     -d '{"model":"REPLACE_WITH_A_LISTED_KIRO_MODEL","max_tokens":64,"tools":[{"name":"lookup","description":"Look up a value","input_schema":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}}],"tool_choice":{"type":"auto"},"messages":[{"role":"user","content":"Use the lookup tool for q=hello."}]}'

   # Set IMAGE_BASE64 to bytes from a local image only when the selected model
   # and account support image input.
   export IMAGE_BASE64=REPLACE_WITH_BASE64_IMAGE_BYTES
   curl -fsS "$CPA_URL/v1/messages" \
     -H "Authorization: Bearer $CPA_CLIENT_API_KEY" \
     -H "Content-Type: application/json" \
     -H "anthropic-version: 2023-06-01" \
     -d "{\"model\":\"REPLACE_WITH_A_LISTED_KIRO_MODEL\",\"max_tokens\":32,\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"image\",\"source\":{\"type\":\"base64\",\"media_type\":\"image/png\",\"data\":\"$IMAGE_BASE64\"}},{\"type\":\"text\",\"text\":\"Describe this image briefly.\"}]}]}"
   ```

   The tool and image commands are examples of request shapes, not proof that
   the selected model accepts those capabilities.

5. Exercise credential and shutdown behavior only with disposable credentials
   and an approved test account. An expired access token with a valid refresh
   token is required for the refresh check. An intentionally invalid token is
   required for the invalid-token status check. A real account or provider
   test fixture that returns a quota condition is required for the quota/status
   check. Stop the foreground CPA process with its normal shutdown mechanism
   and verify a clean process exit with no plugin crash; do not claim these
   checks from unit or compatibility tests alone.

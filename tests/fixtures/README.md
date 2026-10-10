# Phase 0 Go contract fixtures

Frozen CPA/Kiro JSON captured from `../cpa-kiro-plugin` handlers and tests,
cross-checked against `src/dispatch.rs` envelopes. These files are the
behavior contract for later Rust tests. Do not treat live timestamps, random
UUIDs, or secrets in the Go tree as part of the contract.

## Provenance

| Area | Go sources |
| --- | --- |
| Wire envelope | `main.go` (`envelope`, `pluginError`, `okEnvelope`, `errorEnvelope`) |
| Method names / schema | `CLIProxyAPI/sdk/pluginabi` (`SchemaVersion = 6`) |
| Registration, models, auth, executor RPC types | `CLIProxyAPI/sdk/pluginapi` (exported names, **no `json` tags**) |
| Plugin registration payload | `main.go` `pluginRegistration` |
| Auth parse/refresh | `kiro_auth.go`, `oauth_test.go`, `kiro_test.go` |
| Device login | `login.go`, `login_test.go` |
| Model discovery | `model_discovery.go`, `model_discovery_test.go` |
| Executor + host HTTP | `kiro_executor.go`, `kiro_test.go` |
| Upstream Kiro JSON | `wire_protocol.go`, `claude_to_kiro.go` |
| EventStream frames | `eventstream.go`, `testEventFrame` in `kiro_test.go` |
| Classified errors | `upstream_errors.go` |

`pluginapi` structs serialize as **PascalCase** field names (`FileName`,
`StorageJSON`, `Payload`). Plugin-owned types (`kiroCredential`, Kiro runtime
JSON, Claude JSON, `envelope`) use the tags in the Go sources (`type`,
`auth_method`, `conversationState`, `ok`).

`[]byte` fields (`RawJSON`, `StorageJSON`, `Payload`, `config_yaml`, host
`Body`) are standard Base64.

## Normalization

Fixtures replace non-deterministic values:

| Kind | Fixture value |
| --- | --- |
| Clock | `2026-10-10T00:00:00Z` (`login_test.go` `withFakeClock`) |
| Login state | `kiro-TESTSTATE` (Go prefix is `kiro-`; remainder is HMAC-random) |
| Claude message `id` | `msg_TESTMESSAGEID` (Go: `msg_` + UUID without hyphens) |
| `agentContinuationId` / SDK invocation IDs | `00000000-0000-4000-8000-000000000001` |
| User-agent machine suffix | `REDACTED_MACHINE_ID` |
| Tokens, client secrets, API keys | `REDACTED_*` placeholders |
| Zero `pluginapi` fields | omitted unless a handler reads them |

`conversationId` is **not** random when the first user text is non-empty. Go
builds a SHA-1 UUID (`buildKiroConversationID`) from
`model + "\n" + system + "\n" + first user text`. Those IDs are stored as-is.

Pretty-printed JSON is for review. Semantic comparison should ignore
insignificant whitespace and object key order.

## Envelope

Success: `{"ok":true,"result":...}`.

Failure: `{"ok":false,"error":{"code","message", optional
`http_status`,`retryable`,`retry_after_ms`,`credential_scoped`}}`.

Zero `http_status` is omitted (`omitempty`). Unknown methods return this
error JSON from `handleMethod` with ABI status 0.

## Rust dispatch notes (not the contract)

`src/dispatch.rs` currently wraps the same `ok`/`result` envelope.
Several request paths also accept snake_case aliases (`storage_json`,
`host_callback_id`, `status_code`). Auth parse currently returns the raw
credential as `Auth` instead of `pluginapi.AuthData`. Compare Rust output to
these Go fixtures, not the other way around.

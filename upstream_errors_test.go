package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const testOAuthStorage = `{"type":"kiro","auth_method":"desktop","access_token":"oauth-access","refresh_token":"oauth-refresh","profile_arn":"arn:aws:codewhisperer:us-east-1:111111111111:profile/QUOTA"}`

func withUpstreamClock(t *testing.T, now time.Time) {
	t.Helper()
	previous := upstreamNow
	upstreamNow = func() time.Time { return now }
	t.Cleanup(func() { upstreamNow = previous })
}

// failingRuntime answers every runtime request with one non-200 response.
type failingRuntime struct {
	mu      sync.Mutex
	status  int
	headers http.Header
	body    []byte
	opens   int
	emitted int
	closed  int
}

func (f *failingRuntime) call(method string, payload any) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch method {
	case pluginabi.MethodHostHTTPDoStream:
		f.opens++
		return mustJSONRaw(rpcHostHTTPStreamResponse{StatusCode: f.status, Headers: f.headers, StreamID: "upstream-err"}), nil
	case pluginabi.MethodHostHTTPStreamRead:
		return mustJSONRaw(rpcHostHTTPStreamReadResponse{Payload: f.body, Done: true}), nil
	case pluginabi.MethodHostHTTPStreamClose:
		return json.RawMessage(`{}`), nil
	case pluginabi.MethodHostStreamEmit:
		f.emitted++
		return json.RawMessage(`{}`), nil
	case pluginabi.MethodHostStreamClose:
		f.closed++
		return json.RawMessage(`{}`), nil
	default:
		return nil, nil
	}
}

func installFailingRuntime(t *testing.T, runtime *failingRuntime) {
	t.Helper()
	previous := invokeHost
	invokeHost = runtime.call
	t.Cleanup(func() { invokeHost = previous })
}

func executorRequestRaw(t *testing.T, streamID string) []byte {
	t.Helper()
	raw, errMarshal := json.Marshal(rpcExecutorRequest{
		ExecutorRequest: pluginapi.ExecutorRequest{
			Model:       "claude-sonnet-4.5",
			Payload:     []byte(`{"model":"claude-sonnet-4.5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`),
			StorageJSON: []byte(testOAuthStorage),
		},
		StreamID: streamID,
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	return raw
}

func pluginErrorFrom(t *testing.T, raw []byte) *pluginError {
	t.Helper()
	var env envelope
	if errUnmarshal := json.Unmarshal(raw, &env); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if env.OK || env.Error == nil {
		t.Fatalf("envelope = %s, want an error", raw)
	}
	return env.Error
}

func TestMonthlyQuotaBecomesCredentialScopedCooldownUntilReset(t *testing.T) {
	now := time.Date(2026, 10, 10, 15, 30, 0, 0, time.UTC)
	wantRetry := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Sub(now)
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "429 json reason", status: http.StatusTooManyRequests, body: `{"message":"Monthly quota exhausted","reason":"MONTHLY_REQUEST_COUNT"}`},
		{name: "402 json reason", status: http.StatusPaymentRequired, body: `{"message":"Free tier limit reached","reason":"MONTHLY_REQUEST_COUNT"}`},
		{name: "403 plain marker", status: http.StatusForbidden, body: `MONTHLY_REQUEST_COUNT exceeded`},
	}
	for _, tt := range tests {
		for _, mode := range []string{"execute", "stream"} {
			t.Run(tt.name+"/"+mode, func(t *testing.T) {
				withUpstreamClock(t, now)
				runtime := &failingRuntime{status: tt.status, body: []byte(tt.body)}
				installFailingRuntime(t, runtime)

				var raw []byte
				var errCall error
				if mode == "execute" {
					raw, errCall = executeKiroRequest(executorRequestRaw(t, ""))
				} else {
					raw, errCall = executeKiroStreamingRequest(executorRequestRaw(t, "stream-quota"))
				}
				if errCall != nil {
					t.Fatal(errCall)
				}
				pluginErr := pluginErrorFrom(t, raw)
				if pluginErr.HTTPStatus != http.StatusTooManyRequests || !pluginErr.CredentialScoped || pluginErr.Code != "quota_exhausted" {
					t.Fatalf("error = %+v, want credential-scoped 429 quota_exhausted", pluginErr)
				}
				if pluginErr.RetryAfterMS != wantRetry.Milliseconds() {
					t.Fatalf("RetryAfterMS = %d, want %d (until the monthly reset)", pluginErr.RetryAfterMS, wantRetry.Milliseconds())
				}
				if pluginErr.Retryable || runtime.opens != 1 {
					t.Fatalf("retryable=%t opens=%d, want no retry on the exhausted account", pluginErr.Retryable, runtime.opens)
				}
				if mode == "stream" && (runtime.emitted != 0 || runtime.closed != 0) {
					t.Fatalf("stream emitted=%d closed=%d, want the failure returned before the stream starts", runtime.emitted, runtime.closed)
				}
			})
		}
	}
}

func TestShortRateLimitKeepsModelScopeAndHeaderHint(t *testing.T) {
	withUpstreamClock(t, time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC))
	runtime := &failingRuntime{
		status:  http.StatusTooManyRequests,
		headers: http.Header{"Retry-After": []string{"7"}},
		body:    []byte(`{"message":"Too many requests","reason":"USER_REQUEST_RATE_EXCEEDED"}`),
	}
	installFailingRuntime(t, runtime)

	raw, errStream := executeKiroStreamingRequest(executorRequestRaw(t, "stream-rate"))
	if errStream != nil {
		t.Fatal(errStream)
	}
	pluginErr := pluginErrorFrom(t, raw)
	if pluginErr.HTTPStatus != http.StatusTooManyRequests || pluginErr.CredentialScoped || pluginErr.RetryAfterMS != 7000 {
		t.Fatalf("error = %+v, want model-scoped 429 with 7s hint", pluginErr)
	}
	if runtime.opens != maxAttempts {
		t.Fatalf("opens = %d, want a retry for a transient rate limit", runtime.opens)
	}
}

func TestInvalidBearerTokenIsReportedAsUnauthorized(t *testing.T) {
	runtime := &failingRuntime{
		status: http.StatusForbidden,
		body:   []byte(`{"__type":"com.amazon.kiro.runtimeservice#AccessDeniedException","message":"The bearer token included in the request is invalid."}`),
	}
	installFailingRuntime(t, runtime)

	raw, errExecute := executeKiroRequest(executorRequestRaw(t, ""))
	if errExecute != nil {
		t.Fatal(errExecute)
	}
	pluginErr := pluginErrorFrom(t, raw)
	if pluginErr.HTTPStatus != http.StatusUnauthorized || pluginErr.CredentialScoped {
		t.Fatalf("error = %+v, want 401 so CPA refreshes the token", pluginErr)
	}
	if strings.Contains(pluginErr.Message, "oauth-access") {
		t.Fatalf("error leaks the access token: %q", pluginErr.Message)
	}
}

func TestNextMonthStartRollsOverYear(t *testing.T) {
	got := nextMonthStart(time.Date(2026, 12, 31, 23, 59, 0, 0, time.UTC))
	if want := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("nextMonthStart = %v, want %v", got, want)
	}
}

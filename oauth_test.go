package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	testIDCProfileARN = "arn:aws:codewhisperer:us-east-1:111111111111:profile/IDCTEST"
	testEUProfileARN  = "arn:aws:codewhisperer:eu-central-1:222222222222:profile/EUTEST"
)

func testIDCStorage(t *testing.T, expired string) []byte {
	t.Helper()
	raw, errMarshal := json.Marshal(kiroCredential{
		Type:         pluginIdentifier,
		AuthMethod:   authMethodIDC,
		Region:       "us-east-1",
		ProfileARN:   testIDCProfileARN,
		AccessToken:  "access-old",
		RefreshToken: "refresh-old",
		Expired:      expired,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		StartURL:     builderIDStartURL,
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	return raw
}

func decodeOKEnvelope[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var env envelope
	if errUnmarshal := json.Unmarshal(raw, &env); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if !env.OK {
		t.Fatalf("envelope error = %#v", env.Error)
	}
	var out T
	if errUnmarshal := json.Unmarshal(env.Result, &out); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	return out
}

func TestParseAuthClassifiesOAuthAndAPIKeyCredentials(t *testing.T) {
	expiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	tests := []struct {
		name          string
		raw           []byte
		wantKind      string
		wantRefreshMD bool
	}{
		{name: "idc oauth", raw: testIDCStorage(t, expiry), wantKind: "oauth", wantRefreshMD: true},
		{name: "legacy api key", raw: []byte(`{"type":"kiro","api_key_env":"KIRO_TEST_KEY","region":"us-east-1"}`), wantKind: "api_key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, _ := json.Marshal(pluginapi.AuthParseRequest{FileName: "kiro-test.json", RawJSON: tt.raw})
			raw, errParse := parseAuth(request)
			if errParse != nil {
				t.Fatal(errParse)
			}
			response := decodeOKEnvelope[pluginapi.AuthParseResponse](t, raw)
			if !response.Handled {
				t.Fatal("credential not handled")
			}
			metadata := response.Auth.Metadata
			if metadata["auth_kind"] != tt.wantKind || response.Auth.Attributes["auth_kind"] != tt.wantKind {
				t.Fatalf("auth_kind metadata=%v attribute=%q, want %q", metadata["auth_kind"], response.Auth.Attributes["auth_kind"], tt.wantKind)
			}
			_, hasRefresh := metadata["refresh_token"]
			_, hasInterval := metadata["refresh_interval_seconds"]
			if hasRefresh != tt.wantRefreshMD || hasInterval != tt.wantRefreshMD {
				t.Fatalf("refresh metadata present=%t interval present=%t, want %t", hasRefresh, hasInterval, tt.wantRefreshMD)
			}
			if tt.wantRefreshMD {
				if metadata["access_token"] != "access-old" || metadata["expired"] != expiry || metadata["profile_arn"] != testIDCProfileARN {
					t.Fatalf("OAuth metadata = %#v", metadata)
				}
			}
		})
	}
}

func TestDecodeCredentialRejectsIncompleteOAuthRecords(t *testing.T) {
	tests := map[string]string{
		"idc without client secret":      `{"type":"kiro","auth_method":"idc","refresh_token":"r","client_id":"c"}`,
		"oauth without tokens":           `{"type":"kiro","auth_method":"desktop"}`,
		"external idp over http":         `{"type":"kiro","auth_method":"external-idp","refresh_token":"r","client_id":"c","token_endpoint":"http://idp.example/token"}`,
		"profile arn from other service": `{"type":"kiro","auth_method":"desktop","refresh_token":"r","profile_arn":"arn:aws:s3:us-east-1:1:bucket/x"}`,
		"unknown method":                 `{"type":"kiro","auth_method":"magic","refresh_token":"r"}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, handled, errCredential := decodeCredential([]byte(raw)); !handled || errCredential == nil {
				t.Fatalf("decodeCredential() handled=%t error=%v, want handled rejection", handled, errCredential)
			}
		})
	}
}

// refreshRecorder serves OIDC refreshes and records each request.
type refreshRecorder struct {
	t        *testing.T
	requests []rpcHostHTTPRequest
	respond  func(call int, request rpcHostHTTPRequest) pluginapi.HTTPResponse
}

func (r *refreshRecorder) call(method string, payload any) (json.RawMessage, error) {
	if method != pluginabi.MethodHostHTTPDo {
		r.t.Fatalf("unexpected host method %q", method)
	}
	request := payload.(rpcHostHTTPRequest)
	r.requests = append(r.requests, request)
	return mustJSONRaw(r.respond(len(r.requests), request)), nil
}

func runRefresh(t *testing.T, storage []byte, attributes map[string]string) []byte {
	t.Helper()
	request, _ := json.Marshal(rpcAuthRefreshRequest{
		AuthRefreshRequest: pluginapi.AuthRefreshRequest{AuthID: "kiro-idc.json", StorageJSON: storage, Attributes: attributes},
		HostCallbackID:     "callback-refresh",
	})
	raw, errRefresh := refreshAuth(request)
	if errRefresh != nil {
		t.Fatal(errRefresh)
	}
	return raw
}

func TestRefreshAuthRotatesIDCTokensAcrossTwoCycles(t *testing.T) {
	recorder := &refreshRecorder{t: t, respond: func(call int, request rpcHostHTTPRequest) pluginapi.HTTPResponse {
		body := map[string]any{"accessToken": "access-1", "refreshToken": "refresh-1", "expiresIn": 3600}
		if call == 2 {
			// Second cycle: the server keeps the refresh token.
			body = map[string]any{"accessToken": "access-2", "expiresIn": 3600}
		}
		raw, _ := json.Marshal(body)
		return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: raw}
	}}
	previous := invokeHost
	invokeHost = recorder.call
	t.Cleanup(func() { invokeHost = previous })

	storage := testIDCStorage(t, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339))
	attributes := map[string]string{"path": "/auths/kiro-idc.json", "priority": "5"}
	var refreshed pluginapi.AuthData
	for cycle := 1; cycle <= 2; cycle++ {
		response := decodeOKEnvelope[pluginapi.AuthRefreshResponse](t, runRefresh(t, storage, attributes))
		refreshed = response.Auth
		storage = refreshed.StorageJSON
		attributes = refreshed.Attributes
		if _, hasInterval := refreshed.Metadata["refresh_interval_seconds"]; !hasInterval {
			t.Fatalf("cycle %d dropped refresh_interval_seconds: %#v", cycle, refreshed.Metadata)
		}
	}

	if len(recorder.requests) != 2 {
		t.Fatalf("refresh requests = %d, want 2", len(recorder.requests))
	}
	first := recorder.requests[0]
	if first.URL != "https://oidc.us-east-1.amazonaws.com/token" || first.HostCallbackID != "callback-refresh" {
		t.Fatalf("first refresh request = %s via %q", first.URL, first.HostCallbackID)
	}
	var firstBody map[string]string
	_ = json.Unmarshal(first.Body, &firstBody)
	if firstBody["grantType"] != "refresh_token" || firstBody["refreshToken"] != "refresh-old" || firstBody["clientSecret"] != "client-secret" {
		t.Fatalf("first refresh body = %#v", firstBody)
	}
	var secondBody map[string]string
	_ = json.Unmarshal(recorder.requests[1].Body, &secondBody)
	if secondBody["refreshToken"] != "refresh-1" {
		t.Fatalf("second refresh used %q, want rotated refresh-1", secondBody["refreshToken"])
	}

	credential, _, errCredential := decodeCredential(storage)
	if errCredential != nil {
		t.Fatal(errCredential)
	}
	if credential.AccessToken != "access-2" || credential.RefreshToken != "refresh-1" || credential.ProfileARN != testIDCProfileARN {
		t.Fatalf("final credential tokens/profile = %q %q %q", credential.AccessToken, credential.RefreshToken, credential.ProfileARN)
	}
	expiry, errParse := time.Parse(time.RFC3339, credential.Expired)
	if errParse != nil || time.Until(expiry) < 50*time.Minute {
		t.Fatalf("expired = %q, want about one hour ahead", credential.Expired)
	}
	if refreshed.Metadata["access_token"] != "access-2" || refreshed.Metadata["refresh_token"] != "refresh-1" {
		t.Fatalf("metadata tokens not updated: %#v", refreshed.Metadata)
	}
	if refreshed.Attributes["priority"] != "5" || refreshed.Attributes["path"] != "/auths/kiro-idc.json" {
		t.Fatalf("host attributes not preserved: %#v", refreshed.Attributes)
	}
}

func TestRefreshAuthMapsRejectedRefreshTokenToUpstreamStatus(t *testing.T) {
	recorder := &refreshRecorder{t: t, respond: func(int, rpcHostHTTPRequest) pluginapi.HTTPResponse {
		return pluginapi.HTTPResponse{StatusCode: http.StatusBadRequest, Body: []byte(`{"error":"invalid_grant"}`)}
	}}
	previous := invokeHost
	invokeHost = recorder.call
	t.Cleanup(func() { invokeHost = previous })

	raw := runRefresh(t, testIDCStorage(t, ""), nil)
	var env envelope
	_ = json.Unmarshal(raw, &env)
	if env.OK || env.Error == nil || env.Error.HTTPStatus != http.StatusBadRequest || env.Error.Retryable {
		t.Fatalf("refresh failure envelope = %#v, want non-retryable 400", env.Error)
	}
	if strings.Contains(env.Error.Message, "refresh-old") || strings.Contains(env.Error.Message, "client-secret") {
		t.Fatalf("refresh error leaks credentials: %q", env.Error.Message)
	}
}

func TestPrepareUpstreamRequestUsesOAuthProfileAndRegion(t *testing.T) {
	storage, _ := json.Marshal(kiroCredential{
		Type:         pluginIdentifier,
		AuthMethod:   authMethodDesktop,
		Region:       "us-east-1",
		ProfileARN:   testEUProfileARN,
		AccessToken:  "desktop-access",
		RefreshToken: "desktop-refresh",
	})
	upstream, _, errPrepare := prepareUpstreamRequest(pluginapi.ExecutorRequest{
		Model:       "claude-sonnet-4.5",
		Payload:     []byte(`{"model":"claude-sonnet-4.5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`),
		StorageJSON: storage,
	})
	if errPrepare != nil {
		t.Fatal(errPrepare)
	}
	if upstream.URL != "https://runtime.eu-central-1.kiro.dev/" {
		t.Fatalf("runtime URL = %q, want the profile ARN region", upstream.URL)
	}
	if got := upstream.Headers.Get("Authorization"); got != "Bearer desktop-access" {
		t.Fatalf("Authorization = %q", got)
	}
	if got := upstream.Headers.Get("Tokentype"); got != "" {
		t.Fatalf("Tokentype = %q, want none for desktop OAuth tokens", got)
	}
	var body map[string]any
	if errUnmarshal := json.Unmarshal(upstream.Body, &body); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if body["profileArn"] != testEUProfileARN {
		t.Fatalf("profileArn = %v, want the credential's ARN", body["profileArn"])
	}
}

func TestPrepareUpstreamRequestRejectsOAuthWithoutProfile(t *testing.T) {
	storage := []byte(`{"type":"kiro","auth_method":"desktop","access_token":"a","refresh_token":"r"}`)
	_, _, errPrepare := prepareUpstreamRequest(pluginapi.ExecutorRequest{
		Model:       "claude-sonnet-4.5",
		Payload:     []byte(`{"model":"claude-sonnet-4.5","messages":[{"role":"user","content":"hi"}]}`),
		StorageJSON: storage,
	})
	if errPrepare == nil {
		t.Fatal("prepareUpstreamRequest() accepted an OAuth credential without profile_arn")
	}
	if env := prepareRequestErrorEnvelope(errPrepare); !strings.Contains(string(env), `"http_status":401`) {
		t.Fatalf("missing-profile envelope = %s, want 401", env)
	}
}

func TestAPIKeyRequestKeepsTokenTypeAndOmitsProfile(t *testing.T) {
	t.Setenv("KIRO_TEST_KEY", "test-key")
	upstream, _, errPrepare := prepareUpstreamRequest(pluginapi.ExecutorRequest{
		Model:       "claude-sonnet-4.5",
		Payload:     []byte(`{"model":"claude-sonnet-4.5","messages":[{"role":"user","content":"hi"}]}`),
		StorageJSON: []byte(`{"type":"kiro","api_key_env":"KIRO_TEST_KEY","region":"us-east-1"}`),
	})
	if errPrepare != nil {
		t.Fatal(errPrepare)
	}
	if upstream.Headers.Get("Tokentype") != "API_KEY" || strings.Contains(string(upstream.Body), "profileArn") {
		t.Fatalf("API-key request headers=%v body=%s", upstream.Headers, upstream.Body)
	}
}

func TestModelDiscoveryURLCarriesProfileARN(t *testing.T) {
	rawURL, errURL := modelDiscoveryURL("us-east-1", testIDCProfileARN, "")
	if errURL != nil {
		t.Fatal(errURL)
	}
	parsed, _ := url.Parse(rawURL)
	if parsed.Query().Get("profileArn") != testIDCProfileARN {
		t.Fatalf("discovery URL = %q, want profileArn", rawURL)
	}
}

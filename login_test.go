package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// fakeOIDC simulates AWS SSO OIDC and Kiro management endpoints behind host.http.do.
type fakeOIDC struct {
	t            *testing.T
	mu           sync.Mutex
	tokenReplies []pluginapi.HTTPResponse
	profiles     map[string]pluginapi.HTTPResponse
	calls        []string
}

// call records every request and reports unexpected ones with t.Errorf plus a
// returned error, never t.Fatal: it runs inside plugin code, and FailNow must
// only be called from the test goroutine's own frames.
func (f *fakeOIDC) call(method string, payload any) (json.RawMessage, error) {
	if method != pluginabi.MethodHostHTTPDo {
		f.t.Errorf("unexpected host method %q", method)
		return nil, fmt.Errorf("unexpected host method %q", method)
	}
	request := payload.(rpcHostHTTPRequest)
	parsed, _ := url.Parse(request.URL)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, parsed.Host+parsed.Path)
	switch {
	case strings.HasSuffix(parsed.Path, "/client/register"):
		return mustJSONRaw(pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"clientId":"new-client","clientSecret":"new-secret"}`)}), nil
	case strings.HasSuffix(parsed.Path, "/device_authorization"):
		var body map[string]string
		_ = json.Unmarshal(request.Body, &body)
		if body["clientId"] != "new-client" || body["startUrl"] == "" {
			f.t.Errorf("device authorization body = %#v", body)
		}
		return mustJSONRaw(pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{
			"verificationUri":"https://device.sso.example/",
			"verificationUriComplete":"https://device.sso.example/?user_code=ABCD-EFGH",
			"userCode":"ABCD-EFGH","deviceCode":"device-code","interval":1,"expiresIn":600}`)}), nil
	case strings.HasSuffix(parsed.Path, "/token"):
		if len(f.tokenReplies) == 0 {
			f.t.Errorf("unexpected token poll")
			return nil, fmt.Errorf("unexpected token poll")
		}
		reply := f.tokenReplies[0]
		f.tokenReplies = f.tokenReplies[1:]
		return mustJSONRaw(reply), nil
	case parsed.Path == "/List-Available-Profiles":
		reply, ok := f.profiles[parsed.Host]
		if !ok {
			f.t.Errorf("unexpected profile lookup in %s", parsed.Host)
			return nil, fmt.Errorf("unexpected profile lookup in %s", parsed.Host)
		}
		return mustJSONRaw(reply), nil
	default:
		f.t.Errorf("unexpected request %s", request.URL)
		return nil, fmt.Errorf("unexpected request %s", request.URL)
	}
}
func (f *fakeOIDC) callCount(suffix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, call := range f.calls {
		if strings.HasSuffix(call, suffix) {
			count++
		}
	}
	return count
}

func withFakeClock(t *testing.T) *time.Time {
	t.Helper()
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	previous := loginNow
	loginNow = func() time.Time { return now }
	t.Cleanup(func() { loginNow = previous })
	return &now
}

func installFake(t *testing.T, fake *fakeOIDC) {
	t.Helper()
	previous := invokeHost
	invokeHost = fake.call
	t.Cleanup(func() { invokeHost = previous })
	t.Cleanup(func() {
		loginMu.Lock()
		deviceLogins = make(map[string]*pendingDeviceLogin)
		loginMu.Unlock()
	})
}

func callStartLogin(t *testing.T, metadata map[string]any) ([]byte, pluginapi.AuthLoginStartResponse) {
	t.Helper()
	raw, _ := json.Marshal(rpcAuthLoginStartRequest{AuthLoginStartRequest: pluginapi.AuthLoginStartRequest{Provider: pluginIdentifier, Metadata: metadata}, HostCallbackID: "cb-start"})
	response, errStart := startLogin(raw)
	if errStart != nil {
		t.Fatal(errStart)
	}
	var env envelope
	_ = json.Unmarshal(response, &env)
	var start pluginapi.AuthLoginStartResponse
	if env.OK {
		_ = json.Unmarshal(env.Result, &start)
	}
	return response, start
}

func callPollLogin(t *testing.T, state string) pluginapi.AuthLoginPollResponse {
	t.Helper()
	raw, _ := json.Marshal(rpcAuthLoginPollRequest{AuthLoginPollRequest: pluginapi.AuthLoginPollRequest{Provider: pluginIdentifier, State: state}, HostCallbackID: "cb-poll"})
	response, errPoll := pollLogin(raw)
	if errPoll != nil {
		t.Fatal(errPoll)
	}
	return decodeOKEnvelope[pluginapi.AuthLoginPollResponse](t, response)
}

func TestBuilderIDDeviceLoginProducesRefreshableCredential(t *testing.T) {
	now := withFakeClock(t)
	fake := &fakeOIDC{t: t, tokenReplies: []pluginapi.HTTPResponse{
		{StatusCode: http.StatusBadRequest, Body: []byte(`{"error":"authorization_pending"}`)},
		{StatusCode: http.StatusOK, Body: []byte(`{"accessToken":"builder-access","refreshToken":"builder-refresh","expiresIn":3600}`)},
	}}
	installFake(t, fake)

	_, start := callStartLogin(t, nil)
	if start.URL != "https://device.sso.example/?user_code=ABCD-EFGH" || start.Metadata["user_code"] != "ABCD-EFGH" {
		t.Fatalf("start response = %#v", start)
	}
	if !strings.HasPrefix(start.State, "kiro-") || strings.Contains(start.State, "device-code") {
		t.Fatalf("state %q must be opaque and not reveal the device code", start.State)
	}

	// Polling before the interval elapses must not hit the token endpoint.
	if poll := callPollLogin(t, start.State); poll.Status != pluginapi.AuthLoginStatusPending || fake.callCount("/token") != 0 {
		t.Fatalf("early poll = %#v, token calls = %d", poll, fake.callCount("/token"))
	}
	*now = now.Add(2 * time.Second)
	if poll := callPollLogin(t, start.State); poll.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("pending poll = %#v", poll)
	}
	*now = now.Add(2 * time.Second)
	poll := callPollLogin(t, start.State)
	if poll.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("final poll = %#v", poll)
	}

	auth := poll.Auth
	if auth.Metadata["auth_kind"] != "oauth" || auth.Metadata["refresh_token"] != "builder-refresh" || auth.Metadata["profile_arn"] != builderIDProfileARN {
		t.Fatalf("login metadata = %#v", auth.Metadata)
	}
	if !strings.HasPrefix(auth.FileName, "kiro-idc-") || auth.ID != auth.FileName {
		t.Fatalf("file name = %q id = %q", auth.FileName, auth.ID)
	}
	credential, handled, errCredential := decodeCredential(auth.StorageJSON)
	if !handled || errCredential != nil {
		t.Fatalf("stored credential handled=%t err=%v", handled, errCredential)
	}
	if credential.ClientID != "new-client" || credential.ClientSecret != "new-secret" || credential.StartURL != builderIDStartURL {
		t.Fatalf("stored credential = %#v", credential)
	}
	if fake.callCount("/List-Available-Profiles") != 0 {
		t.Fatal("Builder ID login must not call ListAvailableProfiles")
	}
	// The completed session is gone.
	if again := callPollLogin(t, start.State); again.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("reused state = %#v, want error", again)
	}
}

func TestIdentityCenterLoginDiscoversProfileInOtherRegion(t *testing.T) {
	now := withFakeClock(t)
	fake := &fakeOIDC{t: t,
		tokenReplies: []pluginapi.HTTPResponse{{StatusCode: http.StatusOK, Body: []byte(`{"accessToken":"idc-access","refreshToken":"idc-refresh","expiresIn":3600}`)}},
		profiles: map[string]pluginapi.HTTPResponse{
			"management.eu-central-1.kiro.dev": {StatusCode: http.StatusForbidden, Body: []byte(`{"message":"User is not authorized"}`)},
			"management.us-east-1.kiro.dev":    {StatusCode: http.StatusOK, Body: profileListing(testIDCProfileARN)},
		},
	}
	installFake(t, fake)

	raw, start := callStartLogin(t, map[string]any{"method": "idc", "start_url": "https://example.awsapps.com/start", "region": "eu-west-1"})
	if start.State == "" {
		t.Fatalf("start failed: %s", raw)
	}
	*now = now.Add(2 * time.Second)
	poll := callPollLogin(t, start.State)
	if poll.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("poll = %#v", poll)
	}
	credential, _, _ := decodeCredential(poll.Auth.StorageJSON)
	if credential.ProfileARN != testIDCProfileARN || credential.Region != "eu-west-1" {
		t.Fatalf("credential profile=%q region=%q", credential.ProfileARN, credential.Region)
	}
	if credential.runtimeRegion() != "us-east-1" {
		t.Fatalf("runtime region = %q, want the profile's region", credential.runtimeRegion())
	}
	if !strings.Contains(fake.calls[0], "oidc.eu-west-1.amazonaws.com") {
		t.Fatalf("OIDC calls must use the Identity Center region: %v", fake.calls)
	}
}

func TestDeviceLoginSlowDownBacksOffAndDeniedFails(t *testing.T) {
	now := withFakeClock(t)
	fake := &fakeOIDC{t: t, tokenReplies: []pluginapi.HTTPResponse{
		{StatusCode: http.StatusBadRequest, Body: []byte(`{"error":"slow_down"}`)},
		{StatusCode: http.StatusBadRequest, Body: []byte(`{"error":"access_denied"}`)},
	}}
	installFake(t, fake)

	_, start := callStartLogin(t, nil)
	*now = now.Add(2 * time.Second)
	if poll := callPollLogin(t, start.State); poll.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("slow_down poll = %#v", poll)
	}
	// slow_down adds five seconds to the one-second interval.
	*now = now.Add(3 * time.Second)
	if poll := callPollLogin(t, start.State); poll.Status != pluginapi.AuthLoginStatusPending || fake.callCount("/token") != 1 {
		t.Fatalf("poll inside backoff = %#v token calls = %d", poll, fake.callCount("/token"))
	}
	*now = now.Add(4 * time.Second)
	poll := callPollLogin(t, start.State)
	if poll.Status != pluginapi.AuthLoginStatusError || !strings.Contains(poll.Message, "access_denied") {
		t.Fatalf("denied poll = %#v", poll)
	}
}

func TestDeviceLoginExpires(t *testing.T) {
	now := withFakeClock(t)
	installFake(t, &fakeOIDC{t: t})
	_, start := callStartLogin(t, nil)
	*now = now.Add(11 * time.Minute)
	if poll := callPollLogin(t, start.State); poll.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("expired poll = %#v", poll)
	}
}

func TestStartLoginRejectsInvalidIdentityCenterInput(t *testing.T) {
	installFake(t, &fakeOIDC{t: t})
	for name, metadata := range map[string]map[string]any{
		"http start url": {"method": "idc", "start_url": "http://example.awsapps.com/start", "region": "us-east-1"},
		"missing region": {"method": "idc", "start_url": "https://example.awsapps.com/start"},
		"unknown method": {"method": "magic"},
	} {
		t.Run(name, func(t *testing.T) {
			raw, start := callStartLogin(t, metadata)
			if start.State != "" || !strings.Contains(string(raw), `"http_status":400`) {
				t.Fatalf("start = %s", raw)
			}
		})
	}
}

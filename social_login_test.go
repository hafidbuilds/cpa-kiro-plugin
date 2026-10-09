package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const testSocialProfileARN = "arn:aws:codewhisperer:us-east-1:333333333333:profile/SOCIAL"

func writeCallbackFile(t *testing.T, authDir, state string, callback oauthCallbackFile) string {
	t.Helper()
	raw, _ := json.Marshal(callback)
	path := filepath.Join(authDir, ".oauth-kiro-"+state+".oauth")
	if errWrite := os.WriteFile(path, raw, 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	return path
}

func callSocialPoll(t *testing.T, state, authDir string) pluginapi.AuthLoginPollResponse {
	t.Helper()
	raw, _ := json.Marshal(rpcAuthLoginPollRequest{
		AuthLoginPollRequest: pluginapi.AuthLoginPollRequest{Provider: pluginIdentifier, State: state, Host: pluginapi.HostConfigSummary{AuthDir: authDir}},
		HostCallbackID:       "cb-social",
	})
	response, errPoll := pollLogin(raw)
	if errPoll != nil {
		t.Fatal(errPoll)
	}
	return decodeOKEnvelope[pluginapi.AuthLoginPollResponse](t, response)
}

// socialTokenServer answers the Kiro auth-service code exchange.
func socialTokenServer(t *testing.T, tokenBody string, profileStatus int) (*[]rpcHostHTTPRequest, func(string, any) (json.RawMessage, error)) {
	var requests []rpcHostHTTPRequest
	return &requests, func(method string, payload any) (json.RawMessage, error) {
		request := payload.(rpcHostHTTPRequest)
		requests = append(requests, request)
		parsed, _ := url.Parse(request.URL)
		switch {
		case parsed.Host == "prod.us-east-1.auth.desktop.kiro.dev" && parsed.Path == "/oauth/token":
			return mustJSONRaw(pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: []byte(tokenBody)}), nil
		case parsed.Path == "/List-Available-Profiles":
			if profileStatus != http.StatusOK {
				return mustJSONRaw(pluginapi.HTTPResponse{StatusCode: profileStatus, Body: []byte(`{"message":"denied"}`)}), nil
			}
			return mustJSONRaw(pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: profileListing(testSocialProfileARN)}), nil
		default:
			t.Errorf("unexpected request %s", request.URL)
			return mustJSONRaw(pluginapi.HTTPResponse{StatusCode: http.StatusNotFound}), nil
		}
	}
}

func TestGitHubLoginExchangesSubmittedCallback(t *testing.T) {
	now := withFakeClock(t)
	requests, call := socialTokenServer(t, `{"accessToken":"social-access","refreshToken":"social-refresh","expiresIn":3600,"profileArn":"`+testSocialProfileARN+`"}`, http.StatusOK)
	previous := invokeHost
	invokeHost = call
	t.Cleanup(func() { invokeHost = previous })
	t.Cleanup(func() {
		loginMu.Lock()
		socialLogins = make(map[string]*pendingSocialLogin)
		loginMu.Unlock()
	})
	authDir := t.TempDir()

	_, start := callStartLogin(t, map[string]any{"method": "github"})
	signIn, errParse := url.Parse(start.URL)
	if errParse != nil || signIn.Host != "app.kiro.dev" || signIn.Path != "/signin" {
		t.Fatalf("sign-in URL = %q", start.URL)
	}
	query := signIn.Query()
	if query.Get("state") != start.State || query.Get("redirect_uri") != socialRedirectURI || query.Get("login_option") != "github" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("sign-in query = %v", query)
	}

	if poll := callSocialPoll(t, start.State, authDir); poll.Status != pluginapi.AuthLoginStatusPending || len(*requests) != 0 {
		t.Fatalf("poll before callback = %#v requests=%d", poll, len(*requests))
	}

	path := writeCallbackFile(t, authDir, start.State, oauthCallbackFile{Code: "auth-code", State: start.State})
	*now = now.Add(time.Second)
	poll := callSocialPoll(t, start.State, authDir)
	if poll.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("poll after callback = %#v", poll)
	}
	if _, errStat := os.Stat(path); !os.IsNotExist(errStat) {
		t.Fatalf("callback file was not consumed: %v", errStat)
	}

	if len(*requests) != 1 {
		t.Fatalf("requests = %d, want only the code exchange (profile came with the token)", len(*requests))
	}
	var exchange map[string]string
	_ = json.Unmarshal((*requests)[0].Body, &exchange)
	challenge := sha256.Sum256([]byte(exchange["code_verifier"]))
	if exchange["code"] != "auth-code" || base64.RawURLEncoding.EncodeToString(challenge[:]) != query.Get("code_challenge") {
		t.Fatalf("exchange body does not prove the PKCE verifier: %#v", exchange)
	}
	if exchange["redirect_uri"] != socialRedirectURI+"?login_option=github" {
		t.Fatalf("redirect_uri = %q, want the redirect Kiro issued the code for", exchange["redirect_uri"])
	}

	credential, _, errCredential := decodeCredential(poll.Auth.StorageJSON)
	if errCredential != nil {
		t.Fatal(errCredential)
	}
	if credential.AuthMethod != authMethodDesktop || credential.ProfileARN != testSocialProfileARN || credential.RefreshToken != "social-refresh" {
		t.Fatalf("credential = %#v", credential)
	}
	if !strings.HasPrefix(poll.Auth.FileName, "kiro-desktop-") || poll.Auth.Metadata["auth_kind"] != "oauth" {
		t.Fatalf("auth file=%q metadata=%#v", poll.Auth.FileName, poll.Auth.Metadata)
	}
}

func TestSocialLoginDiscoversProfileWhenTokenOmitsIt(t *testing.T) {
	withFakeClock(t)
	requests, call := socialTokenServer(t, `{"accessToken":"social-access","refreshToken":"social-refresh","expiresIn":3600}`, http.StatusOK)
	previous := invokeHost
	invokeHost = call
	t.Cleanup(func() { invokeHost = previous })
	authDir := t.TempDir()

	_, start := callStartLogin(t, map[string]any{"method": "google"})
	writeCallbackFile(t, authDir, start.State, oauthCallbackFile{Code: "auth-code", State: start.State})
	poll := callSocialPoll(t, start.State, authDir)
	if poll.Status != pluginapi.AuthLoginStatusSuccess || poll.Auth.Metadata["profile_arn"] != testSocialProfileARN {
		t.Fatalf("poll = %#v", poll)
	}
	if len(*requests) != 2 || !strings.HasSuffix((*requests)[1].URL, "/List-Available-Profiles") {
		t.Fatalf("requests = %d, want code exchange then profile discovery", len(*requests))
	}
}

func TestSocialLoginRejectsMismatchedOrFailedCallback(t *testing.T) {
	tests := map[string]oauthCallbackFile{
		"provider error": {Error: "access_denied"},
		"wrong state":    {Code: "auth-code", State: "kiro-other"},
	}
	for name, callback := range tests {
		t.Run(name, func(t *testing.T) {
			withFakeClock(t)
			requests, call := socialTokenServer(t, `{}`, http.StatusOK)
			previous := invokeHost
			invokeHost = call
			t.Cleanup(func() { invokeHost = previous })
			authDir := t.TempDir()

			_, start := callStartLogin(t, map[string]any{"method": "social"})
			if callback.State == "" {
				callback.State = start.State
			}
			writeCallbackFile(t, authDir, start.State, callback)
			if poll := callSocialPoll(t, start.State, authDir); poll.Status != pluginapi.AuthLoginStatusError {
				t.Fatalf("poll = %#v, want error", poll)
			}
			if len(*requests) != 0 {
				t.Fatalf("token exchange ran for a rejected callback")
			}
			if again := callSocialPoll(t, start.State, authDir); again.Status != pluginapi.AuthLoginStatusError {
				t.Fatalf("session survived a rejected callback: %#v", again)
			}
		})
	}
}

func TestSocialLoginExpires(t *testing.T) {
	now := withFakeClock(t)
	_, start := callStartLogin(t, map[string]any{"method": "github"})
	*now = now.Add(socialLoginTTL + time.Second)
	if poll := callSocialPoll(t, start.State, t.TempDir()); poll.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("expired poll = %#v", poll)
	}
}

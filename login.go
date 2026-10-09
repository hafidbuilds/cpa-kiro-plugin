package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// Device-code login for AWS Builder ID and IAM Identity Center.
//
// CPA's management API returns only the login URL and an opaque state from
// StartLogin, then drives PollLogin each time a client checks
// /v8/management/oauth/status. The plugin therefore returns the complete
// verification URL (with the user code embedded) and keeps the device flow in
// process memory, keyed by state. Only a non-secret state reaches the host.

const (
	loginMethodBuilderID = "builder-id"
	loginMethodIDC       = "idc"

	// deviceLoginFallbackTTL applies when the device authorization omits expiresIn.
	deviceLoginFallbackTTL = 10 * time.Minute
)

type deviceAuthorization struct {
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	UserCode                string `json:"userCode"`
	DeviceCode              string `json:"deviceCode"`
	Interval                int64  `json:"interval"`
	ExpiresIn               int64  `json:"expiresIn"`
}

type pendingDeviceLogin struct {
	// method is loginMethodBuilderID or loginMethodIDC; it decides how the
	// profile ARN is obtained once tokens arrive.
	method       string
	region       string
	startURL     string
	clientID     string
	clientSecret string
	deviceCode   string
	interval     time.Duration
	nextPollAt   time.Time
	expiresAt    time.Time
}

type rpcAuthLoginStartRequest struct {
	pluginapi.AuthLoginStartRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type rpcAuthLoginPollRequest struct {
	pluginapi.AuthLoginPollRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

var (
	loginMu       sync.Mutex
	deviceLogins  = make(map[string]*pendingDeviceLogin)
	loginNow      = time.Now
	loginStateKey = newLoginStateKey()
)

func newLoginStateKey() []byte {
	key := make([]byte, 32)
	if _, errRead := rand.Read(key); errRead != nil {
		panic(fmt.Sprintf("initialise Kiro login state key: %v", errRead))
	}
	return key
}

func startLogin(raw []byte) ([]byte, error) {
	var request rpcAuthLoginStartRequest
	if errUnmarshal := json.Unmarshal(raw, &request); errUnmarshal != nil {
		return nil, fmt.Errorf("decode login start request: %w", errUnmarshal)
	}
	method := strings.ToLower(strings.TrimSpace(metadataString(request.Metadata, "method")))
	switch method {
	case "", loginMethodBuilderID:
		return startDeviceLogin(request.HostCallbackID, loginMethodBuilderID, builderIDStartURL, "us-east-1")
	case loginMethodIDC:
		startURL := strings.TrimSpace(metadataString(request.Metadata, "start_url"))
		parsed, errParse := url.Parse(startURL)
		if errParse != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return errorEnvelope("invalid_request", "idc login requires an https start_url query parameter", http.StatusBadRequest, false), nil
		}
		region := strings.ToLower(strings.TrimSpace(metadataString(request.Metadata, "region")))
		if !regionPattern.MatchString(region) {
			return errorEnvelope("invalid_request", "idc login requires the Identity Center region query parameter", http.StatusBadRequest, false), nil
		}
		return startDeviceLogin(request.HostCallbackID, loginMethodIDC, startURL, region)
	default:
		return errorEnvelope("invalid_request", fmt.Sprintf("unsupported Kiro login method %q; use builder-id or idc", method), http.StatusBadRequest, false), nil
	}
}

func startDeviceLogin(hostCallbackID, method, startURL, region string) ([]byte, error) {
	registerBody, _ := json.Marshal(map[string]any{
		"clientName": "Kiro CLI",
		"clientType": "public",
		"scopes":     oidcScopes,
		"grantTypes": []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
	})
	var registration struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	if errRegister := postJSON(hostCallbackID, oidcEndpoint(region)+"/client/register", oidcHeaders(), registerBody, &registration); errRegister != nil {
		return loginErrorEnvelope("register Kiro OIDC client", errRegister), nil
	}
	if registration.ClientID == "" || registration.ClientSecret == "" {
		return errorEnvelope("login_failed", "Kiro OIDC client registration returned no client credentials", http.StatusBadGateway, true), nil
	}

	authorizeBody, _ := json.Marshal(map[string]string{
		"clientId":     registration.ClientID,
		"clientSecret": registration.ClientSecret,
		"startUrl":     startURL,
	})
	var device deviceAuthorization
	if errAuthorize := postJSON(hostCallbackID, oidcEndpoint(region)+"/device_authorization", oidcHeaders(), authorizeBody, &device); errAuthorize != nil {
		return loginErrorEnvelope("start Kiro device authorization", errAuthorize), nil
	}
	if device.DeviceCode == "" || device.VerificationURIComplete == "" {
		return errorEnvelope("login_failed", "Kiro device authorization returned no device code", http.StatusBadGateway, true), nil
	}

	now := loginNow()
	interval := time.Duration(device.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ttl := time.Duration(device.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = deviceLoginFallbackTTL
	}
	state := newLoginState()
	pending := &pendingDeviceLogin{
		method:       method,
		region:       region,
		startURL:     startURL,
		clientID:     registration.ClientID,
		clientSecret: registration.ClientSecret,
		deviceCode:   device.DeviceCode,
		interval:     interval,
		nextPollAt:   now.Add(interval),
		expiresAt:    now.Add(ttl),
	}
	loginMu.Lock()
	pruneExpiredLoginsLocked(now)
	deviceLogins[state] = pending
	loginMu.Unlock()

	return okEnvelope(pluginapi.AuthLoginStartResponse{
		Provider:  pluginIdentifier,
		URL:       device.VerificationURIComplete,
		State:     state,
		ExpiresAt: pending.expiresAt,
		Metadata:  map[string]any{"flow": "device", "user_code": device.UserCode},
	})
}

func pollLogin(raw []byte) ([]byte, error) {
	var request rpcAuthLoginPollRequest
	if errUnmarshal := json.Unmarshal(raw, &request); errUnmarshal != nil {
		return nil, fmt.Errorf("decode login poll request: %w", errUnmarshal)
	}
	now := loginNow()
	loginMu.Lock()
	stored, ok := deviceLogins[request.State]
	if ok && now.After(stored.expiresAt) {
		delete(deviceLogins, request.State)
		ok = false
	}
	ready := ok && !now.Before(stored.nextPollAt)
	var pending pendingDeviceLogin
	if ready {
		// Reserve this poll slot so concurrent status checks do not trigger slow_down,
		// and snapshot the session so the token exchange below runs without the lock.
		stored.nextPollAt = now.Add(stored.interval)
		pending = *stored
	}
	loginMu.Unlock()
	if !ok {
		return pollErrorResponse("Kiro login session expired or is unknown; start a new login")
	}
	if !ready {
		return pollPendingResponse()
	}

	tokenBody, _ := json.Marshal(map[string]string{
		"clientId":     pending.clientID,
		"clientSecret": pending.clientSecret,
		"deviceCode":   pending.deviceCode,
		"grantType":    "urn:ietf:params:oauth:grant-type:device_code",
	})
	response, errPost := hostPost(request.HostCallbackID, oidcEndpoint(pending.region)+"/token", oidcHeaders(), tokenBody)
	if errPost != nil {
		// Transport failures are retried on the next status check.
		return pollPendingResponse()
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		var oidcErr struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(response.Body, &oidcErr)
		switch oidcErr.Error {
		case "authorization_pending":
			return pollPendingResponse()
		case "slow_down":
			loginMu.Lock()
			if current, exists := deviceLogins[request.State]; exists {
				current.interval += 5 * time.Second
				current.nextPollAt = loginNow().Add(current.interval)
			}
			loginMu.Unlock()
			return pollPendingResponse()
		default:
			finishDeviceLogin(request.State)
			reason := firstNonEmpty(oidcErr.Error, fmt.Sprintf("HTTP %d", response.StatusCode))
			return pollErrorResponse("Kiro device authorization failed: " + reason)
		}
	}

	var token oidcTokenResponse
	if errUnmarshal := json.Unmarshal(response.Body, &token); errUnmarshal != nil || token.AccessToken == "" || token.RefreshToken == "" {
		finishDeviceLogin(request.State)
		return pollErrorResponse("Kiro device authorization returned no tokens")
	}
	finishDeviceLogin(request.State)

	credential := kiroCredential{
		Type:         pluginIdentifier,
		AuthMethod:   authMethodIDC,
		Region:       pending.region,
		ClientID:     pending.clientID,
		ClientSecret: pending.clientSecret,
		StartURL:     pending.startURL,
	}
	credential, errApply := applyTokenResponse(credential, token.AccessToken, token.RefreshToken, token.ExpiresIn, "")
	if errApply != nil {
		return pollErrorResponse(errApply.Error())
	}
	switch pending.method {
	case loginMethodBuilderID:
		// Builder ID accounts share one fixed profile; ListAvailableProfiles
		// rejects Builder ID tokens, so the profile cannot be discovered.
		credential.ProfileARN = builderIDProfileARN
	case loginMethodIDC:
		profileARN, errProfile := discoverProfileARN(request.HostCallbackID, credential)
		if errProfile != nil {
			return pollErrorResponse("Kiro login succeeded but no profile was found: " + errProfile.Error())
		}
		credential.ProfileARN = profileARN
	default:
		return pollErrorResponse(fmt.Sprintf("unsupported Kiro login method %q", pending.method))
	}

	fileName := credentialFileName(credential)
	data, errData := authDataFromCredential(credential, fileName, fileName)
	if errData != nil {
		return nil, errData
	}
	return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusSuccess, Auth: data})
}

func finishDeviceLogin(state string) {
	loginMu.Lock()
	delete(deviceLogins, state)
	loginMu.Unlock()
}

func pruneExpiredLoginsLocked(now time.Time) {
	for state, pending := range deviceLogins {
		if now.After(pending.expiresAt) {
			delete(deviceLogins, state)
		}
	}
}

func pollPendingResponse() ([]byte, error) {
	return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusPending})
}

func pollErrorResponse(message string) ([]byte, error) {
	return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: message})
}

func loginErrorEnvelope(action string, errValue error) []byte {
	var refreshErr *tokenRefreshError
	if errors.As(errValue, &refreshErr) && refreshErr.status >= 400 && refreshErr.status < 500 {
		return errorEnvelope("login_failed", fmt.Sprintf("%s: %v", action, errValue), refreshErr.status, false)
	}
	return errorEnvelope("login_failed", fmt.Sprintf("%s: %v", action, errValue), http.StatusBadGateway, true)
}

// newLoginState returns a path-safe state token accepted by CPA's OAuth session store.
func newLoginState() string {
	nonce := make([]byte, 16)
	if _, errRead := rand.Read(nonce); errRead != nil {
		panic(fmt.Sprintf("generate Kiro login state: %v", errRead))
	}
	mac := hmac.New(sha256.New, loginStateKey)
	mac.Write(nonce)
	return "kiro-" + base64.RawURLEncoding.EncodeToString(append(nonce, mac.Sum(nil)[:8]...))
}

// credentialFileName names the auth file after the profile so each Kiro
// account lands in its own file and re-login replaces it.
func credentialFileName(credential kiroCredential) string {
	return fmt.Sprintf("kiro-%s-%s.json", credential.AuthMethod, credentialFingerprint(credential))
}

func metadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	switch value := metadata[key].(type) {
	case string:
		return value
	case []any:
		if len(value) > 0 {
			if first, ok := value[0].(string); ok {
				return first
			}
		}
	}
	return ""
}

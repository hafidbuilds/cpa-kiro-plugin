package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

var regionPattern = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-\d+$`)

var errKiroAPIKeyUnavailable = errors.New("Kiro API key unavailable")

// Kiro credential families. Each one refreshes against a different endpoint.
const (
	authMethodAPIKey      = "apikey"
	authMethodIDC         = "idc"
	authMethodDesktop     = "desktop"
	authMethodExternalIDP = "external-idp"
)

const (
	builderIDStartURL   = "https://view.awsapps.com/start"
	builderIDProfileARN = "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX"

	// tokenRefreshSkew keeps refreshes ahead of the server-side expiry.
	tokenRefreshSkew = 5 * time.Minute
	// minRefreshInterval bounds the host refresh cadence for very short-lived tokens.
	minRefreshInterval = time.Minute
	// defaultTokenLifetime is used when a token endpoint omits expires_in.
	defaultTokenLifetime = time.Hour
)

var oidcScopes = []string{
	"codewhisperer:completions",
	"codewhisperer:analysis",
	"codewhisperer:conversations",
	"codewhisperer:transformations",
	"codewhisperer:taskassist",
}

type kiroCredential struct {
	Type       string `json:"type"`
	AuthMethod string `json:"auth_method,omitempty"`
	APIKey     string `json:"api_key,omitempty"`
	APIKeyEnv  string `json:"api_key_env,omitempty"`
	// Region is the login region: the AWS SSO OIDC region for idc credentials and
	// the Kiro auth-service region for desktop credentials.
	Region string `json:"region,omitempty"`
	// ProfileARN identifies the Kiro profile for this account. Runtime requests
	// require it for OAuth tokens and must be sent to the ARN's region.
	ProfileARN    string `json:"profile_arn,omitempty"`
	AccessToken   string `json:"access_token,omitempty"`
	RefreshToken  string `json:"refresh_token,omitempty"`
	Expired       string `json:"expired,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	ClientSecret  string `json:"client_secret,omitempty"`
	StartURL      string `json:"start_url,omitempty"`
	TokenEndpoint string `json:"token_endpoint,omitempty"`
	Email         string `json:"email,omitempty"`
	Label         string `json:"label,omitempty"`
	Prefix        string `json:"prefix,omitempty"`
	ProxyURL      string `json:"proxy_url,omitempty"`
	Disabled      bool   `json:"disabled,omitempty"`
}

func (c kiroCredential) isOAuth() bool {
	return c.AuthMethod != authMethodAPIKey
}

// runtimeRegion is the region whose runtime host accepts this credential's
// profile. A profile ARN issued in another region is rejected with a generic
// "Improperly formed request.", so the ARN region wins over the login region.
func (c kiroCredential) runtimeRegion() string {
	if region := regionFromProfileARN(c.ProfileARN); region != "" {
		return region
	}
	return apiRegion(c.Region)
}

// apiRegionMap folds AWS SSO regions into the two Kiro API regions.
var apiRegionMap = map[string]string{
	"sa-east-1":      "us-east-1",
	"us-west-1":      "us-east-1",
	"us-west-2":      "us-east-1",
	"us-east-2":      "us-east-1",
	"ap-southeast-1": "us-east-1",
	"ap-southeast-2": "us-east-1",
	"ap-northeast-1": "us-east-1",
	"ap-northeast-2": "us-east-1",
	"ap-south-1":     "us-east-1",
	"eu-west-1":      "eu-central-1",
	"eu-west-2":      "eu-central-1",
	"eu-west-3":      "eu-central-1",
	"eu-north-1":     "eu-central-1",
	"eu-south-1":     "eu-central-1",
	"eu-south-2":     "eu-central-1",
	"eu-central-2":   "eu-central-1",
}

func apiRegion(region string) string {
	if mapped, ok := apiRegionMap[region]; ok {
		return mapped
	}
	return firstNonEmpty(region, "us-east-1")
}

func regionFromProfileARN(arn string) string {
	parts := strings.Split(strings.TrimSpace(arn), ":")
	if len(parts) < 6 || parts[0] != "arn" || parts[2] != "codewhisperer" {
		return ""
	}
	if !regionPattern.MatchString(parts[3]) {
		return ""
	}
	return parts[3]
}

func parseAuth(raw []byte) ([]byte, error) {
	var request pluginapi.AuthParseRequest
	if errUnmarshal := json.Unmarshal(raw, &request); errUnmarshal != nil {
		return nil, fmt.Errorf("decode auth parse request: %w", errUnmarshal)
	}
	credential, handled, errCredential := decodeCredential(request.RawJSON)
	if errCredential != nil {
		return errorEnvelope("invalid_auth", errCredential.Error(), 0, false), nil
	}
	if !handled {
		return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
	}
	authID := strings.TrimSpace(request.FileName)
	if authID == "" {
		authID = "kiro-" + credentialFingerprint(credential)
	}
	data, errData := authDataFromCredential(credential, authID, request.FileName)
	if errData != nil {
		return nil, errData
	}
	return okEnvelope(pluginapi.AuthParseResponse{Handled: true, Auth: data})
}

// authDataFromCredential builds the host record for a credential. OAuth token
// fields are mirrored into Metadata because the host reads access_token,
// refresh_token, and expired from metadata to detect refreshable credentials,
// schedule refreshes, and retry after a 401.
func authDataFromCredential(credential kiroCredential, authID, fileName string) (pluginapi.AuthData, error) {
	storage, errMarshal := json.Marshal(credential)
	if errMarshal != nil {
		return pluginapi.AuthData{}, fmt.Errorf("encode Kiro credential: %w", errMarshal)
	}
	label := firstNonEmpty(credential.Label, credential.Email, strings.TrimSuffix(fileName, filepath.Ext(fileName)), credentialFingerprint(credential))
	metadata := map[string]any{
		"type":        pluginIdentifier,
		"auth_method": credential.AuthMethod,
		"region":      credential.Region,
	}
	attributes := map[string]string{
		"auth_method": credential.AuthMethod,
		"region":      credential.Region,
	}
	if credential.isOAuth() {
		metadata["auth_kind"] = "oauth"
		attributes["auth_kind"] = "oauth"
		metadata["access_token"] = credential.AccessToken
		metadata["refresh_token"] = credential.RefreshToken
		if credential.Expired != "" {
			metadata["expired"] = credential.Expired
		}
		if credential.ProfileARN != "" {
			metadata["profile_arn"] = credential.ProfileARN
			attributes["profile_arn"] = credential.ProfileARN
		}
		if credential.Email != "" {
			metadata["email"] = credential.Email
		}
		if interval := refreshInterval(credential); interval > 0 {
			// The host has no refresh lead for plugin providers and clears
			// NextRefreshAfter after each refresh, so a persisted interval is what
			// keeps the credential on the refresh schedule.
			metadata["refresh_interval_seconds"] = int64(interval / time.Second)
		}
	} else {
		metadata["auth_kind"] = "api_key"
		attributes["auth_kind"] = "api_key"
		metadata["key_source"] = keySource(credential)
		metadata["key_present"] = credential.APIKey != "" || os.Getenv(credential.APIKeyEnv) != ""
	}
	return pluginapi.AuthData{
		Provider:    pluginIdentifier,
		ID:          authID,
		FileName:    fileName,
		Label:       label,
		Prefix:      credential.Prefix,
		ProxyURL:    credential.ProxyURL,
		Disabled:    credential.Disabled,
		StorageJSON: storage,
		Metadata:    metadata,
		Attributes:  attributes,
	}, nil
}

// refreshInterval derives a refresh cadence from the token's remaining lifetime.
func refreshInterval(credential kiroCredential) time.Duration {
	expiry, errParse := time.Parse(time.RFC3339, credential.Expired)
	if errParse != nil {
		return 0
	}
	lifetime := time.Until(expiry) - tokenRefreshSkew
	if lifetime < minRefreshInterval {
		return minRefreshInterval
	}
	return lifetime
}

func refreshAuth(raw []byte) ([]byte, error) {
	var request rpcAuthRefreshRequest
	if errUnmarshal := json.Unmarshal(raw, &request); errUnmarshal != nil {
		return nil, fmt.Errorf("decode auth refresh request: %w", errUnmarshal)
	}
	credential, handled, errCredential := decodeCredential(request.StorageJSON)
	if errCredential != nil {
		return errorEnvelope("invalid_auth", errCredential.Error(), 0, false), nil
	}
	if !handled {
		return errorEnvelope("invalid_auth", "Kiro auth storage is not recognized", 0, false), nil
	}
	if credential.isOAuth() {
		refreshed, errRefresh := refreshOAuthCredential(request.HostCallbackID, credential)
		if errRefresh != nil {
			var refreshErr *tokenRefreshError
			if errors.As(errRefresh, &refreshErr) && refreshErr.status != 0 {
				return errorEnvelope("refresh_failed", errRefresh.Error(), refreshErr.status, false), nil
			}
			return errorEnvelope("refresh_failed", errRefresh.Error(), http.StatusBadGateway, true), nil
		}
		credential = refreshed
	}
	data, errData := authDataFromCredential(credential, request.AuthID, "")
	if errData != nil {
		return nil, errData
	}
	data.Attributes = mergeStringMaps(request.Attributes, data.Attributes)
	return okEnvelope(pluginapi.AuthRefreshResponse{Auth: data})
}

type tokenRefreshError struct {
	status int
	detail string
}

func (e *tokenRefreshError) Error() string {
	return fmt.Sprintf("Kiro token refresh failed: HTTP %d: %s", e.status, e.detail)
}

type oidcTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int64  `json:"expiresIn"`
	ProfileARN   string `json:"profileArn"`
}

type externalIDPTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// refreshOAuthCredential exchanges the refresh token for a new access token
// using the endpoint that issued it. Rotated refresh tokens replace the old one;
// an omitted refresh token or profile ARN keeps the previous value.
func refreshOAuthCredential(hostCallbackID string, credential kiroCredential) (kiroCredential, error) {
	if credential.RefreshToken == "" {
		return credential, &tokenRefreshError{status: http.StatusUnauthorized, detail: "credential has no refresh token"}
	}
	switch credential.AuthMethod {
	case authMethodIDC:
		body, _ := json.Marshal(map[string]string{
			"clientId":     credential.ClientID,
			"clientSecret": credential.ClientSecret,
			"refreshToken": credential.RefreshToken,
			"grantType":    "refresh_token",
		})
		var response oidcTokenResponse
		if errPost := postJSON(hostCallbackID, oidcEndpoint(credential.Region)+"/token", oidcHeaders(), body, &response); errPost != nil {
			return credential, errPost
		}
		return applyTokenResponse(credential, response.AccessToken, response.RefreshToken, response.ExpiresIn, response.ProfileARN)
	case authMethodDesktop:
		body, _ := json.Marshal(map[string]string{"refreshToken": credential.RefreshToken})
		headers := http.Header{"Content-Type": []string{"application/json"}, "User-Agent": []string{desktopUserAgent}}
		var response oidcTokenResponse
		if errPost := postJSON(hostCallbackID, desktopAuthBase(credential.Region)+"/refreshToken", headers, body, &response); errPost != nil {
			return credential, errPost
		}
		return applyTokenResponse(credential, response.AccessToken, response.RefreshToken, response.ExpiresIn, response.ProfileARN)
	case authMethodExternalIDP:
		form := url.Values{
			"grant_type":    []string{"refresh_token"},
			"client_id":     []string{credential.ClientID},
			"refresh_token": []string{credential.RefreshToken},
		}
		headers := http.Header{
			"Content-Type": []string{"application/x-www-form-urlencoded"},
			"Accept":       []string{"application/json"},
		}
		var response externalIDPTokenResponse
		if errPost := postJSON(hostCallbackID, credential.TokenEndpoint, headers, []byte(form.Encode()), &response); errPost != nil {
			return credential, errPost
		}
		return applyTokenResponse(credential, response.AccessToken, response.RefreshToken, response.ExpiresIn, "")
	default:
		return credential, fmt.Errorf("unsupported Kiro auth method %q", credential.AuthMethod)
	}
}

func applyTokenResponse(credential kiroCredential, accessToken, refreshToken string, expiresIn int64, profileARN string) (kiroCredential, error) {
	if strings.TrimSpace(accessToken) == "" {
		return credential, fmt.Errorf("Kiro token response is missing an access token")
	}
	credential.AccessToken = strings.TrimSpace(accessToken)
	if refreshToken = strings.TrimSpace(refreshToken); refreshToken != "" {
		credential.RefreshToken = refreshToken
	}
	if profileARN = strings.TrimSpace(profileARN); profileARN != "" {
		credential.ProfileARN = profileARN
	}
	lifetime := time.Duration(expiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = defaultTokenLifetime
	}
	credential.Expired = time.Now().Add(lifetime).UTC().Format(time.RFC3339)
	return credential, nil
}

const desktopUserAgent = "Kiro-Desktop/0.2.13 (darwin; arm64)"

func oidcEndpoint(region string) string {
	return "https://oidc." + firstNonEmpty(region, "us-east-1") + ".amazonaws.com"
}

func desktopAuthBase(region string) string {
	return "https://prod." + firstNonEmpty(region, "us-east-1") + ".auth.desktop.kiro.dev"
}

func oidcHeaders() http.Header {
	return http.Header{
		"Content-Type":          []string{"application/json"},
		"User-Agent":            []string{"aws-sdk-js/3.714.0 os/macos/24.3.0 lang/js md/nodejs/22.14.0 api/ssooidc/3.714.0 exec-env/kiro-cli/2.7.0 m/E"},
		"Amz-Sdk-Invocation-Id": []string{randomUUID()},
		"Amz-Sdk-Request":       []string{"attempt=1; max=1"},
	}
}

// postJSON sends a request through the host HTTP transport (so the selected
// auth's proxy policy applies) and decodes a 2xx JSON response.
func postJSON(hostCallbackID, endpoint string, headers http.Header, body []byte, out any) error {
	response, errPost := hostPost(hostCallbackID, endpoint, headers, body)
	if errPost != nil {
		return errPost
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return &tokenRefreshError{status: response.StatusCode, detail: limitedErrorBody(response.Body)}
	}
	if out == nil {
		return nil
	}
	if errUnmarshal := json.Unmarshal(response.Body, out); errUnmarshal != nil {
		return fmt.Errorf("decode %s response: %w", redactURL(endpoint), errUnmarshal)
	}
	return nil
}

// hostPost sends a POST through the host HTTP transport and returns the raw
// response, leaving status handling to the caller.
func hostPost(hostCallbackID, endpoint string, headers http.Header, body []byte) (pluginapi.HTTPResponse, error) {
	rawResponse, errCall := invokeHost(pluginabi.MethodHostHTTPDo, rpcHostHTTPRequest{
		HostCallbackID: hostCallbackID,
		Method:         http.MethodPost,
		URL:            endpoint,
		Headers:        headers,
		Body:           body,
	})
	if errCall != nil {
		return pluginapi.HTTPResponse{}, fmt.Errorf("call %s: %w", redactURL(endpoint), errCall)
	}
	var response pluginapi.HTTPResponse
	if errUnmarshal := json.Unmarshal(rawResponse, &response); errUnmarshal != nil {
		return pluginapi.HTTPResponse{}, fmt.Errorf("decode host HTTP response: %w", errUnmarshal)
	}
	return response, nil
}

func redactURL(endpoint string) string {
	parsed, errParse := url.Parse(endpoint)
	if errParse != nil {
		return "upstream endpoint"
	}
	return parsed.Scheme + "://" + parsed.Host + parsed.Path
}

func mergeStringMaps(base, overlay map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overlay))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range overlay {
		out[key] = value
	}
	return out
}

func decodeCredential(raw []byte) (kiroCredential, bool, error) {
	var credential kiroCredential
	if len(raw) == 0 {
		return credential, false, nil
	}
	if errUnmarshal := json.Unmarshal(raw, &credential); errUnmarshal != nil {
		return credential, false, nil
	}
	credential.Type = strings.ToLower(strings.TrimSpace(credential.Type))
	if credential.Type != pluginIdentifier {
		return credential, false, nil
	}
	credential.AuthMethod = strings.ToLower(strings.TrimSpace(credential.AuthMethod))
	credential.APIKey = strings.TrimSpace(credential.APIKey)
	credential.APIKeyEnv = strings.TrimSpace(credential.APIKeyEnv)
	credential.Region = firstNonEmpty(strings.ToLower(strings.TrimSpace(credential.Region)), "us-east-1")
	credential.ProfileARN = strings.TrimSpace(credential.ProfileARN)
	credential.AccessToken = strings.TrimSpace(credential.AccessToken)
	credential.RefreshToken = strings.TrimSpace(credential.RefreshToken)
	credential.Label = strings.TrimSpace(credential.Label)
	credential.Prefix = strings.TrimSpace(credential.Prefix)
	credential.ProxyURL = strings.TrimSpace(credential.ProxyURL)
	if credential.AuthMethod == "" {
		// Records written before OAuth support carry only API-key fields.
		credential.AuthMethod = authMethodAPIKey
	}
	if !regionPattern.MatchString(credential.Region) {
		return credential, true, fmt.Errorf("invalid Kiro region %q", credential.Region)
	}
	if credential.ProfileARN != "" && regionFromProfileARN(credential.ProfileARN) == "" {
		return credential, true, fmt.Errorf("invalid Kiro profile ARN")
	}
	switch credential.AuthMethod {
	case authMethodAPIKey:
		if credential.APIKey == "" && credential.APIKeyEnv == "" {
			return credential, true, fmt.Errorf("either api_key or api_key_env is required")
		}
		if credential.APIKeyEnv != "" && strings.ContainsRune(credential.APIKeyEnv, '=') {
			return credential, true, fmt.Errorf("api_key_env must be an environment variable name")
		}
	case authMethodIDC:
		if credential.ClientID == "" || credential.ClientSecret == "" {
			return credential, true, fmt.Errorf("idc credentials require client_id and client_secret")
		}
	case authMethodDesktop:
	case authMethodExternalIDP:
		if credential.ClientID == "" {
			return credential, true, fmt.Errorf("external-idp credentials require client_id")
		}
		endpoint, errParse := url.Parse(credential.TokenEndpoint)
		if errParse != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
			return credential, true, fmt.Errorf("external-idp credentials require an https token_endpoint")
		}
	default:
		return credential, true, fmt.Errorf("unsupported Kiro auth_method %q", credential.AuthMethod)
	}
	if credential.isOAuth() && credential.AccessToken == "" && credential.RefreshToken == "" {
		return credential, true, fmt.Errorf("%s credentials require access_token or refresh_token", credential.AuthMethod)
	}
	return credential, true, nil
}

// bearerToken returns the credential sent as the Authorization bearer.
func bearerToken(credential kiroCredential) (string, error) {
	if credential.isOAuth() {
		if credential.AccessToken == "" {
			return "", fmt.Errorf("%w: OAuth access token is empty", errKiroAPIKeyUnavailable)
		}
		return credential.AccessToken, nil
	}
	return resolveAPIKey(credential)
}

func resolveAPIKey(credential kiroCredential) (string, error) {
	if credential.APIKey != "" {
		return credential.APIKey, nil
	}
	key := strings.TrimSpace(os.Getenv(credential.APIKeyEnv))
	if key == "" {
		return "", fmt.Errorf("%w: environment variable %s is empty", errKiroAPIKeyUnavailable, credential.APIKeyEnv)
	}
	return key, nil
}

// applyAuthHeaders sets the bearer and, where Kiro requires it, the token type.
// API keys need tokentype API_KEY and external-IdP JWTs need EXTERNAL_IDP;
// AWS SSO and desktop tokens must not carry the header.
func applyAuthHeaders(headers http.Header, credential kiroCredential, token string) {
	headers.Set("Authorization", "Bearer "+token)
	switch credential.AuthMethod {
	case authMethodAPIKey:
		headers.Set("Tokentype", "API_KEY")
	case authMethodExternalIDP:
		headers.Set("Tokentype", "EXTERNAL_IDP")
	default:
		headers.Del("Tokentype")
	}
}

func keySource(credential kiroCredential) string {
	if credential.APIKey != "" {
		return "auth_file"
	}
	return "env:" + credential.APIKeyEnv
}

// credentialFingerprint is a stable, non-secret identifier for labels and IDs.
func credentialFingerprint(credential kiroCredential) string {
	seed := "env:" + credential.APIKeyEnv
	switch {
	case credential.isOAuth():
		seed = "oauth:" + firstNonEmpty(credential.ProfileARN, credential.Email, credential.RefreshToken)
	case credential.APIKey != "":
		seed = credential.APIKey
	}
	sum := sha256.Sum256([]byte("KiroAPIKey/" + seed))
	return hex.EncodeToString(sum[:6])
}

// machineID derives the stable client identifier sent in user-agent headers.
func machineID(credential kiroCredential, token string) string {
	seed := token
	if credential.isOAuth() {
		// Access tokens rotate; keep the identifier stable per account.
		seed = "oauth:" + firstNonEmpty(credential.ProfileARN, credential.RefreshToken, token)
	}
	sum := sha256.Sum256([]byte("KiroAPIKey/" + seed))
	return hex.EncodeToString(sum[:])
}

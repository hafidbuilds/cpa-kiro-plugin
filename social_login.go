package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// Google/GitHub ("social") login through the Kiro auth service.
//
// Kiro only accepts the kiro-cli loopback redirect, http://localhost:3128, for
// this client. CPA does not listen there, so after signing in the browser lands
// on an unreachable localhost page. The user submits that URL to CPA's OAuth
// callback endpoint (POST /v8/management/oauth/callback with redirect_url, or
// GET with code and state); CPA writes it to .oauth-kiro-<state>.oauth in the
// auth directory, and PollLogin exchanges the code from that file.

const (
	loginMethodGoogle = "google"
	loginMethodGitHub = "github"
	loginMethodSocial = "social"

	socialRedirectURI = "http://localhost:3128"
	socialLoginTTL    = 10 * time.Minute
	kiroSignInURL     = "https://app.kiro.dev/signin"
)

type pendingSocialLogin struct {
	codeVerifier string
	loginOption  string
	expiresAt    time.Time
}

var socialLogins = make(map[string]*pendingSocialLogin)

func startSocialLogin(provider string) ([]byte, error) {
	verifierBytes := make([]byte, 32)
	if _, errRead := rand.Read(verifierBytes); errRead != nil {
		return nil, fmt.Errorf("generate PKCE verifier: %w", errRead)
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challenge := sha256.Sum256([]byte(verifier))
	state := newLoginState()

	query := url.Values{
		"state":                 []string{state},
		"code_challenge":        []string{base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": []string{"S256"},
		"redirect_uri":          []string{socialRedirectURI},
		"redirect_from":         []string{"kirocli"},
	}
	if provider != "" {
		query.Set("login_option", provider)
	}

	now := loginNow()
	pending := &pendingSocialLogin{codeVerifier: verifier, loginOption: provider, expiresAt: now.Add(socialLoginTTL)}
	loginMu.Lock()
	pruneExpiredLoginsLocked(now)
	socialLogins[state] = pending
	loginMu.Unlock()

	return okEnvelope(pluginapi.AuthLoginStartResponse{
		Provider:  pluginIdentifier,
		URL:       kiroSignInURL + "?" + query.Encode(),
		State:     state,
		ExpiresAt: pending.expiresAt,
		Metadata:  map[string]any{"flow": "social", "callback": "submit the localhost:3128 redirect URL to /v8/management/oauth/callback"},
	})
}

type oauthCallbackFile struct {
	Code  string `json:"code"`
	State string `json:"state"`
	Error string `json:"error"`
}

// pollSocialLogin reports whether state belongs to a social login and, if so,
// the poll response.
func pollSocialLogin(request rpcAuthLoginPollRequest) ([]byte, bool, error) {
	now := loginNow()
	loginMu.Lock()
	stored, ok := socialLogins[request.State]
	var pending pendingSocialLogin
	if ok {
		if now.After(stored.expiresAt) {
			delete(socialLogins, request.State)
		} else {
			pending = *stored
		}
	}
	loginMu.Unlock()
	if !ok {
		return nil, false, nil
	}
	if pending.codeVerifier == "" {
		response, errResponse := pollErrorResponse("Kiro login session expired; start a new login")
		return response, true, errResponse
	}

	callback, found, errCallback := readOAuthCallbackFile(request.Host.AuthDir, request.State)
	if errCallback != nil {
		finishSocialLogin(request.State)
		response, errResponse := pollErrorResponse(errCallback.Error())
		return response, true, errResponse
	}
	if !found {
		response, errResponse := pollPendingResponse()
		return response, true, errResponse
	}
	finishSocialLogin(request.State)
	if callback.Error != "" {
		response, errResponse := pollErrorResponse("Kiro sign-in failed: " + callback.Error)
		return response, true, errResponse
	}
	if callback.State != request.State || callback.Code == "" {
		response, errResponse := pollErrorResponse("Kiro sign-in callback did not match this login")
		return response, true, errResponse
	}

	credential, errExchange := exchangeSocialCode(request.HostCallbackID, callback.Code, pending)
	if errExchange != nil {
		response, errResponse := pollErrorResponse(errExchange.Error())
		return response, true, errResponse
	}
	fileName := credentialFileName(credential)
	data, errData := authDataFromCredential(credential, fileName, fileName)
	if errData != nil {
		return nil, true, errData
	}
	response, errResponse := okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusSuccess, Auth: data})
	return response, true, errResponse
}

func exchangeSocialCode(hostCallbackID, code string, pending pendingSocialLogin) (kiroCredential, error) {
	redirectURI := socialRedirectURI
	if pending.loginOption != "" {
		redirectURI += "?login_option=" + url.QueryEscape(pending.loginOption)
	}
	body, _ := json.Marshal(map[string]string{
		"code":          code,
		"code_verifier": pending.codeVerifier,
		"redirect_uri":  redirectURI,
	})
	var token oidcTokenResponse
	if errPost := postJSON(hostCallbackID, desktopAuthBase("us-east-1")+"/oauth/token", oidcHeaders(), body, &token); errPost != nil {
		return kiroCredential{}, fmt.Errorf("exchange Kiro sign-in code: %w", errPost)
	}
	if token.RefreshToken == "" {
		return kiroCredential{}, fmt.Errorf("Kiro sign-in returned no refresh token")
	}
	credential := kiroCredential{Type: pluginIdentifier, AuthMethod: authMethodDesktop, Region: "us-east-1"}
	credential, errApply := applyTokenResponse(credential, token.AccessToken, token.RefreshToken, token.ExpiresIn, token.ProfileARN)
	if errApply != nil {
		return kiroCredential{}, errApply
	}
	if credential.ProfileARN == "" {
		profileARN, errProfile := discoverProfileARN(hostCallbackID, credential)
		if errProfile != nil {
			return kiroCredential{}, fmt.Errorf("Kiro sign-in succeeded but no profile was found: %w", errProfile)
		}
		credential.ProfileARN = profileARN
	}
	return credential, nil
}

// readOAuthCallbackFile consumes CPA's callback file for state, if present.
func readOAuthCallbackFile(authDir, state string) (oauthCallbackFile, bool, error) {
	if strings.TrimSpace(authDir) == "" {
		return oauthCallbackFile{}, false, fmt.Errorf("host did not provide an auth directory for the Kiro sign-in callback")
	}
	path := filepath.Join(authDir, ".oauth-"+pluginIdentifier+"-"+state+".oauth")
	raw, errRead := os.ReadFile(path)
	if errors.Is(errRead, os.ErrNotExist) {
		return oauthCallbackFile{}, false, nil
	}
	if errRead != nil {
		return oauthCallbackFile{}, false, fmt.Errorf("read Kiro sign-in callback: %w", errRead)
	}
	_ = os.Remove(path)
	var callback oauthCallbackFile
	if errUnmarshal := json.Unmarshal(raw, &callback); errUnmarshal != nil {
		return oauthCallbackFile{}, false, fmt.Errorf("decode Kiro sign-in callback: %w", errUnmarshal)
	}
	return callback, true, nil
}

func finishSocialLogin(state string) {
	loginMu.Lock()
	delete(socialLogins, state)
	loginMu.Unlock()
}

// socialLoginOption maps a login method to Kiro's login_option value.
func socialLoginOption(method string) (string, bool) {
	switch method {
	case loginMethodGoogle, loginMethodGitHub:
		return method, true
	case loginMethodSocial:
		return "", true
	default:
		return "", false
	}
}

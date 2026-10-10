package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	kiroLoginFlag       = "kiro-login"
	kiroLoginMethodFlag = "kiro-login-method"
	kiroLoginStartURL   = "kiro-login-start-url"
	kiroLoginRegion     = "kiro-login-region"
)

var openKiroLoginURL = openKiroBrowser

func registerKiroCommandLine(_ []byte) ([]byte, error) {
	return okEnvelope(pluginapi.CommandLineRegistrationResponse{Flags: []pluginapi.CommandLineFlag{
		{Name: kiroLoginFlag, Usage: "Login to Kiro using OAuth", Type: "bool"},
		{Name: kiroLoginMethodFlag, Usage: "Kiro login method: builder-id, idc, github, google, or social", Type: "string", DefaultValue: loginMethodBuilderID},
		{Name: kiroLoginStartURL, Usage: "IAM Identity Center start URL", Type: "string"},
		{Name: kiroLoginRegion, Usage: "IAM Identity Center region", Type: "string", DefaultValue: "us-east-1"},
	}})
}

func executeKiroCommandLine(raw []byte) ([]byte, error) {
	var request pluginapi.CommandLineExecutionRequest
	if errUnmarshal := json.Unmarshal(raw, &request); errUnmarshal != nil {
		return nil, fmt.Errorf("decode Kiro command-line request: %w", errUnmarshal)
	}
	if !commandLineFlagSet(request, kiroLoginFlag) {
		return okEnvelope(pluginapi.CommandLineExecutionResponse{})
	}

	method, errMethod := normalizeKiroLoginMethod(commandLineFlag(request, kiroLoginMethodFlag))
	if errMethod != nil {
		return okEnvelope(pluginapi.CommandLineExecutionResponse{
			Stderr:   []byte(errMethod.Error() + "\n"),
			ExitCode: 2,
		})
	}

	startURL := strings.TrimSpace(commandLineFlag(request, kiroLoginStartURL))
	region := strings.TrimSpace(commandLineFlag(request, kiroLoginRegion))
	if region == "" {
		region = "us-east-1"
	}
	if method == loginMethodIDC && startURL == "" {
		return okEnvelope(pluginapi.CommandLineExecutionResponse{
			Stderr:   []byte("Kiro IAM Identity Center login requires --kiro-login-start-url\n"),
			ExitCode: 2,
		})
	}

	metadata := map[string]any{"method": method}
	if method == loginMethodIDC {
		metadata["start_url"] = startURL
		metadata["region"] = region
	}
	startRequest, errMarshal := json.Marshal(rpcAuthLoginStartRequest{
		AuthLoginStartRequest: pluginapi.AuthLoginStartRequest{
			Provider: pluginIdentifier,
			Host:     request.Host,
			Metadata: metadata,
		},
	})
	if errMarshal != nil {
		return nil, fmt.Errorf("encode Kiro login request: %w", errMarshal)
	}
	startRaw, errStart := startLogin(startRequest)
	if errStart != nil {
		return nil, errStart
	}
	start, errDecodeStart := decodeKiroLoginEnvelope[pluginapi.AuthLoginStartResponse](startRaw)
	if errDecodeStart != nil {
		return commandLineErrorResponse(errDecodeStart)
	}

	var callbackCleanup func()
	if method == loginMethodGoogle || method == loginMethodGitHub || method == loginMethodSocial {
		callbackCleanup, errStart = startKiroSocialCallback(request.Host.AuthDir, start.State)
		if errStart != nil {
			return commandLineErrorResponse(errStart)
		}
		defer callbackCleanup()
	}

	var output bytes.Buffer
	fmt.Fprintf(&output, "Kiro %s login started.\n", method)
	fmt.Fprintf(&output, "Login URL: %s\n", start.URL)
	if errOpen := openKiroLoginURL(start.URL); errOpen != nil {
		fmt.Fprintf(&output, "Open the URL above in a browser: %v\n", errOpen)
	}

	pollRequest := rpcAuthLoginPollRequest{AuthLoginPollRequest: pluginapi.AuthLoginPollRequest{
		Provider: pluginIdentifier,
		State:    start.State,
		Host:     request.Host,
	}}
	deadline := start.ExpiresAt
	if deadline.IsZero() {
		deadline = time.Now().Add(10 * time.Minute)
	}
	for time.Now().Before(deadline) {
		pollRaw, errPoll := json.Marshal(pollRequest)
		if errPoll != nil {
			return nil, fmt.Errorf("encode Kiro login poll request: %w", errPoll)
		}
		pollResponseRaw, errPoll := pollLogin(pollRaw)
		if errPoll != nil {
			return nil, errPoll
		}
		poll, errDecodePoll := decodeKiroLoginEnvelope[pluginapi.AuthLoginPollResponse](pollResponseRaw)
		if errDecodePoll != nil {
			return commandLineErrorResponse(errDecodePoll)
		}
		switch poll.Status {
		case pluginapi.AuthLoginStatusPending:
			time.Sleep(time.Second)
			continue
		case pluginapi.AuthLoginStatusSuccess:
			return okEnvelope(pluginapi.CommandLineExecutionResponse{
				Stdout: output.Bytes(),
				Auths:  []pluginapi.AuthData{poll.Auth},
			})
		default:
			message := firstNonEmpty(poll.Message, "Kiro login failed")
			return okEnvelope(pluginapi.CommandLineExecutionResponse{
				Stdout:   output.Bytes(),
				Stderr:   []byte(message + "\n"),
				ExitCode: 1,
			})
		}
	}
	return okEnvelope(pluginapi.CommandLineExecutionResponse{
		Stdout:   output.Bytes(),
		Stderr:   []byte("Kiro login timed out. Start the command again.\n"),
		ExitCode: 1,
	})
}

func normalizeKiroLoginMethod(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "builder", "builder-id", "builderid":
		return loginMethodBuilderID, nil
	case loginMethodIDC:
		return loginMethodIDC, nil
	case loginMethodGitHub:
		return loginMethodGitHub, nil
	case loginMethodGoogle:
		return loginMethodGoogle, nil
	case loginMethodSocial:
		return loginMethodSocial, nil
	default:
		return "", fmt.Errorf("unsupported Kiro login method %q; use builder-id, idc, github, google, or social", raw)
	}
}

func commandLineFlag(request pluginapi.CommandLineExecutionRequest, name string) string {
	if value, ok := request.TriggeredFlags[name]; ok && value.Set {
		return value.Value
	}
	if value, ok := request.Flags[name]; ok {
		return value.Value
	}
	return ""
}

func commandLineFlagSet(request pluginapi.CommandLineExecutionRequest, name string) bool {
	value, ok := request.TriggeredFlags[name]
	return ok && value.Set
}

func decodeKiroLoginEnvelope[T any](raw []byte) (T, error) {
	var zero T
	var response envelope
	if errUnmarshal := json.Unmarshal(raw, &response); errUnmarshal != nil {
		return zero, fmt.Errorf("decode Kiro login response: %w", errUnmarshal)
	}
	if !response.OK {
		if response.Error != nil {
			return zero, fmt.Errorf("%s: %s", response.Error.Code, response.Error.Message)
		}
		return zero, fmt.Errorf("Kiro login returned an unknown error")
	}
	var result T
	if errUnmarshal := json.Unmarshal(response.Result, &result); errUnmarshal != nil {
		return zero, fmt.Errorf("decode Kiro login result: %w", errUnmarshal)
	}
	return result, nil
}

func commandLineErrorResponse(errValue error) ([]byte, error) {
	return okEnvelope(pluginapi.CommandLineExecutionResponse{
		Stderr:   []byte(errValue.Error() + "\n"),
		ExitCode: 1,
	})
}

func openKiroBrowser(loginURL string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", loginURL)
	case "linux":
		command = exec.Command("xdg-open", loginURL)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", loginURL)
	default:
		return fmt.Errorf("automatic browser launch is not supported on %s", runtime.GOOS)
	}
	if errStart := command.Start(); errStart != nil {
		return errStart
	}
	_ = command.Process.Release()
	return nil
}

func startKiroSocialCallback(authDir, state string) (func(), error) {
	if strings.TrimSpace(authDir) == "" {
		return nil, fmt.Errorf("CLIProxyAPI did not provide an auth directory")
	}
	if errMkdir := os.MkdirAll(authDir, 0o700); errMkdir != nil {
		return nil, fmt.Errorf("create Kiro auth directory: %w", errMkdir)
	}

	listener, errListen := net.Listen("tcp", "127.0.0.1:3128")
	if errListen != nil {
		return nil, fmt.Errorf("listen for Kiro social login callback on 127.0.0.1:3128: %w", errListen)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		callback := oauthCallbackFile{
			Code:  request.URL.Query().Get("code"),
			State: request.URL.Query().Get("state"),
			Error: request.URL.Query().Get("error"),
		}
		if callback.State != state {
			http.Error(writer, "Kiro login state does not match", http.StatusBadRequest)
			return
		}
		raw, errMarshal := json.Marshal(callback)
		if errMarshal != nil {
			http.Error(writer, "encode Kiro login callback failed", http.StatusInternalServerError)
			return
		}
		path := filepath.Join(authDir, ".oauth-"+pluginIdentifier+"-"+state+".oauth")
		if errWrite := os.WriteFile(path, raw, 0o600); errWrite != nil {
			http.Error(writer, "save Kiro login callback failed", http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = writer.Write([]byte("Kiro login callback received. Return to the terminal.\n"))
	})

	server := &http.Server{Handler: mux}
	go func() {
		if errServe := server.Serve(listener); errServe != nil && errServe != http.ErrServerClosed {
			return
		}
	}()
	return func() {
		_ = server.Shutdown(context.Background())
	}, nil
}

package main

import (
	"encoding/json"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestRegisterKiroCommandLineDeclaresLoginFlags(t *testing.T) {
	raw, errRegister := registerKiroCommandLine(nil)
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	var response pluginapi.CommandLineRegistrationResponse
	if errDecode := decodeKiroCommandLineResult(raw, &response); errDecode != nil {
		t.Fatal(errDecode)
	}

	got := make(map[string]pluginapi.CommandLineFlag, len(response.Flags))
	for _, flag := range response.Flags {
		got[flag.Name] = flag
	}
	for _, name := range []string{kiroLoginFlag, kiroLoginMethodFlag, kiroLoginStartURL, kiroLoginRegion} {
		if _, ok := got[name]; !ok {
			t.Errorf("missing Kiro login flag %q", name)
		}
	}
	if got[kiroLoginMethodFlag].DefaultValue != loginMethodBuilderID {
		t.Fatalf("login method default = %q, want %q", got[kiroLoginMethodFlag].DefaultValue, loginMethodBuilderID)
	}
}

func TestNormalizeKiroLoginMethod(t *testing.T) {
	tests := map[string]string{
		"":          loginMethodBuilderID,
		"builder":   loginMethodBuilderID,
		"builderid": loginMethodBuilderID,
		"idc":       loginMethodIDC,
		"github":    loginMethodGitHub,
		"google":    loginMethodGoogle,
		"social":    loginMethodSocial,
	}
	for raw, want := range tests {
		got, errNormalize := normalizeKiroLoginMethod(raw)
		if errNormalize != nil {
			t.Errorf("normalizeKiroLoginMethod(%q) error = %v", raw, errNormalize)
			continue
		}
		if got != want {
			t.Errorf("normalizeKiroLoginMethod(%q) = %q, want %q", raw, got, want)
		}
	}
	if _, errNormalize := normalizeKiroLoginMethod("password"); errNormalize == nil {
		t.Fatal("normalizeKiroLoginMethod(password) error = nil")
	}
}

func TestExecuteKiroCommandLineRequiresIDCStartURL(t *testing.T) {
	rawRequest, errMarshal := json.Marshal(pluginapi.CommandLineExecutionRequest{
		TriggeredFlags: map[string]pluginapi.CommandLineFlagValue{
			kiroLoginFlag:       {Name: kiroLoginFlag, Type: "bool", Value: "true", Set: true},
			kiroLoginMethodFlag: {Name: kiroLoginMethodFlag, Type: "string", Value: loginMethodIDC, Set: true},
		},
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	rawResponse, errExecute := executeKiroCommandLine(rawRequest)
	if errExecute != nil {
		t.Fatal(errExecute)
	}
	var response pluginapi.CommandLineExecutionResponse
	if errDecode := decodeKiroCommandLineResult(rawResponse, &response); errDecode != nil {
		t.Fatal(errDecode)
	}
	if response.ExitCode != 2 || string(response.Stderr) == "" {
		t.Fatalf("response = %#v, want validation error", response)
	}
}

func decodeKiroCommandLineResult(raw []byte, result any) error {
	var response envelope
	if errUnmarshal := json.Unmarshal(raw, &response); errUnmarshal != nil {
		return errUnmarshal
	}
	if !response.OK {
		if response.Error != nil {
			return response.Error
		}
		return &testCommandLineError{message: "command-line response failed"}
	}
	return json.Unmarshal(response.Result, result)
}

type testCommandLineError struct {
	message string
}

func (e *testCommandLineError) Error() string { return e.message }

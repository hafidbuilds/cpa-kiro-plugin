package main

import (
	"encoding/json"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestRegisterKiroCommandLineDeclaresOnlyLoginFlag(t *testing.T) {
	raw, errRegister := registerKiroCommandLine(nil)
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	var response pluginapi.CommandLineRegistrationResponse
	if errDecode := decodeKiroCommandLineResult(raw, &response); errDecode != nil {
		t.Fatal(errDecode)
	}
	if len(response.Flags) != 1 {
		t.Fatalf("registered flags = %d, want 1", len(response.Flags))
	}
	if response.Flags[0].Name != kiroLoginFlag || response.Flags[0].Type != "bool" {
		t.Fatalf("registered flag = %#v, want %q bool flag", response.Flags[0], kiroLoginFlag)
	}
}

func TestExecuteKiroCommandLineWithoutLoginFlagIsNoOp(t *testing.T) {
	rawRequest, errMarshal := json.Marshal(pluginapi.CommandLineExecutionRequest{})
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
	if response.ExitCode != 0 || len(response.Stdout) != 0 || len(response.Stderr) != 0 {
		t.Fatalf("response = %#v, want an empty success response", response)
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

package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestDiscoverKiroModelsForAuthPaginatesAndCaches(t *testing.T) {
	configureKiroTest(t, "models:\n  - '*'\n")
	t.Setenv("KIRO_TEST_KEY", "test-discovery-key")

	var requests []rpcHostHTTPRequest
	previous := invokeHost
	invokeHost = func(method string, payload any) (json.RawMessage, error) {
		if method != pluginabi.MethodHostHTTPDo {
			return nil, os.ErrInvalid
		}
		request := payload.(rpcHostHTTPRequest)
		requests = append(requests, request)
		if request.Headers.Get("Authorization") != "Bearer test-discovery-key" || request.Headers.Get("TokenType") != "API_KEY" {
			t.Fatalf("discovery headers = %#v", request.Headers)
		}
		machine := machineID(kiroCredential{AuthMethod: authMethodAPIKey}, "test-discovery-key")
		if !strings.Contains(request.Headers.Get("User-Agent"), "api/codewhispererruntime#1.0.0") ||
			!strings.HasSuffix(request.Headers.Get("User-Agent"), "-"+machine) ||
			!strings.HasSuffix(request.Headers.Get("X-Amz-User-Agent"), "-"+machine) ||
			request.Headers.Get("X-Amzn-Codewhisperer-Optout") != "true" {
			t.Fatalf("Kiro identity headers = %#v", request.Headers)
		}
		parsed, errParse := url.Parse(request.URL)
		if errParse != nil {
			t.Fatal(errParse)
		}
		if parsed.Host != "codewhisperer.us-east-1.amazonaws.com" || parsed.Path != "/ListAvailableModels" {
			t.Fatalf("discovery URL = %q", request.URL)
		}
		var body []byte
		switch len(requests) {
		case 1:
			if parsed.Query().Get("nextToken") != "" {
				t.Fatalf("first nextToken = %q", parsed.Query().Get("nextToken"))
			}
			body = []byte(`{
				"models":[
					{"modelId":"claude-opus-5","modelName":"Claude Opus 5","description":"Large context","supportedInputTypes":["TEXT","IMAGE"],"tokenLimits":{"maxInputTokens":1000000,"maxOutputTokens":128000}},
					{"modelId":"","modelName":"invalid"}
				],
				"nextToken":"page +/="
			}`)
		case 2:
			if parsed.Query().Get("nextToken") != "page +/=" {
				t.Fatalf("second nextToken = %q", parsed.Query().Get("nextToken"))
			}
			body = []byte(`{
				"models":[
					{"modelId":"claude-opus-5","modelName":"duplicate"},
					{"modelId":"glm-5","modelName":"GLM 5","supportedInputTypes":["TEXT"],"tokenLimits":{"maxInputTokens":200000,"maxOutputTokens":64000}}
				],
				"nextToken":null
			}`)
		default:
			t.Fatalf("unexpected discovery request %d", len(requests))
		}
		return mustJSONRaw(pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: body}), nil
	}
	t.Cleanup(func() { invokeHost = previous })

	response := callModelsForAuthTest(t, "kiro-pro", "callback-1")
	if len(response.Models) != 2 {
		t.Fatalf("discovered models = %#v", response.Models)
	}
	if response.Models[0].ID != "claude-opus-5" || response.Models[0].InputTokenLimit != 1_000_000 || response.Models[0].OutputTokenLimit != 128_000 {
		t.Fatalf("first model = %#v", response.Models[0])
	}
	if strings.Join(response.Models[0].SupportedInputModalities, ",") != "text,image" {
		t.Fatalf("first model modalities = %#v", response.Models[0].SupportedInputModalities)
	}
	if response.Models[1].ID != "glm-5" || strings.Join(response.Models[1].SupportedInputModalities, ",") != "text" {
		t.Fatalf("second model = %#v", response.Models[1])
	}

	cached := callModelsForAuthTest(t, "kiro-pro", "callback-2")
	if len(cached.Models) != 2 || len(requests) != 2 {
		t.Fatalf("cached models=%d HTTP requests=%d", len(cached.Models), len(requests))
	}
}

func TestBuildKiroModelDiscoveryURLUsesRegionalHosts(t *testing.T) {
	tests := []struct {
		region string
		host   string
	}{
		{region: "us-east-1", host: "codewhisperer.us-east-1.amazonaws.com"},
		{region: "eu-central-1", host: "q.eu-central-1.amazonaws.com"},
	}
	for _, test := range tests {
		rawURL, errURL := modelDiscoveryURL(test.region, "", "")
		if errURL != nil {
			t.Fatalf("modelDiscoveryURL(%q) error = %v", test.region, errURL)
		}
		parsed, errParse := url.Parse(rawURL)
		if errParse != nil {
			t.Fatal(errParse)
		}
		if parsed.Host != test.host {
			t.Fatalf("modelDiscoveryURL(%q) host = %q, want %q", test.region, parsed.Host, test.host)
		}
	}
}

func TestDiscoverKiroModelsForAuthAppliesAllowList(t *testing.T) {
	configureKiroTest(t, "models:\n  - claude-sonnet-4.5\n")
	t.Setenv("KIRO_TEST_KEY", "test-allow-list-key")

	previous := invokeHost
	invokeHost = func(method string, payload any) (json.RawMessage, error) {
		if method != pluginabi.MethodHostHTTPDo {
			return nil, os.ErrInvalid
		}
		body := []byte(`{"models":[{"modelId":"claude-sonnet-4.5","modelName":"Sonnet"},{"modelId":"claude-opus-5","modelName":"Opus"}]}`)
		return mustJSONRaw(pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: body}), nil
	}
	t.Cleanup(func() { invokeHost = previous })

	response := callModelsForAuthTest(t, "kiro-allow-list", "callback-allow-list")
	if len(response.Models) != 1 || response.Models[0].ID != "claude-sonnet-4.5" {
		t.Fatalf("allow-listed models = %#v", response.Models)
	}
}

func TestDiscoverKiroModelsForAuthUsesConfiguredFallback(t *testing.T) {
	configureKiroTest(t, "models:\n  - '*'\n")
	t.Setenv("KIRO_TEST_KEY", "test-fallback-key")

	previous := invokeHost
	invokeHost = func(method string, payload any) (json.RawMessage, error) {
		switch method {
		case pluginabi.MethodHostHTTPDo:
			return mustJSONRaw(pluginapi.HTTPResponse{StatusCode: http.StatusServiceUnavailable, Body: []byte(`{"message":"temporary"}`)}), nil
		case pluginabi.MethodHostLog:
			return json.RawMessage(`{}`), nil
		default:
			return nil, os.ErrInvalid
		}
	}
	t.Cleanup(func() { invokeHost = previous })

	response := callModelsForAuthTest(t, "kiro-fallback", "callback-fallback")
	if len(response.Models) != 2 || response.Models[0].ID != "claude-sonnet-4.5" || response.Models[1].ID != "claude-haiku-4.5" {
		t.Fatalf("fallback models = %#v", response.Models)
	}
	for _, model := range response.Models {
		if model.ID == "*" {
			t.Fatal("wildcard was registered as a model")
		}
	}
}

func TestDiscoverKiroModelsForAuthUsesStaleCache(t *testing.T) {
	configureKiroTest(t, "models:\n  - '*'\n")
	t.Setenv("KIRO_TEST_KEY", "test-stale-key")
	cacheKey := modelCacheKey("kiro-stale", "us-east-1", "test-stale-key")
	modelCacheMu.Lock()
	modelCache[cacheKey] = modelCacheEntry{
		Models:    []pluginapi.ModelInfo{{ID: "claude-opus-5", Name: "Claude Opus 5"}},
		FetchedAt: time.Now().Add(-modelCacheTTL - time.Second),
	}
	modelCacheMu.Unlock()

	previous := invokeHost
	invokeHost = func(method string, payload any) (json.RawMessage, error) {
		switch method {
		case pluginabi.MethodHostHTTPDo:
			return nil, os.ErrDeadlineExceeded
		case pluginabi.MethodHostLog:
			return json.RawMessage(`{}`), nil
		default:
			return nil, os.ErrInvalid
		}
	}
	t.Cleanup(func() { invokeHost = previous })

	response := callModelsForAuthTest(t, "kiro-stale", "callback-stale")
	if len(response.Models) != 1 || response.Models[0].ID != "claude-opus-5" {
		t.Fatalf("stale models = %#v", response.Models)
	}
}
func configureKiroTest(t *testing.T, configYAML string) {
	t.Helper()
	request, errMarshal := json.Marshal(lifecycleRequest{ConfigYAML: []byte(configYAML)})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if errConfigure := configure(request); errConfigure != nil {
		t.Fatal(errConfigure)
	}
	t.Cleanup(func() {
		if errConfigure := configure(nil); errConfigure != nil {
			t.Errorf("restore default configuration: %v", errConfigure)
		}
	})
}

func callModelsForAuthTest(t *testing.T, authID, hostCallbackID string) pluginapi.ModelResponse {
	t.Helper()
	rawRequest, errMarshal := json.Marshal(rpcAuthModelRequest{
		AuthModelRequest: pluginapi.AuthModelRequest{
			AuthID:      authID,
			StorageJSON: []byte(`{"type":"kiro","api_key_env":"KIRO_TEST_KEY","region":"us-east-1"}`),
		},
		HostCallbackID: hostCallbackID,
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	rawResponse, errModels := discoverKiroModelsForAuth(rawRequest)
	if errModels != nil {
		t.Fatal(errModels)
	}
	var env envelope
	if errUnmarshal := json.Unmarshal(rawResponse, &env); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if !env.OK {
		t.Fatalf("discoverKiroModelsForAuth() envelope = %#v", env)
	}
	var response pluginapi.ModelResponse
	if errUnmarshal := json.Unmarshal(env.Result, &response); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	return response
}

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Kiro reason codes that change how a failure is scheduled.
const (
	reasonMonthlyRequestCount = "MONTHLY_REQUEST_COUNT"
	reasonModelCapacity       = "INSUFFICIENT_MODEL_CAPACITY"
	reasonRequestRateExceeded = "USER_REQUEST_RATE_EXCEEDED"
)

var reasonMarkers = []string{
	reasonMonthlyRequestCount,
	reasonModelCapacity,
	reasonRequestRateExceeded,
	"CONTENT_LENGTH_EXCEEDS_THRESHOLD",
	"REQUEST_BODY_INVALID",
}

// maxRetryAfterHint bounds header-provided retry hints.
const maxRetryAfterHint = 24 * time.Hour

var upstreamNow = time.Now

// upstreamError is a classified Kiro runtime failure. status is what CPA sees;
// it can differ from upstreamStatus where Kiro's status would make CPA schedule
// the failure incorrectly.
type upstreamError struct {
	status           int
	upstreamStatus   int
	reason           string
	message          string
	retryAfter       time.Duration
	credentialScoped bool
}

func (e *upstreamError) Error() string {
	return e.message
}

// classifyUpstreamError maps a non-2xx Kiro runtime response onto CPA's
// cooldown semantics:
//   - MONTHLY_REQUEST_COUNT is an account-wide quota that only resets at the
//     start of the next month. It is reported as a credential-scoped 429 with a
//     retry hint until that reset, whatever status Kiro used, because CPA only
//     honors retry hints and credential scope on 429.
//   - A 403 whose body says the bearer token is invalid is reported as 401 so
//     CPA refreshes the credential and retries; Kiro uses 403 for expired tokens.
//   - Other 429s carry the response's retry header as a hint.
func classifyUpstreamError(status int, headers http.Header, body []byte) *upstreamError {
	detail := limitedErrorBody(body)
	reason := extractReasonCode(body)
	result := &upstreamError{
		status:         status,
		upstreamStatus: status,
		reason:         reason,
		message:        fmt.Sprintf("Kiro upstream HTTP %d: %s", status, detail),
	}
	switch {
	case reason == reasonMonthlyRequestCount:
		now := upstreamNow().UTC()
		result.status = http.StatusTooManyRequests
		result.credentialScoped = true
		result.retryAfter = nextMonthStart(now).Sub(now)
	case status == http.StatusForbidden && isInvalidBearerToken(body):
		result.status = http.StatusUnauthorized
	case status == http.StatusTooManyRequests:
		result.retryAfter = retryAfterFromHeaders(headers)
	}
	return result
}

// nextMonthStart is when Kiro's monthly allowance resets; usage responses
// report nextDateReset as midnight UTC on the first of the month.
func nextMonthStart(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
}

func extractReasonCode(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "{") {
		var parsed struct {
			Reason     string `json:"reason"`
			ReasonCode string `json:"reasonCode"`
		}
		if json.Unmarshal([]byte(trimmed), &parsed) == nil {
			if reason := firstNonEmpty(parsed.Reason, parsed.ReasonCode); reason != "" {
				return reason
			}
		}
	}
	for _, marker := range reasonMarkers {
		if strings.Contains(trimmed, marker) {
			return marker
		}
	}
	return ""
}

func isInvalidBearerToken(body []byte) bool {
	text := strings.ToLower(string(body))
	return strings.Contains(text, "bearer token included in the request is invalid") ||
		strings.Contains(text, "invalid token") ||
		strings.Contains(text, "token has expired")
}

func retryAfterFromHeaders(headers http.Header) time.Duration {
	if headers == nil {
		return 0
	}
	if value := strings.TrimSpace(headers.Get("Retry-After-Ms")); value != "" {
		if millis, errParse := strconv.ParseInt(value, 10, 64); errParse == nil && millis > 0 {
			return clampRetryAfter(time.Duration(millis) * time.Millisecond)
		}
	}
	for _, name := range []string{"Retry-After", "X-Ratelimit-Reset-After"} {
		value := strings.TrimSpace(headers.Get(name))
		if value == "" {
			continue
		}
		if seconds, errParse := strconv.ParseFloat(value, 64); errParse == nil && seconds > 0 {
			return clampRetryAfter(time.Duration(seconds * float64(time.Second)))
		}
		if at, errParse := http.ParseTime(value); errParse == nil {
			if wait := at.Sub(upstreamNow()); wait > 0 {
				return clampRetryAfter(wait)
			}
		}
	}
	return 0
}

func clampRetryAfter(wait time.Duration) time.Duration {
	if wait > maxRetryAfterHint {
		return maxRetryAfterHint
	}
	return wait
}

// upstreamFailure reports the CPA-facing status and scope for an upstream error.
func upstreamFailure(errValue error) (int, bool) {
	var classified *upstreamError
	if errors.As(errValue, &classified) {
		return classified.status, classified.credentialScoped
	}
	return 0, false
}

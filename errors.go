package onionguard

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"onionguard/store"
)

// Storage Sentinel Errors (re-exported from store package for caller convenience)
var (
	ErrNotFound         = store.ErrNotFound
	ErrCapacityExceeded = store.ErrCapacityExceeded
	ErrKeyTooLarge      = store.ErrKeyTooLarge
	ErrValueTooLarge    = store.ErrValueTooLarge
	ErrStoreClosed      = store.ErrStoreClosed
	ErrStoreUnavailable = store.ErrStoreUnavailable
	ErrInvalidTTL       = store.ErrInvalidTTL
	ErrLockUnavailable  = store.ErrLockUnavailable
	ErrInvalidValue     = store.ErrInvalidValue

	// Engine & Configuration Sentinel Errors
	ErrEngineNotInitialized = errors.New("onionguard: engine not initialized")
	ErrStoreNotConfigured   = errors.New("onionguard: store not configured")
	ErrCircuitOpen          = errors.New("onionguard: circuit breaker is open; service temporarily unavailable")
)

// Session & Admission Sentinel Errors
var (
	ErrInvalidSession      = errors.New("onionguard: invalid or malformed session")
	ErrSessionExpired      = errors.New("onionguard: session has expired")
	ErrSessionRevoked      = errors.New("onionguard: session has been revoked")
	ErrWaitTimeNotElapsed  = errors.New("onionguard: wait time has not elapsed")
	ErrWaitRequired        = ErrWaitTimeNotElapsed
	ErrInvalidTransition   = errors.New("onionguard: invalid admission state transition")
	ErrRenewalLimitReached = errors.New("onionguard: maximum session renewals exceeded")
)

// Challenge & CAPTCHA Sentinel Errors
var (
	ErrChallengeNotFound   = errors.New("onionguard: challenge not found or already consumed")
	ErrChallengeRequired   = errors.New("onionguard: challenge is required")
	ErrChallengeInvalid    = errors.New("onionguard: challenge solution is incorrect")
	ErrChallengeFailed     = ErrChallengeInvalid
	ErrChallengeExpired    = errors.New("onionguard: challenge has expired")
	ErrMaxAttemptsExceeded = errors.New("onionguard: maximum challenge attempts exceeded")
)

// Rate Limiting & HTTP Transport Sentinel Errors
var (
	ErrRateLimited     = errors.New("onionguard: rate limit quota exceeded")
	ErrPayloadTooLarge = errors.New("onionguard: request payload exceeds limit")
	ErrInvalidToken    = errors.New("onionguard: invalid or unauthorized API token")
)

// secretPatterns matches sensitive tokens, passwords, and credentials for scrubbing.
var (
	bearerRegex   = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9_\-\.]+`)
	passwordRegex = regexp.MustCompile(`(?i)(password[:=]\s*)[^\s,;&]+`)
	tokenRegex    = regexp.MustCompile(`(?i)(token[:=]\s*)[^\s,;&]+`)
	cookieRegex   = regexp.MustCompile(`(?i)(session[:=]\s*)[^\s,;&]+`)
)

// ScrubSecrets strips raw credentials, authorization tokens, passwords, and session IDs
// from error and log messages (Invariant 1).
func ScrubSecrets(input string) string {
	if input == "" {
		return ""
	}
	s := bearerRegex.ReplaceAllString(input, "${1}[REDACTED]")
	s = passwordRegex.ReplaceAllString(s, "${1}[REDACTED]")
	s = tokenRegex.ReplaceAllString(s, "${1}[REDACTED]")
	s = cookieRegex.ReplaceAllString(s, "${1}[REDACTED]")
	return s
}

// AdmissionError provides structured HTTP context without leaking secrets (Invariant 1).
type AdmissionError struct {
	StatusCode int           `json:"status"`
	Code       string        `json:"code"`
	Message    string        `json:"message"`
	RetryAfter time.Duration `json:"retry_after,omitempty"`
	Err        error         `json:"-"` // Internal cause; never serialized to client HTTP responses
}

// Error formats the error message safely, ensuring internal secrets are scrubbed.
func (e *AdmissionError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s (%s): %s", e.Message, e.Code, ScrubSecrets(e.Err.Error()))
	}
	return fmt.Sprintf("%s (%s)", e.Message, e.Code)
}

// Unwrap returns the underlying error.
func (e *AdmissionError) Unwrap() error {
	return e.Err
}

// ClientSafeError translates internal errors into client-safe AdmissionError structs,
// ensuring no stack traces, database details, or raw tokens are leaked (Invariant 1).
func ClientSafeError(err error) *AdmissionError {
	if err == nil {
		return nil
	}

	var admErr *AdmissionError
	if errors.As(err, &admErr) {
		return admErr
	}

	switch {
	case errors.Is(err, ErrRateLimited):
		return &AdmissionError{
			StatusCode: 429,
			Code:       "RATE_LIMITED",
			Message:    "Too many requests. Please slow down.",
			Err:        err,
		}
	case errors.Is(err, ErrWaitTimeNotElapsed):
		return &AdmissionError{
			StatusCode: 429,
			Code:       "WAIT_ROOM",
			Message:    "Proof of patience in progress. Please wait.",
			Err:        err,
		}
	case errors.Is(err, ErrPayloadTooLarge):
		return &AdmissionError{
			StatusCode: 413,
			Code:       "PAYLOAD_TOO_LARGE",
			Message:    "Request entity too large.",
			Err:        err,
		}
	case errors.Is(err, ErrInvalidToken):
		return &AdmissionError{
			StatusCode: 401,
			Code:       "UNAUTHORIZED",
			Message:    "Invalid or unauthorized credentials.",
			Err:        err,
		}
	case errors.Is(err, ErrSessionExpired), errors.Is(err, ErrSessionRevoked), errors.Is(err, ErrInvalidSession):
		return &AdmissionError{
			StatusCode: 403,
			Code:       "SESSION_INVALID",
			Message:    "Session invalid or expired. Admission required.",
			Err:        err,
		}
	case errors.Is(err, ErrChallengeExpired), errors.Is(err, ErrChallengeNotFound), errors.Is(err, ErrChallengeFailed), errors.Is(err, ErrMaxAttemptsExceeded):
		return &AdmissionError{
			StatusCode: 403,
			Code:       "CHALLENGE_FAILED",
			Message:    "Challenge verification failed.",
			Err:        err,
		}
	case errors.Is(err, ErrCapacityExceeded), errors.Is(err, ErrStoreUnavailable), errors.Is(err, ErrLockUnavailable), errors.Is(err, ErrStoreClosed), errors.Is(err, ErrCircuitOpen):
		return &AdmissionError{
			StatusCode: 503,
			Code:       "SERVICE_UNAVAILABLE",
			Message:    "Service temporarily unavailable. Please retry later.",
			Err:        err,
		}
	case errors.Is(err, ErrInvalidTransition):
		return &AdmissionError{
			StatusCode: 400,
			Code:       "INVALID_TRANSITION",
			Message:    "Invalid admission transition request.",
			Err:        err,
		}
	default:
		return &AdmissionError{
			StatusCode: 500,
			Code:       "INTERNAL_ERROR",
			Message:    "An unexpected error occurred.",
			Err:        err,
		}
	}
}

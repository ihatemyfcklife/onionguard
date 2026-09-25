package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	og "github.com/ihatemyfcklife/onionguard"
)

type Option func(*options)
type options struct{ Cost int64 }

func WithCost(cost int64) Option {
	return func(o *options) {
		if cost > 0 {
			o.Cost = cost
		}
	}
}

func Middleware(engine *og.Engine, opts ...Option) func(http.Handler) http.Handler {
	cfg := og.DefaultConfig()
	if engine != nil {
		cfg = engine.Config()
	}
	o := options{}
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if engine == nil {
				writeJSONError(w, 500, "INTERNAL_ERROR", "Engine unavailable.", 0)
				return
			}
			if cfg.MaxBodyBytes > 0 {
				if r.ContentLength > cfg.MaxBodyBytes {
					secureHeaders(w, cfg)
					writeJSONError(w, 413, "PAYLOAD_TOO_LARGE", "Request entity too large.", 0)
					return
				}
				r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)
			}
			secureHeaders(w, cfg)

			if r.URL != nil && r.URL.Path == cfg.Captcha.EndpointPath {
				handleChallengeHTTP(engine, cfg, w, r, o)
				return
			}

			decision, err := engine.AuthorizeRequestWithCost(r.Context(), r, o.Cost)
			if err != nil {
				retryAfter := decision.Admission.RetryAfter
				if retryAfter <= 0 && decision.RateLimit.RetryAfter > 0 {
					retryAfter = decision.RateLimit.RetryAfter
				}
				writeMappedError(w, r, cfg, err, retryAfter)
				return
			}
			if c := engine.SessionCookie(decision.Session); c != nil && decision.Identity.Kind >= og.IdentityAnonymous {
				http.SetCookie(w, c)
			}
			ctx := og.WithClientIdentity(r.Context(), decision.Identity)
			if decision.Session != nil {
				ctx = og.WithSession(ctx, decision.Session)
			}
			r = r.WithContext(ctx)
			if !decision.Admission.Allowed {
				switch decision.Admission.State {
				case og.StateWaiting:
					if acceptsHTML(r) {
						body := og.RenderWaitRoomHTML(decision.Admission.RetryAfter)
						if cfg.CustomWaitRoomHTML != nil {
							body = cfg.CustomWaitRoomHTML(r, decision.Admission.RetryAfter)
						}
						renderCustomHTML(w, http.StatusTooManyRequests, decision.Admission.RetryAfter, body)
						return
					}
					writeJSONError(w, 429, "WAIT_ROOM", "Proof of patience in progress. Please wait.", decision.Admission.RetryAfter)
				case og.StateChallengeRequired:
					if cfg.CustomChallengeHTML != nil && acceptsHTML(r) {
						writeChallengeResponse(w, r, decision.Challenge, cfg)
						return
					}
					writeChallengeResponse(w, r, decision.Challenge, cfg)
				case og.StateExpired, og.StateRevoked:
					if cfg.CustomErrorHTML != nil && acceptsHTML(r) {
						adm := og.ClientSafeError(og.ErrSessionExpired)
						renderCustomHTML(w, adm.StatusCode, 0, cfg.CustomErrorHTML(r, adm))
						return
					}
					writeJSONError(w, 403, "SESSION_INVALID", "Session invalid or expired. Admission required.", 0)
				default:
					writeJSONError(w, 403, "ADMISSION_REQUIRED", "Admission required.", 0)
				}
				return
			}
			if next != nil {
				next.ServeHTTP(w, r)
			}
		})
	}
}

func secureHeaders(w http.ResponseWriter, cfg og.Config) {
	og.ApplySecurityHeaders(w.Header(), cfg.SecurityHeaders)
}

func handleChallengeHTTP(engine *og.Engine, cfg og.Config, w http.ResponseWriter, r *http.Request, o options) {
	cookie, err := r.Cookie(cfg.SessionCookieName)
	if err != nil || cookie.Value == "" {
		writeJSONError(w, 403, "CHALLENGE_REQUIRED", "A valid session is required.", 0)
		return
	}
	id := strings.TrimSpace(cookie.Value)
	if err := og.ValidateSessionID(id); err != nil {
		writeJSONError(w, 403, "CHALLENGE_REQUIRED", "A valid session is required.", 0)
		return
	}
	ci := og.ClientIdentity{Kind: og.IdentityAnonymousNew, SessionID: id, PrincipalID: id}
	if decision, err := engine.AllowRateLimit(r.Context(), ci, "challenge:"+r.Method, 0); err != nil {
		writeMappedError(w, r, cfg, err, decision.RetryAfter)
		return
	}
	target := "/"
	if r != nil {
		if r.Method == http.MethodGet && r.URL != nil {
			target = sanitizeRedirectTarget(r.URL.Query().Get("target"))
		} else {
			target = sanitizeRedirectTarget(r.FormValue("target"))
		}
	}
	sess, sessErr := og.GetSession(r.Context(), engine.Store(), id)
	if sessErr == nil && sess != nil {
		now := time.Now()
		if cfg.Clock != nil {
			now = cfg.Clock.Now()
		}
		if sess.State == og.StateAdmitted && !sess.IsExpired(now) && !sess.IsRevoked() {
			if acceptsHTML(r) {
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"admitted": true, "message": "Session is already admitted.", "target": target})
			return
		}
	}
	if r.Method == http.MethodGet {
		ch, err := engine.IssueChallenge(r.Context(), id)
		if err != nil {
			writeMappedError(w, r, cfg, err, 0)
			return
		}
		og.ApplyNoStore(w.Header())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if cfg.CustomChallengeHTML != nil && acceptsHTML(r) {
			_, _ = io.WriteString(w, cfg.CustomChallengeHTML(r, ch, cfg.Captcha))
		} else {
			_, _ = io.WriteString(w, og.RenderCaptchaHTMLWithTarget(ch, cfg.Captcha, target))
		}
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeJSONError(w, 405, "METHOD_NOT_ALLOWED", "Method not allowed.", 0)
		return
	}
	if err := r.ParseForm(); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeJSONError(w, 413, "PAYLOAD_TOO_LARGE", "Request entity too large.", 0)
			return
		}
		writeJSONError(w, 400, "INVALID_INPUT", "Invalid request body.", 0)
		return
	}
	answer := r.FormValue("answer")
	if len(answer) > cfg.MaxCookieValueBytes {
		writeJSONError(w, 400, "INVALID_INPUT", "Invalid challenge response.", 0)
		return
	}
	if err := engine.ValidateChallenge(r.Context(), id, answer); err != nil {
		if acceptsHTML(r) {
			if errors.Is(err, og.ErrMaxAttemptsExceeded) {
				if cfg.WaitRoom.Enabled {
					body := og.RenderWaitRoomHTML(cfg.WaitRoom.WaitTime)
					if cfg.CustomWaitRoomHTML != nil {
						body = cfg.CustomWaitRoomHTML(r, cfg.WaitRoom.WaitTime)
					}
					renderCustomHTML(w, http.StatusTooManyRequests, cfg.WaitRoom.WaitTime, body)
					return
				}
				writeMappedError(w, r, cfg, err, 0)
				return
			}
			if errors.Is(err, og.ErrChallengeFailed) || errors.Is(err, og.ErrChallengeInvalid) || errors.Is(err, og.ErrChallengeExpired) || errors.Is(err, og.ErrChallengeNotFound) {
				og.ApplyNoStore(w.Header())
				ch, issueErr := engine.IssueChallenge(r.Context(), id)
				if issueErr == nil && ch != nil {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusForbidden)
					if cfg.CustomChallengeHTML != nil {
						_, _ = io.WriteString(w, cfg.CustomChallengeHTML(r, ch, cfg.Captcha))
					} else {
						_, _ = io.WriteString(w, og.RenderCaptchaHTMLWithTarget(ch, cfg.Captcha, target))
					}
					return
				}
			}
		}
		writeMappedError(w, r, cfg, err, 0)
		return
	}
	og.ApplyNoStore(w.Header())
	if acceptsHTML(r) {
		renderCustomHTML(w, http.StatusOK, 0, fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="1;url=%s"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"><title>Admitted</title><style>body{background:#f8f9fa;color:#212529;font-family:system-ui,-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.box{border:1px solid #dee2e6;background:#fff;padding:2rem;border-radius:6px;text-align:center;box-shadow:0 2px 4px rgba(0,0,0,0.05);max-width:360px}h1{font-size:1.25rem;margin:0 0 .5rem}p{margin:0;color:#28a745}</style></head><body><main class="box"><h1>Verification Successful</h1><p>Admission granted. Redirecting...</p></main></body></html>`, html.EscapeString(target)))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"admitted": true, "target": target})
}

func writeChallengeResponse(w http.ResponseWriter, r *http.Request, ch *og.CaptchaChallenge, cfg og.Config) {
	og.ApplyNoStore(w.Header())
	if ch == nil {
		writeJSONError(w, 403, "CHALLENGE_REQUIRED", "Challenge required.", 0)
		return
	}
	target := "/"
	if r != nil {
		if r.URL != nil && r.URL.Path != cfg.Captcha.EndpointPath {
			target = sanitizeRedirectTarget(r.RequestURI)
		} else {
			target = sanitizeRedirectTarget(r.FormValue("target"))
		}
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") && !acceptsHTML(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":          "CHALLENGE_REQUIRED",
			"challenge_id":   ch.ID,
			"image_data_uri": ch.ImageDataURI,
			"endpoint":       cfg.Captcha.EndpointPath,
			"expires_at":     ch.ExpiresAt,
			"target":         target,
		})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	if cfg.CustomChallengeHTML != nil && acceptsHTML(r) {
		_, _ = io.WriteString(w, cfg.CustomChallengeHTML(r, ch, cfg.Captcha))
	} else {
		_, _ = io.WriteString(w, og.RenderCaptchaHTMLWithTarget(ch, cfg.Captcha, target))
	}
}

func writeMappedError(w http.ResponseWriter, r *http.Request, cfg og.Config, err error, retryAfter time.Duration) {
	adm := og.ClientSafeError(err)
	if adm == nil {
		return
	}
	if retryAfter <= 0 {
		retryAfter = adm.RetryAfter
	}
	if retryAfter > 0 {
		seconds := int(retryAfter.Seconds())
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	}
	if cfg.CustomErrorHTML != nil && acceptsHTML(r) {
		renderCustomHTML(w, adm.StatusCode, retryAfter, cfg.CustomErrorHTML(r, adm))
		return
	}
	writeJSONError(w, adm.StatusCode, adm.Code, adm.Message, retryAfter)
}

func writeJSONError(w http.ResponseWriter, status int, code, msg string, retryAfter time.Duration) {
	og.ApplyNoStore(w.Header())
	w.Header().Set("Content-Type", "application/json")
	if retryAfter > 0 {
		seconds := int(retryAfter.Seconds())
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": code, "message": msg})
}

// acceptsHTML returns true if the client's Accept header includes text/html.
func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// renderCustomHTML writes a custom HTML body with appropriate security headers.
func renderCustomHTML(w http.ResponseWriter, status int, retryAfter time.Duration, body string) {
	og.ApplyNoStore(w.Header())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if retryAfter > 0 {
		sec := int(retryAfter.Seconds())
		if sec < 1 {
			sec = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(sec))
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func sanitizeRedirectTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	// Must be an absolute path starting with '/', but not protocol-relative ('//')
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "/"
	}
	// Disallow backslashes to prevent browser scheme confusion
	if strings.Contains(raw, "\\") {
		return "/"
	}
	// Disallow control characters / CRLF to prevent header injection or response splitting
	for i := 0; i < len(raw); i++ {
		if raw[i] < 32 || raw[i] == 127 {
			return "/"
		}
	}
	return raw
}

package fiber

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
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

// Aliases for compatibility
type FiberOption = Option

var FiberWithCost = WithCost
var FiberMiddleware = Middleware

func Middleware(engine *og.Engine, opts ...Option) fiber.Handler {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return func(c *fiber.Ctx) error {
		if engine == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "INTERNAL_ERROR", "message": "Engine unavailable."})
		}
		cfg := engine.Config()
		applyFiberSecurityHeaders(c, cfg.SecurityHeaders)
		if cfg.MaxBodyBytes > 0 {
			if cl := int64(c.Request().Header.ContentLength()); cl > cfg.MaxBodyBytes {
				return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{"error": "PAYLOAD_TOO_LARGE", "message": "Request entity too large."})
			}
			if int64(len(c.Body())) > cfg.MaxBodyBytes {
				return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{"error": "PAYLOAD_TOO_LARGE", "message": "Request entity too large."})
			}
		}
		ctx := c.UserContext()
		if ctx == nil {
			ctx = c.Context()
		}
		// Copy request metadata into a short-lived net/http request so the same identity resolver
		// semantics are used without retaining any Fiber-owned byte slices beyond this call.
		r, err := http.NewRequestWithContext(ctx, c.Method(), c.OriginalURL(), nil)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "BAD_REQUEST", "message": "Malformed request URL."})
		}
		c.Request().Header.VisitAll(func(k, v []byte) { r.Header.Add(string(k), string(v)) })

		// Challenge endpoint is handled separately to prevent method-based admission bypass.
		if c.Path() == cfg.Captcha.EndpointPath {
			cookieVal := strings.TrimSpace(c.Cookies(cfg.SessionCookieName))
			if cookieVal == "" || og.ValidateSessionID(cookieVal) != nil {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "CHALLENGE_REQUIRED", "message": "A valid session is required."})
			}
			ci := og.ClientIdentity{Kind: og.IdentityAnonymousNew, SessionID: cookieVal, PrincipalID: cookieVal}
			rl, err := engine.AllowRateLimit(ctx, ci, "challenge:"+c.Method(), 0)
			if err != nil {
				return writeFiberMappedError(c, r, cfg, err, rl.RetryAfter)
			}
			target := "/"
			if c.Method() == http.MethodGet {
				target = sanitizeRedirectTarget(c.Query("target"))
			} else {
				target = sanitizeRedirectTarget(string(c.FormValue("target")))
			}
			sess, sessErr := og.GetSession(ctx, engine.Store(), cookieVal)
			if sessErr == nil && sess != nil {
				now := time.Now()
				if cfg.Clock != nil {
					now = cfg.Clock.Now()
				}
				if sess.State == og.StateAdmitted && !sess.IsExpired(now) && !sess.IsRevoked() {
					if fiberAcceptsHTML(c) {
						return c.Redirect(target, fiber.StatusFound)
					}
					return c.JSON(fiber.Map{"admitted": true, "message": "Session is already admitted.", "target": target})
				}
			}
			if c.Method() == http.MethodGet {
				ch, err := engine.IssueChallenge(ctx, cookieVal)
				if err != nil {
					return writeFiberMappedError(c, r, cfg, err, 0)
				}
				c.Set("Cache-Control", "no-store")
				c.Set("Pragma", "no-cache")
				c.Type("html", "utf-8")
				if cfg.CustomChallengeHTML != nil && fiberAcceptsHTML(c) {
					return c.SendString(cfg.CustomChallengeHTML(r, ch, cfg.Captcha))
				}
				return c.SendString(og.RenderCaptchaHTMLWithTarget(ch, cfg.Captcha, target))
			}
			if c.Method() != http.MethodPost {
				c.Set(fiber.HeaderAllow, "GET, POST")
				return c.Status(fiber.StatusMethodNotAllowed).JSON(fiber.Map{"error": "METHOD_NOT_ALLOWED", "message": "Method not allowed."})
			}
			answer := string(c.FormValue("answer"))
			if len(answer) > cfg.MaxCookieValueBytes {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "INVALID_INPUT", "message": "Invalid challenge response."})
			}
			if err := engine.ValidateChallenge(ctx, cookieVal, answer); err != nil {
				if fiberAcceptsHTML(c) {
					if errors.Is(err, og.ErrMaxAttemptsExceeded) {
						if cfg.WaitRoom.Enabled {
							body := og.RenderWaitRoomHTML(cfg.WaitRoom.WaitTime)
							if cfg.CustomWaitRoomHTML != nil {
								body = cfg.CustomWaitRoomHTML(r, cfg.WaitRoom.WaitTime)
							}
							return renderFiberCustomHTML(c, fiber.StatusTooManyRequests, cfg.WaitRoom.WaitTime, body)
						}
						return writeFiberMappedError(c, r, cfg, err, 0)
					}
					if errors.Is(err, og.ErrChallengeFailed) || errors.Is(err, og.ErrChallengeInvalid) || errors.Is(err, og.ErrChallengeExpired) || errors.Is(err, og.ErrChallengeNotFound) {
						c.Set("Cache-Control", "no-store")
						c.Set("Pragma", "no-cache")
						ch, issueErr := engine.IssueChallenge(ctx, cookieVal)
						if issueErr == nil && ch != nil {
							c.Type("html", "utf-8")
							if cfg.CustomChallengeHTML != nil {
								return c.Status(fiber.StatusForbidden).SendString(cfg.CustomChallengeHTML(r, ch, cfg.Captcha))
							}
							return c.Status(fiber.StatusForbidden).SendString(og.RenderCaptchaHTMLWithTarget(ch, cfg.Captcha, target))
						}
					}
				}
				return writeFiberMappedError(c, r, cfg, err, 0)
			}
			c.Set("Cache-Control", "no-store")
			c.Set("Pragma", "no-cache")
			if fiberAcceptsHTML(c) {
				return renderFiberCustomHTML(c, fiber.StatusOK, 0, fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="1;url=%s"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"><title>Admitted</title><style>body{background:#f8f9fa;color:#212529;font-family:system-ui,-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.box{border:1px solid #dee2e6;background:#fff;padding:2rem;border-radius:6px;text-align:center;box-shadow:0 2px 4px rgba(0,0,0,0.05);max-width:360px}h1{font-size:1.25rem;margin:0 0 .5rem}p{margin:0;color:#28a745}</style></head><body><main class="box"><h1>Verification Successful</h1><p>Admission granted. Redirecting...</p></main></body></html>`, html.EscapeString(target)))
			}
			return c.JSON(fiber.Map{"admitted": true, "target": target})
		}
		decision, err := engine.AuthorizeRequestWithCost(ctx, r, o.Cost)
		if err != nil {
			retryAfter := decision.Admission.RetryAfter
			if retryAfter <= 0 && decision.RateLimit.RetryAfter > 0 {
				retryAfter = decision.RateLimit.RetryAfter
			}
			return writeFiberMappedError(c, r, cfg, err, retryAfter)
		}
		if ck := engine.SessionCookie(decision.Session); ck != nil && decision.Identity.Kind >= og.IdentityAnonymous {
			c.Cookie(&fiber.Cookie{Name: ck.Name, Value: ck.Value, Path: ck.Path, Domain: ck.Domain, HTTPOnly: ck.HttpOnly, Secure: ck.Secure, SameSite: cookieSameSiteString(ck.SameSite), MaxAge: ck.MaxAge, Expires: ck.Expires})
		}
		if !decision.Admission.Allowed {
			switch decision.Admission.State {
			case og.StateWaiting:
				if fiberAcceptsHTML(c) {
					body := og.RenderWaitRoomHTML(decision.Admission.RetryAfter)
					if cfg.CustomWaitRoomHTML != nil {
						body = cfg.CustomWaitRoomHTML(r, decision.Admission.RetryAfter)
					}
					return renderFiberCustomHTML(c, fiber.StatusTooManyRequests, decision.Admission.RetryAfter, body)
				}
				if decision.Admission.RetryAfter > 0 {
					sec := int(decision.Admission.RetryAfter.Seconds())
					if sec < 1 {
						sec = 1
					}
					c.Set(fiber.HeaderRetryAfter, strconv.Itoa(sec))
				}
				return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "WAIT_ROOM", "message": "Proof of patience in progress. Please wait."})
			case og.StateChallengeRequired:
				c.Set("Cache-Control", "no-store")
				c.Set("Pragma", "no-cache")
				target := sanitizeRedirectTarget(c.OriginalURL())
				if strings.Contains(c.Get("Accept"), "application/json") && !fiberAcceptsHTML(c) {
					return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
						"error":          "CHALLENGE_REQUIRED",
						"challenge_id":   decision.Challenge.ID,
						"image_data_uri": decision.Challenge.ImageDataURI,
						"endpoint":       cfg.Captcha.EndpointPath,
						"expires_at":     decision.Challenge.ExpiresAt,
						"target":         target,
					})
				}
				c.Type("html", "utf-8")
				if cfg.CustomChallengeHTML != nil && fiberAcceptsHTML(c) {
					return c.Status(fiber.StatusForbidden).SendString(cfg.CustomChallengeHTML(r, decision.Challenge, cfg.Captcha))
				}
				return c.Status(fiber.StatusForbidden).SendString(og.RenderCaptchaHTMLWithTarget(decision.Challenge, cfg.Captcha, target))
			case og.StateExpired, og.StateRevoked:
				if cfg.CustomErrorHTML != nil && fiberAcceptsHTML(c) {
					adm := og.ClientSafeError(og.ErrSessionExpired)
					return renderFiberCustomHTML(c, adm.StatusCode, 0, cfg.CustomErrorHTML(r, adm))
				}
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "SESSION_INVALID", "message": "Session invalid or expired. Admission required."})
			default:
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "ADMISSION_REQUIRED", "message": "Admission required."})
			}
		}
		ctx = og.WithClientIdentity(ctx, decision.Identity)
		if decision.Session != nil {
			ctx = og.WithSession(ctx, decision.Session)
		}
		c.SetUserContext(ctx)
		return c.Next()
	}
}

func writeFiberMappedError(c *fiber.Ctx, r *http.Request, cfg og.Config, err error, retry time.Duration) error {
	c.Set("Cache-Control", "no-store")
	c.Set("Pragma", "no-cache")
	adm := og.ClientSafeError(err)
	if adm == nil {
		return nil
	}
	if retry <= 0 {
		retry = adm.RetryAfter
	}
	if retry > 0 {
		sec := int(retry.Seconds())
		if sec < 1 {
			sec = 1
		}
		c.Set(fiber.HeaderRetryAfter, strconv.Itoa(sec))
	}
	if cfg.CustomErrorHTML != nil && fiberAcceptsHTML(c) {
		return renderFiberCustomHTML(c, adm.StatusCode, retry, cfg.CustomErrorHTML(r, adm))
	}
	return c.Status(adm.StatusCode).JSON(fiber.Map{"error": adm.Code, "message": adm.Message})
}

func fiberAcceptsHTML(c *fiber.Ctx) bool {
	return strings.Contains(c.Get("Accept"), "text/html")
}

func renderFiberCustomHTML(c *fiber.Ctx, status int, retryAfter time.Duration, body string) error {
	c.Set("Cache-Control", "no-store")
	c.Set("Pragma", "no-cache")
	c.Type("html", "utf-8")
	if retryAfter > 0 {
		sec := int(retryAfter.Seconds())
		if sec < 1 {
			sec = 1
		}
		c.Set(fiber.HeaderRetryAfter, strconv.Itoa(sec))
	}
	return c.Status(status).SendString(body)
}

func cookieSameSiteString(v http.SameSite) string {
	switch v {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Lax"
	}
}

func applyFiberSecurityHeaders(c *fiber.Ctx, cfg og.SecurityHeadersConfig) {
	set := func(name, value string) {
		if value == "" {
			return
		}
		switch cfg.Policy {
		case og.HeaderOverride:
			c.Set(name, value)
		case og.HeaderMerge:
			if ex := c.Get(name); ex != "" && name == "Content-Security-Policy" && ex != value {
				c.Set(name, ex+"; "+value)
			} else if ex == "" {
				c.Set(name, value)
			}
		default:
			if c.Get(name) == "" {
				c.Set(name, value)
			}
		}
	}
	set("Content-Security-Policy", cfg.ContentSecurityPolicy)
	set("Referrer-Policy", cfg.ReferrerPolicy)
	set("X-Frame-Options", cfg.XFrameOptions)
	set("X-Content-Type-Options", cfg.XContentTypeOptions)
}

func shouldSetFiberSessionCookie(c *fiber.Ctx, cookieName string, ck *http.Cookie, state og.State) bool {
	if ck == nil {
		return false
	}
	if ck.MaxAge < 0 {
		return true
	}
	if state != og.StateAdmitted {
		return true
	}
	if c.Cookies(cookieName) != ck.Value {
		return true
	}
	return false
}

func sanitizeRedirectTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "/"
	}
	if strings.Contains(raw, "\\") {
		return "/"
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 32 || raw[i] == 127 {
			return "/"
		}
	}
	return raw
}

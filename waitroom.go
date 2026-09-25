package onionguard

import (
	"fmt"
	"time"
)

// WaitRemaining returns the server-side remaining proof-of-patience time.
// Negative clock movement is clamped to the configured wait time.
func WaitRemaining(firstSeen, now time.Time, wait time.Duration) time.Duration {
	if wait <= 0 {
		return 0
	}
	elapsed := now.Sub(firstSeen)
	if elapsed < 0 {
		return wait
	}
	if elapsed >= wait {
		return 0
	}
	return wait - elapsed
}

func WaitSatisfied(firstSeen, now time.Time, wait time.Duration) bool {
	return WaitRemaining(firstSeen, now, wait) == 0
}

// RenderWaitRoomHTML returns a clean, zero-JavaScript HTML page that auto-refreshes
// using a standard meta refresh tag when the wait room proof-of-patience expires.
func RenderWaitRoomHTML(retryAfter time.Duration) string {
	sec := int(retryAfter.Seconds())
	if sec < 1 {
		sec = 1
	}
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="%d"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"><title>Please Wait</title><style>body{background:#f8f9fa;color:#212529;font-family:system-ui,-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.box{border:1px solid #dee2e6;background:#fff;padding:2rem;border-radius:6px;text-align:center;box-shadow:0 2px 4px rgba(0,0,0,0.05);max-width:360px}h1{font-size:1.25rem;margin:0 0 .5rem}p{margin:0;color:#6c757d}</style></head><body><main class="box"><h1>Queue Protection</h1><p>Please wait %d second(s) while your admission request is processed...</p></main></body></html>`, sec, sec)
}

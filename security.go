package onionguard

import (
	"net/http"
	"strings"
)

func applySecurityHeaders(h http.Header, cfg SecurityHeadersConfig) {
	set := func(name, value string) {
		if value == "" {
			return
		}
		switch cfg.Policy {
		case HeaderOverride:
			h.Set(name, value)
		case HeaderMerge:
			if existing := h.Get(name); existing != "" && name == "Content-Security-Policy" && existing != value {
				h.Set(name, existing+"; "+strings.TrimSpace(value))
			} else if existing == "" {
				h.Set(name, value)
			}
		default:
			if h.Get(name) == "" {
				h.Set(name, value)
			}
		}
	}
	set("Content-Security-Policy", cfg.ContentSecurityPolicy)
	set("Referrer-Policy", cfg.ReferrerPolicy)
	set("X-Frame-Options", cfg.XFrameOptions)
	set("X-Content-Type-Options", cfg.XContentTypeOptions)
}

func applyNoStore(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}

func ApplySecurityHeaders(h http.Header, cfg SecurityHeadersConfig) { applySecurityHeaders(h, cfg) }
func ApplyNoStore(h http.Header)                                    { applyNoStore(h) }

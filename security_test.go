package onionguard

import (
	"net/http/httptest"
	"testing"
)

func TestSecurityHeadersPreserveOverrideMerge(t *testing.T) {
	cfg := DefaultConfig()
	w := httptest.NewRecorder()
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	ApplySecurityHeaders(w.Header(), cfg.SecurityHeaders)
	if w.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Fatal("preserve failed")
	}
	cfg.SecurityHeaders.Policy = HeaderOverride
	ApplySecurityHeaders(w.Header(), cfg.SecurityHeaders)
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("override failed")
	}
}

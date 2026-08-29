package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/auth"
)

func TestOwnerUIAlwaysSetsAntiClickjackingHeaders(t *testing.T) {
	_, handler, _ := newZonesTestHandler(t)
	tests := []struct {
		name  string
		path  string
		owner bool
	}{
		{name: "owner page", path: "/accounts", owner: true},
		{name: "denied page", path: "/accounts"},
		{name: "missing page", path: "/not-found", owner: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.owner {
				req.Header.Set(auth.HeaderIsOwner, "true")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if got := response.Header().Get("Content-Security-Policy"); got != ownerContentSecurityPolicy {
				t.Errorf("Content-Security-Policy = %q, want %q", got, ownerContentSecurityPolicy)
			}
			if got := response.Header().Get("X-Frame-Options"); got != ownerFrameOptions {
				t.Errorf("X-Frame-Options = %q, want %q", got, ownerFrameOptions)
			}
		})
	}
}

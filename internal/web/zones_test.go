package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/auth"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsops"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
)

func newZonesTestHandler(t *testing.T) (*store.Store, http.Handler, int64) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	accountID, err := st.CreateAccount("test", "test-account", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceZones([]store.ZoneBinding{{Zone: "example.com", AccountID: accountID}}); err != nil {
		t.Fatal(err)
	}

	server, err := New(st, dnsops.New(st))
	if err != nil {
		t.Fatal(err)
	}
	return st, server.Handler(), accountID
}

func replaceZones(t *testing.T, handler http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/zones", strings.NewReader(body))
	req.Header.Set(auth.HeaderIsOwner, "true")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestZonesReplaceRejectsInvalidBodiesWithoutChangingZones(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "unknown field", body: `{"zones":[],"extra":true}`},
		{name: "missing zones", body: `{}`},
		{name: "null zones", body: `{"zones":null}`},
		{name: "trailing JSON", body: `{"zones":[]} {}`},
		{name: "malformed JSON", body: `{"zones":[}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, handler, accountID := newZonesTestHandler(t)
			rec := replaceZones(t, handler, tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}

			zones, err := st.Zones()
			if err != nil {
				t.Fatal(err)
			}
			if len(zones) != 1 || zones[0].Zone != "example.com" || zones[0].AccountID != accountID {
				t.Fatalf("rejected request changed zones: %+v", zones)
			}
		})
	}
}

func TestZonesReplaceAllowsExplicitEmptyList(t *testing.T) {
	st, handler, _ := newZonesTestHandler(t)
	rec := replaceZones(t, handler, `{"zones":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	zones, err := st.Zones()
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 0 {
		t.Fatalf("explicit empty zones list did not clear zones: %+v", zones)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"zones":[]}` {
		t.Fatalf("unexpected response body %s", got)
	}
}

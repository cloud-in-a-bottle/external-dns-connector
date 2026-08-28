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

func TestProviderSelectorShowsOnlyProductionProviders(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	server, err := New(st, dnsops.New(st))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/accounts?provider=mock", nil)
	req.Header.Set(auth.HeaderIsOwner, "true")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if got := strings.Count(body, `<option value="`); got != 2 {
		t.Fatalf("expected exactly two provider options, got %d: %s", got, body)
	}
	for _, key := range []string{"route53", "hetzner"} {
		if !strings.Contains(body, `<option value="`+key+`"`) {
			t.Errorf("provider selector is missing %q", key)
		}
	}
	if strings.Contains(body, `value="mock"`) {
		t.Error("mock provider appeared in the owner provider form")
	}
	if !strings.Contains(body, `<input type="hidden" name="provider" value="route53">`) {
		t.Error("provider=mock selected the hidden mock instead of the default production provider")
	}
}

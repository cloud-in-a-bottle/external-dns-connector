package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/auth"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsops"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsprov"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
)

func TestOwnerDeleteNoMatchIsAuditedAsFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	accountID, err := st.CreateAccount(dnsprov.MockKey, "test-mock", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateAccountCredentials(accountID, dnsprov.MockCredentials(accountID)); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceZones([]store.ZoneBinding{{Zone: "example.com", AccountID: accountID}}); err != nil {
		t.Fatal(err)
	}
	server, err := New(st, dnsops.New(st))
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"name": {"missing"},
		"type": {"TXT"},
		"ttl":  {"60"},
		"data": {"not-present"},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/zones/example.com/delete",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set(auth.HeaderIsOwner, "true")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	const noMatchError = "no matching record was found, so nothing was deleted"
	if response.Code != http.StatusSeeOther {
		t.Fatalf("delete returned %d, want %d", response.Code, http.StatusSeeOther)
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := location.Query().Get("err"); got != noMatchError {
		t.Fatalf("redirect error = %q, want %q", got, noMatchError)
	}

	entries, err := st.AuditEntries(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1: %+v", len(entries), entries)
	}
	entry := entries[0]
	if entry.Op != "delete" || entry.OK || entry.Error != noMatchError {
		t.Fatalf("no-op delete audit entry = %+v", entry)
	}
}

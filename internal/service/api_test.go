package service

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/auth"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsops"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsprov"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
)

const (
	zoneA = "example.com"
	zoneB = "other.org"
)

func newTestAPI(t *testing.T) http.Handler {
	t.Helper()
	handler, _ := newTestAPIWithStore(t)
	return handler
}

func newTestAPIWithStore(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	id, err := st.CreateAccount(dnsprov.MockKey, "test-mock", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateAccountCredentials(id, dnsprov.MockCredentials(id)); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceZones([]store.ZoneBinding{
		{Zone: zoneA, AccountID: id},
		{Zone: zoneB, AccountID: id},
	}); err != nil {
		t.Fatal(err)
	}
	return New(st, dnsops.New(st)).Handler(), st
}

// call issues a service request the way the router would: with a consumer identity and a
// pre-filtered permissions array.
func call(
	t *testing.T,
	h http.Handler,
	path string,
	body any,
	perms string,
) (int, resultsResponse, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	req.Header.Set(auth.HeaderConsumerID, "consumer-app-id")
	req.Header.Set(auth.HeaderConsumerName, "consumer-app")
	if perms != "" {
		req.Header.Set(auth.HeaderPermissions, perms)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var results resultsResponse
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &results)
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	return rec.Code, results, raw
}

func globalGrant(name, rrtype, access string) string {
	b, _ := json.Marshal([]map[string]any{{
		"grant": map[string]string{"name": name, "type": rrtype, "access": access},
		"scope": "global",
	}})
	return string(b)
}

const acmeGrant = `[{"grant":{"name":"_acme-challenge.**","type":"TXT","access":"rw"},"scope":"global"}]`

func TestWriteAndReadBackWithinGrant(t *testing.T) {
	h := newTestAPI(t)
	body := map[string]any{
		"zone":    zoneA,
		"records": []map[string]any{{"name": "_acme-challenge.www", "type": "TXT", "ttl": 60, "data": "token-1"}},
	}
	code, res, _ := call(t, h, "/records/set", body, acmeGrant)
	if code != http.StatusOK || !res.OK {
		t.Fatalf("set returned %d %+v", code, res)
	}

	code, res, _ = call(t, h, "/records/get", map[string]any{"zone": zoneA}, acmeGrant)
	if code != http.StatusOK {
		t.Fatalf("get returned %d", code)
	}
	if len(res.Results) != 1 || len(res.Results[0].Records) != 1 {
		t.Fatalf("expected exactly the one written record, got %+v", res.Results)
	}
	if got := res.Results[0].Records[0]; got.Data != "token-1" || got.Name != "_acme-challenge.www" {
		t.Errorf("read back %+v", got)
	}
}

func TestWriteOutsideGrantIsRefused(t *testing.T) {
	h := newTestAPI(t)
	body := map[string]any{
		"zone":    zoneA,
		"records": []map[string]any{{"name": "home", "type": "A", "ttl": 300, "data": "192.0.2.1"}},
	}
	code, _, raw := call(t, h, "/records/set", body, acmeGrant)
	if code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%v)", code, raw)
	}
	if raw["error"] != "permission_required" {
		t.Errorf("expected the router-understood permission_required shape, got %v", raw)
	}
	rg, ok := raw["required_grant"].(map[string]any)
	if !ok || rg["scope"] != "global" {
		t.Errorf("required_grant should be global-scoped so the router can attach a grant_url, got %v", raw)
	}
}

// A partially-permitted batch must not apply its permitted half.
func TestPartiallyPermittedBatchWritesNothing(t *testing.T) {
	h := newTestAPI(t)
	perms := globalGrant("**", "TXT", "rw")
	body := map[string]any{
		"zone": zoneA,
		"records": []map[string]any{
			{"name": "allowed", "type": "TXT", "ttl": 60, "data": "yes"},
			{"name": "denied", "type": "A", "ttl": 60, "data": "192.0.2.1"},
		},
	}
	if code, _, _ := call(t, h, "/records/set", body, perms); code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", code)
	}
	_, res, _ := call(t, h, "/records/get", map[string]any{"zone": zoneA}, perms)
	for _, zr := range res.Results {
		if len(zr.Records) != 0 {
			t.Errorf("the permitted half of a refused batch was applied: %+v", zr.Records)
		}
	}
}

func TestReadsAreFilteredToGrantedRecords(t *testing.T) {
	h := newTestAPI(t)
	writeAll := globalGrant("**", "**", "rw")
	seed := map[string]any{
		"zone": zoneA,
		"records": []map[string]any{
			{"name": "_acme-challenge.a", "type": "TXT", "ttl": 60, "data": "mine"},
			{"name": "home", "type": "A", "ttl": 60, "data": "192.0.2.1"},
			{"name": "@", "type": "MX", "ttl": 60, "data": "10 mail.example.net."},
		},
	}
	if code, _, raw := call(t, h, "/records/set", seed, writeAll); code != http.StatusOK {
		t.Fatalf("seed failed: %d %v", code, raw)
	}

	_, res, _ := call(t, h, "/records/get", map[string]any{"zone": zoneA}, acmeGrant)
	if len(res.Results) != 1 {
		t.Fatalf("got %d zone results", len(res.Results))
	}
	got := res.Results[0].Records
	if len(got) != 1 || got[0].Data != "mine" {
		t.Errorf("a narrowly-granted app should see only its own records, got %+v", got)
	}
}

func TestRecordReadsDoNotCreateAuditRows(t *testing.T) {
	h, st := newTestAPIWithStore(t)
	perms := globalGrant("**", "TXT", "rw")

	for i := 0; i < 3; i++ {
		if code, _, _ := call(t, h, "/records/get", map[string]any{"zone": zoneA}, perms); code != http.StatusOK {
			t.Fatalf("read %d returned %d", i+1, code)
		}
	}
	entries, err := st.AuditEntries(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("repeated reads created audit rows: %+v", entries)
	}

	mutation := map[string]any{
		"zone": zoneA,
		"records": []map[string]any{
			{"name": "audited", "type": "TXT", "ttl": 60, "data": "value"},
		},
	}
	if code, _, raw := call(t, h, "/records/set", mutation, perms); code != http.StatusOK {
		t.Fatalf("mutation returned %d: %v", code, raw)
	}
	entries, err = st.AuditEntries(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Op != "set" {
		t.Fatalf("mutation should create one set audit row, got %+v", entries)
	}

	for i := 0; i < 3; i++ {
		call(t, h, "/records/get", map[string]any{"zone": zoneA}, perms)
	}
	entries, err = st.AuditEntries(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("reads after the mutation changed the audit row count: %+v", entries)
	}
}

func TestNoGrantsSeesNothingAndCannotListZones(t *testing.T) {
	h := newTestAPI(t)
	code, res, _ := call(t, h, "/records/get", map[string]any{"zone": zoneA}, "")
	if code != http.StatusOK {
		t.Fatalf("get returned %d", code)
	}
	for _, zr := range res.Results {
		if len(zr.Records) != 0 {
			t.Errorf("an app with no grants saw records: %+v", zr.Records)
		}
	}
	if code, _, _ := call(t, h, "/zones", nil, ""); code != http.StatusForbidden {
		t.Errorf("zone listing should need at least one grant, got %d", code)
	}
}

func TestZoneIsRequiredOnWrites(t *testing.T) {
	h := newTestAPI(t)
	body := map[string]any{
		"records": []map[string]any{{"name": "_acme-challenge.a", "type": "TXT", "ttl": 60, "data": "x"}},
	}
	code, _, raw := call(t, h, "/records/set", body, acmeGrant)
	if code != http.StatusBadRequest || raw["error"] != "zone_required" {
		t.Fatalf("expected 400 zone_required, got %d %v", code, raw)
	}
}

func TestUnknownZoneIsRejected(t *testing.T) {
	h := newTestAPI(t)
	body := map[string]any{
		"zone":    "not-configured.test",
		"records": []map[string]any{{"name": "_acme-challenge.a", "type": "TXT", "ttl": 60, "data": "x"}},
	}
	code, _, raw := call(t, h, "/records/set", body, acmeGrant)
	if code != http.StatusBadRequest || raw["error"] != "unknown_zone" {
		t.Fatalf("expected 400 unknown_zone, got %d %v", code, raw)
	}
}

func TestWildcardZoneFansOutToEveryZone(t *testing.T) {
	h := newTestAPI(t)
	body := map[string]any{
		"zone":    "*",
		"records": []map[string]any{{"name": "_acme-challenge.a", "type": "TXT", "ttl": 60, "data": "fanned"}},
	}
	code, res, _ := call(t, h, "/records/set", body, acmeGrant)
	if code != http.StatusOK || len(res.Results) != 2 {
		t.Fatalf("expected both zones written, got %d %+v", code, res.Results)
	}
	seen := map[string]bool{}
	for _, zr := range res.Results {
		if !zr.OK {
			t.Errorf("zone %s failed: %s", zr.Zone, zr.Error)
		}
		seen[zr.Zone] = true
	}
	if !seen[zoneA] || !seen[zoneB] {
		t.Errorf("fan-out missed a zone: %v", seen)
	}
}

func TestSetReplacesTheRRsetAndAppendAddsToIt(t *testing.T) {
	h := newTestAPI(t)
	perms := globalGrant("**", "TXT", "rw")
	rec := func(data string) map[string]any {
		return map[string]any{"name": "multi", "type": "TXT", "ttl": 60, "data": data}
	}

	call(t, h, "/records/set", map[string]any{"zone": zoneA, "records": []map[string]any{rec("one")}}, perms)
	call(t, h, "/records/append", map[string]any{"zone": zoneA, "records": []map[string]any{rec("two")}}, perms)
	_, res, _ := call(t, h, "/records/get", map[string]any{"zone": zoneA, "name": "multi"}, perms)
	if len(res.Results[0].Records) != 2 {
		t.Fatalf("append should have left both records, got %+v", res.Results[0].Records)
	}

	// SetRecords has RRset semantics: the input becomes the whole RRset for that (name, type).
	call(t, h, "/records/set", map[string]any{"zone": zoneA, "records": []map[string]any{rec("three")}}, perms)
	_, res, _ = call(t, h, "/records/get", map[string]any{"zone": zoneA, "name": "multi"}, perms)
	if len(res.Results[0].Records) != 1 || res.Results[0].Records[0].Data != "three" {
		t.Errorf("set should have replaced the RRset, got %+v", res.Results[0].Records)
	}
}

func TestDeleteRemovesOnlyTheNamedRecord(t *testing.T) {
	h := newTestAPI(t)
	perms := globalGrant("**", "TXT", "rw")
	seed := map[string]any{"zone": zoneA, "records": []map[string]any{
		{"name": "keep", "type": "TXT", "ttl": 60, "data": "keep-me"},
		{"name": "drop", "type": "TXT", "ttl": 60, "data": "drop-me"},
	}}
	call(t, h, "/records/set", seed, perms)

	del := map[string]any{"zone": zoneA, "records": []map[string]any{
		{"name": "drop", "type": "TXT", "ttl": 60, "data": "drop-me"},
	}}
	if code, _, raw := call(t, h, "/records/delete", del, perms); code != http.StatusOK {
		t.Fatalf("delete returned %d %v", code, raw)
	}
	_, res, _ := call(t, h, "/records/get", map[string]any{"zone": zoneA}, perms)
	if len(res.Results[0].Records) != 1 || res.Results[0].Records[0].Name != "keep" {
		t.Errorf("delete affected the wrong records: %+v", res.Results[0].Records)
	}
}

func TestOwnerSessionCannotUseTheServiceAPI(t *testing.T) {
	h := newTestAPI(t)
	req := httptest.NewRequest(http.MethodPost, "/records/get", bytes.NewBufferString(`{}`))
	req.Header.Set(auth.HeaderIsOwner, "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("service routes act for a calling app and should reject a bare owner session, got %d", rec.Code)
	}
}

func TestDecodeRejectsTrailingJSON(t *testing.T) {
	h := newTestAPI(t)
	req := httptest.NewRequest(
		http.MethodPost,
		"/records/get",
		bytes.NewBufferString(`{"zone":"example.com"} {}`),
	)
	req.Header.Set(auth.HeaderConsumerID, "consumer-app-id")
	req.Header.Set(auth.HeaderPermissions, globalGrant("**", "**", "r"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || body.Error != "invalid_request" {
		t.Fatalf("expected 400 invalid_request, got %d %+v", rec.Code, body)
	}
}

func TestAppScopedGrantsAreIgnored(t *testing.T) {
	h := newTestAPI(t)
	appScoped := `[{"grant":{"name":"**","type":"**","access":"rw"},"scope":"app"}]`
	body := map[string]any{
		"zone":    zoneA,
		"records": []map[string]any{{"name": "home", "type": "A", "ttl": 60, "data": "192.0.2.1"}},
	}
	if code, _, _ := call(t, h, "/records/set", body, appScoped); code != http.StatusForbidden {
		t.Errorf("only global-scoped grants are honored; an app-scoped write-all was accepted (%d)", code)
	}
}

func TestUnwritableTypeIsRejectedEvenWithWriteAll(t *testing.T) {
	h := newTestAPI(t)
	body := map[string]any{
		"zone":    zoneA,
		"records": []map[string]any{{"name": "@", "type": "SOA", "ttl": 60, "data": "ns1. root. 1 2 3 4 5"}},
	}
	code, _, raw := call(t, h, "/records/set", body, globalGrant("**", "**", "rw"))
	if code != http.StatusBadRequest || raw["error"] != "invalid_record" {
		t.Errorf("expected the type allowlist to reject SOA, got %d %v", code, raw)
	}
}

// An A grant must not become an AAAA write. libdns derives A vs AAAA from the address family, so an
// unchecked IPv6 value in an "A" record would be written as AAAA — a type the caller has no grant for.
func TestARecordGrantCannotWriteAAAA(t *testing.T) {
	h := newTestAPI(t)
	body := map[string]any{
		"zone":    zoneA,
		"records": []map[string]any{{"name": "home", "type": "A", "ttl": 60, "data": "2001:db8::1"}},
	}
	code, _, raw := call(t, h, "/records/set", body, globalGrant("home", "A", "rw"))
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %v", code, raw)
	}
	_, res, _ := call(t, h, "/records/get", map[string]any{"zone": zoneA}, globalGrant("**", "**", "r"))
	for _, zr := range res.Results {
		if len(zr.Records) != 0 {
			t.Errorf("an AAAA record was written under an A-only grant: %+v", zr.Records)
		}
	}
}

// An app with no grants must not be able to probe the owner's configuration through error messages.
func TestUngrantedAppLearnsNothingAboutZones(t *testing.T) {
	h := newTestAPI(t)
	body := map[string]any{
		"zone":    "does-not-exist.test",
		"records": []map[string]any{{"name": "home", "type": "A", "ttl": 60, "data": "192.0.2.1"}},
	}
	code, _, raw := call(t, h, "/records/set", body, "")
	if code != http.StatusForbidden {
		t.Errorf("expected 403 before any zone lookup, got %d %v", code, raw)
	}
	if raw["error"] == "unknown_zone" {
		t.Error("the error revealed whether a zone exists to an app with no grants")
	}
}

// Clearing an RRset by omitting data is what a cleanup path needs: a run that crashed before it
// recorded the token it wrote cannot delete by exact value.
func TestDeleteWithoutDataClearsTheWholeRRset(t *testing.T) {
	h := newTestAPI(t)
	perms := globalGrant("**", "TXT", "rw")
	seed := map[string]any{"zone": zoneA, "records": []map[string]any{
		{"name": "_acme-challenge", "type": "TXT", "ttl": 60, "data": "token-one"},
		{"name": "_acme-challenge", "type": "TXT", "ttl": 60, "data": "token-two"},
		{"name": "keep", "type": "TXT", "ttl": 60, "data": "untouched"},
	}}
	if code, _, raw := call(t, h, "/records/append", seed, perms); code != http.StatusOK {
		t.Fatalf("seed failed: %d %v", code, raw)
	}

	clear := map[string]any{"zone": zoneA, "records": []map[string]any{
		{"name": "_acme-challenge", "type": "TXT"},
	}}
	code, res, raw := call(t, h, "/records/delete", clear, perms)
	if code != http.StatusOK {
		t.Fatalf("clear returned %d %v", code, raw)
	}
	if len(res.Results[0].Records) != 2 {
		t.Errorf("expected both tokens reported deleted, got %+v", res.Results[0].Records)
	}

	_, res, _ = call(t, h, "/records/get", map[string]any{"zone": zoneA}, perms)
	got := res.Results[0].Records
	if len(got) != 1 || got[0].Name != "keep" {
		t.Errorf("the clear should have removed only the _acme-challenge RRset, leaving %+v", got)
	}
}

func TestDeleteRejectsPresentBlankOrNullDataWithoutChangingRecords(t *testing.T) {
	tests := []struct {
		name string
		data any
	}{
		{name: "empty", data: ""},
		{name: "whitespace", data: " \t\n"},
		{name: "null", data: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestAPI(t)
			perms := globalGrant("**", "TXT", "rw")
			seed := map[string]any{"zone": zoneA, "records": []map[string]any{
				{"name": "keep", "type": "TXT", "ttl": 60, "data": "still-here"},
			}}
			if code, _, raw := call(t, h, "/records/set", seed, perms); code != http.StatusOK {
				t.Fatalf("seed returned %d: %v", code, raw)
			}

			request := map[string]any{"zone": zoneA, "records": []map[string]any{
				{"name": "keep", "type": "TXT", "ttl": 60, "data": tt.data},
			}}
			code, _, raw := call(t, h, "/records/delete", request, perms)
			if code != http.StatusBadRequest || raw["error"] != "invalid_record" {
				t.Fatalf("expected 400 invalid_record, got %d %v", code, raw)
			}

			_, results, _ := call(t, h, "/records/get", map[string]any{"zone": zoneA}, perms)
			if len(results.Results) != 1 || len(results.Results[0].Records) != 1 {
				t.Fatalf("rejected delete changed records: %+v", results.Results)
			}
			if got := results.Results[0].Records[0]; got.Name != "keep" || got.Data != "still-here" {
				t.Fatalf("rejected delete changed record to %+v", got)
			}
		})
	}
}

// The clear must respect the same grant check as any other write.
func TestClearingAnRRsetOutsideTheGrantIsRefused(t *testing.T) {
	h := newTestAPI(t)
	body := map[string]any{"zone": zoneA, "records": []map[string]any{
		{"name": "home", "type": "A"},
	}}
	code, _, raw := call(t, h, "/records/delete", body, acmeGrant)
	if code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d %v", code, raw)
	}
	if raw["error"] != "permission_required" {
		t.Errorf("got %v", raw)
	}
}

// Clearing a name that holds nothing is a no-op, not an error: a cleanup path runs unconditionally
// and should not have to know whether a previous run got as far as writing anything.
func TestClearingAnEmptyRRsetSucceeds(t *testing.T) {
	h := newTestAPI(t)
	body := map[string]any{"zone": zoneA, "records": []map[string]any{
		{"name": "_acme-challenge.never-written", "type": "TXT"},
	}}
	code, res, raw := call(t, h, "/records/delete", body, acmeGrant)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d %v", code, raw)
	}
	if len(res.Results[0].Records) != 0 {
		t.Errorf("nothing should have been deleted, got %+v", res.Results[0].Records)
	}
}

// Omitting data is a wildcard only when removing records; set and append require a nonblank string.
func TestSetAndAppendRequireNonblankData(t *testing.T) {
	tests := []struct {
		name    string
		include bool
		data    any
	}{
		{name: "omitted"},
		{name: "empty", include: true, data: ""},
		{name: "whitespace", include: true, data: " \t\n"},
		{name: "null", include: true, data: nil},
	}

	for _, path := range []string{"/records/set", "/records/append"} {
		for _, tt := range tests {
			t.Run(path+"/"+tt.name, func(t *testing.T) {
				h := newTestAPI(t)
				record := map[string]any{"name": "_acme-challenge.x", "type": "TXT"}
				if tt.include {
					record["data"] = tt.data
				}
				body := map[string]any{"zone": zoneA, "records": []map[string]any{record}}
				code, _, raw := call(t, h, path, body, acmeGrant)
				if code != http.StatusBadRequest || raw["error"] != "invalid_record" {
					t.Errorf("expected 400 invalid_record, got %d %v", code, raw)
				}
			})
		}
	}
}

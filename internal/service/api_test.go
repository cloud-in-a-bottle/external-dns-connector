package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/auth"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsops"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsprov"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/records"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
)

const (
	zoneA = "example.com"
	zoneB = "other.org"
)

type fakeRecordOperations struct {
	zones    []store.Zone
	getFn    func(context.Context, store.Zone) ([]libdns.Record, error)
	writeFn  func(context.Context, store.Zone, dnsops.WriteOp, []libdns.Record) ([]libdns.Record, error)
	deleteFn func(
		context.Context,
		store.Zone,
		[]libdns.Record,
		[]records.RRset,
	) ([]libdns.Record, error)
}

func (f *fakeRecordOperations) ResolveZones(string) ([]store.Zone, error) {
	return append([]store.Zone(nil), f.zones...), nil
}

func (f *fakeRecordOperations) Get(ctx context.Context, zone store.Zone) ([]libdns.Record, error) {
	if f.getFn == nil {
		return nil, errors.New("unexpected Get call")
	}
	return f.getFn(ctx, zone)
}

func (f *fakeRecordOperations) Write(
	ctx context.Context,
	zone store.Zone,
	op dnsops.WriteOp,
	records []libdns.Record,
) ([]libdns.Record, error) {
	if f.writeFn == nil {
		return nil, errors.New("unexpected Write call")
	}
	return f.writeFn(ctx, zone, op, records)
}

func (f *fakeRecordOperations) Delete(
	ctx context.Context,
	zone store.Zone,
	exact []libdns.Record,
	clears []records.RRset,
) ([]libdns.Record, error) {
	if f.deleteFn == nil {
		return nil, errors.New("unexpected Delete call")
	}
	return f.deleteFn(ctx, zone, exact, clears)
}

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

const acmeGrant = `[
  {"grant":{"name":"_acme-challenge","type":"TXT","access":"rw"},"scope":"global"},
  {"grant":{"name":"_acme-challenge.**","type":"TXT","access":"rw"},"scope":"global"}
]`

func TestWriteResultsStatuses(t *testing.T) {
	tests := []struct {
		name    string
		results []dnsops.ZoneResult
		status  int
		ok      bool
	}{
		{
			name: "all zones succeeded",
			results: []dnsops.ZoneResult{
				{Zone: zoneA, OK: true},
				{Zone: zoneB, OK: true},
			},
			status: http.StatusOK,
			ok:     true,
		},
		{
			name: "some zones succeeded",
			results: []dnsops.ZoneResult{
				{Zone: zoneA, OK: true},
				{Zone: zoneB, Error: "provider failed"},
			},
			status: http.StatusMultiStatus,
		},
		{
			name: "no zones succeeded",
			results: []dnsops.ZoneResult{
				{Zone: zoneA, Error: "provider failed"},
				{Zone: zoneB, Error: "provider failed"},
			},
			status: http.StatusBadGateway,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writeResults(recorder, tt.results)
			if recorder.Code != tt.status {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.status)
			}
			var response resultsResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.OK != tt.ok {
				t.Fatalf("ok = %v, want %v", response.OK, tt.ok)
			}
		})
	}
}

func TestFanOutZonesStartsInParallelAndBoundsConcurrency(t *testing.T) {
	zones := serviceTestZones(maxZoneWorkers + 3)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()

	started := make(chan string, len(zones))
	var mu sync.Mutex
	active := 0
	maxActive := 0
	done := make(chan []dnsops.ZoneResult, 1)
	go func() {
		done <- fanOutZones(t.Context(), zones, func(
			ctx context.Context,
			zone store.Zone,
		) ([]records.Wire, error) {
			mu.Lock()
			active++
			maxActive = max(maxActive, active)
			mu.Unlock()
			defer func() {
				mu.Lock()
				active--
				mu.Unlock()
			}()

			started <- zone.Zone
			select {
			case <-release:
				return []records.Wire{{Name: zone.Zone}}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
	}()

	for range maxZoneWorkers {
		receiveService(t, started)
	}
	select {
	case zone := <-started:
		t.Fatalf("zone %s started while all %d workers were blocked", zone, maxZoneWorkers)
	default:
	}

	releaseAll()
	results := receiveService(t, done)
	if got := maxZoneWorkers + len(started); got != len(zones) {
		t.Fatalf("started %d zones, want %d", got, len(zones))
	}
	mu.Lock()
	gotMaxActive := maxActive
	mu.Unlock()
	if gotMaxActive != maxZoneWorkers {
		t.Fatalf("maximum concurrency = %d, want %d", gotMaxActive, maxZoneWorkers)
	}
	for index, result := range results {
		if result.Zone != zones[index].Zone || !result.OK {
			t.Fatalf("result %d = %+v, want successful zone %s", index, result, zones[index].Zone)
		}
	}
}

func TestFanOutZonesPreservesResolvedOrder(t *testing.T) {
	zones := serviceTestZones(maxZoneWorkers)
	releases := make([]chan struct{}, len(zones))
	zoneIndexes := make(map[string]int, len(zones))
	for index, zone := range zones {
		releases[index] = make(chan struct{})
		zoneIndexes[zone.Zone] = index
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan int, len(zones))
	completed := make(chan int, len(zones))
	done := make(chan []dnsops.ZoneResult, 1)
	go func() {
		done <- fanOutZones(ctx, zones, func(ctx context.Context, zone store.Zone) ([]records.Wire, error) {
			index := zoneIndexes[zone.Zone]
			started <- index
			select {
			case <-releases[index]:
				completed <- index
				return []records.Wire{{Name: zone.Zone}}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
	}()

	for range zones {
		receiveService(t, started)
	}
	for index := len(zones) - 1; index >= 0; index-- {
		close(releases[index])
		if got := receiveService(t, completed); got != index {
			t.Fatalf("completion index = %d, want %d", got, index)
		}
	}

	results := receiveService(t, done)
	for index, result := range results {
		if result.Zone != zones[index].Zone || result.Records[0].Name != zones[index].Zone {
			t.Fatalf("result %d = %+v, want zone %s", index, result, zones[index].Zone)
		}
	}
}

func TestServiceFanOutSharesDeadlineAndFailsCanceledZones(t *testing.T) {
	zones := serviceTestZones(maxZoneWorkers + 1)
	started := make(chan time.Time, maxZoneWorkers)
	ops := &fakeRecordOperations{
		zones: zones,
		getFn: func(ctx context.Context, _ store.Zone) ([]libdns.Record, error) {
			deadline, ok := ctx.Deadline()
			if !ok {
				return nil, errors.New("zone read received no request deadline")
			}
			started <- deadline
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	api := newAPI(nil, ops)
	api.requestTimeout = time.Minute

	parent, cancel := context.WithCancel(t.Context())
	requestStarted := time.Now()
	request := serviceRequest(
		t,
		"/records/get",
		map[string]any{"zone": "*"},
		globalGrant("**", "**", "r"),
	).WithContext(parent)
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	handler := api.Handler()
	go func() {
		handler.ServeHTTP(recorder, request)
		close(done)
	}()

	deadlines := make([]time.Time, 0, maxZoneWorkers)
	for range maxZoneWorkers {
		deadlines = append(deadlines, receiveService(t, started))
	}
	for _, deadline := range deadlines[1:] {
		if !deadline.Equal(deadlines[0]) {
			t.Fatalf("zone deadlines differ: %s and %s", deadlines[0], deadline)
		}
	}
	if remaining := deadlines[0].Sub(requestStarted); remaining < 59*time.Second || remaining > 61*time.Second {
		t.Fatalf("injected request deadline is %s from request start, want about one minute", remaining)
	}
	cancel()
	receiveService(t, done)

	var response resultsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusBadGateway || len(response.Results) != len(zones) {
		t.Fatalf("canceled request returned %d %+v", recorder.Code, response)
	}
	for index, result := range response.Results {
		if result.Zone != zones[index].Zone || result.OK || result.Error != context.Canceled.Error() {
			t.Fatalf("result %d = %+v, want ordered cancellation failure", index, result)
		}
	}
	select {
	case deadline := <-started:
		t.Fatalf("queued zone started after cancellation with deadline %s", deadline)
	default:
	}
}

func TestServiceFanOutDeadlineExpires(t *testing.T) {
	zones := serviceTestZones(1)
	var observedDeadline time.Time
	ops := &fakeRecordOperations{
		zones: zones,
		getFn: func(ctx context.Context, _ store.Zone) ([]libdns.Record, error) {
			var ok bool
			observedDeadline, ok = ctx.Deadline()
			if !ok {
				return nil, errors.New("zone read received no request deadline")
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	api := newAPI(nil, ops)
	api.requestTimeout = 50 * time.Millisecond

	started := time.Now()
	code, response, _ := call(
		t,
		api.Handler(),
		"/records/get",
		map[string]any{"zone": "*"},
		globalGrant("**", "**", "r"),
	)
	elapsed := time.Since(started)
	if code != http.StatusBadGateway || len(response.Results) != 1 {
		t.Fatalf("expired request returned %d %+v", code, response)
	}
	if result := response.Results[0]; result.OK || result.Error != context.DeadlineExceeded.Error() {
		t.Fatalf("expired zone result = %+v", result)
	}
	if deadlineAfterStart := observedDeadline.Sub(started); deadlineAfterStart <= 0 ||
		deadlineAfterStart > api.requestTimeout+time.Second {
		t.Fatalf("observed request deadline after %s", deadlineAfterStart)
	}
	if elapsed > api.requestTimeout+time.Second {
		t.Fatalf("handler returned after %s with a %s deadline", elapsed, api.requestTimeout)
	}
}

func TestGetFanOutMixedResultsReturnsMultiStatus(t *testing.T) {
	zones := serviceTestZones(3)
	ops := &fakeRecordOperations{
		zones: zones,
		getFn: func(_ context.Context, zone store.Zone) ([]libdns.Record, error) {
			if zone.Zone == zones[1].Zone {
				return nil, errors.New("provider failed")
			}
			return []libdns.Record{libdns.RR{
				Name: "visible", Type: "TXT", TTL: time.Minute, Data: zone.Zone,
			}}, nil
		},
	}

	code, response, _ := call(
		t,
		newAPI(nil, ops).Handler(),
		"/records/get",
		map[string]any{"zone": "*"},
		globalGrant("**", "**", "r"),
	)
	if code != http.StatusMultiStatus || response.OK {
		t.Fatalf("mixed fan-out returned %d %+v", code, response)
	}
	for index, result := range response.Results {
		if result.Zone != zones[index].Zone {
			t.Fatalf("result %d zone = %s, want %s", index, result.Zone, zones[index].Zone)
		}
		if result.OK != (index != 1) {
			t.Fatalf("result %d success = %v", index, result.OK)
		}
	}
}

func TestGetRequiresBodyAndAcceptsEmptyObject(t *testing.T) {
	handler := newTestAPI(t)
	permissions := globalGrant("**", "**", "r")

	code, _, raw := call(t, handler, "/records/get", nil, permissions)
	if code != http.StatusBadRequest || raw["error"] != "invalid_request" {
		t.Fatalf("missing body returned %d %v, want 400 invalid_request", code, raw)
	}

	code, results, raw := call(t, handler, "/records/get", struct{}{}, permissions)
	if code != http.StatusOK || !results.OK {
		t.Fatalf("empty object returned %d %v, want 200 results", code, raw)
	}
}

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
	var detail []recordRequest
	if err := json.Unmarshal([]byte(entries[0].Detail), &detail); err != nil {
		t.Fatalf("decode audit detail: %v", err)
	}
	if len(detail) != 1 {
		t.Fatalf("audit detail = %+v, want one record", detail)
	}
	if ttl, err := detail[0].TTL.seconds(true); err != nil || ttl != 60 {
		t.Fatalf("audit detail TTL = %d, %v; want 60", ttl, err)
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

func TestNoGrantsSeesNoRecordsOrZones(t *testing.T) {
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
	code, _, raw := call(t, h, "/zones", nil, "")
	if code != http.StatusOK {
		t.Fatalf("zone listing returned %d, want 200", code)
	}
	zones, ok := raw["zones"].([]any)
	if !ok || len(zones) != 0 {
		t.Errorf("an app with no grants should receive an empty zone list, got %v", raw)
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

func TestFailedMultiRRsetWriteReportsEarlierAppliedRecords(t *testing.T) {
	handler, st := newTestAPIWithStore(t)
	if _, err := st.DB().Exec(`
		CREATE TRIGGER fail_second_rrset BEFORE INSERT ON mock_records
		WHEN NEW.name = 'b'
		BEGIN
			SELECT RAISE(FAIL, 'second RRset failed');
		END
	`); err != nil {
		t.Fatal(err)
	}

	body := map[string]any{
		"zone": zoneA,
		"records": []map[string]any{
			{"name": "b", "type": "TXT", "ttl": 60, "data": "fails"},
			{"name": "a", "type": "TXT", "ttl": 60, "data": "applied"},
		},
	}
	code, response, raw := call(t, handler, "/records/set", body, globalGrant("**", "TXT", "rw"))
	if code != http.StatusBadGateway || response.OK || len(response.Results) != 1 {
		t.Fatalf("failed multi-RRset write returned %d %+v (%v)", code, response, raw)
	}
	result := response.Results[0]
	if result.OK || !strings.Contains(result.Error, "set RRset b/TXT") {
		t.Fatalf("failed zone result = %+v", result)
	}
	if len(result.Records) != 1 || result.Records[0].Name != "a" || result.Records[0].Data != "applied" {
		t.Fatalf("partial applied records = %+v, want a/TXT applied", result.Records)
	}

	entries, err := st.AuditEntries(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].OK || entries[0].Error == "" {
		t.Fatalf("partial mutation audit entry = %+v, want one failed entry", entries)
	}

	_, readResponse, _ := call(
		t,
		handler,
		"/records/get",
		map[string]any{"zone": zoneA},
		globalGrant("**", "TXT", "r"),
	)
	if len(readResponse.Results) != 1 || len(readResponse.Results[0].Records) != 1 ||
		readResponse.Results[0].Records[0].Name != "a" {
		t.Fatalf("provider state after partial write = %+v", readResponse.Results)
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

func TestExactDeleteIgnoresOmittedOrDifferentTTL(t *testing.T) {
	tests := []struct {
		name       string
		includeTTL bool
		ttl        int64
	}{
		{name: "omitted"},
		{name: "different", includeTTL: true, ttl: records.MaxTTLSeconds},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestAPI(t)
			permissions := globalGrant("**", "TXT", "rw")
			seed := map[string]any{
				"zone": zoneA,
				"records": []map[string]any{{
					"name": "drop", "type": "TXT", "ttl": 60, "data": "drop-me",
				}},
			}
			if code, _, raw := call(t, h, "/records/set", seed, permissions); code != http.StatusOK {
				t.Fatalf("seed returned %d: %v", code, raw)
			}

			target := map[string]any{"name": "drop", "type": "TXT", "data": "drop-me"}
			if tt.includeTTL {
				target["ttl"] = tt.ttl
			}
			request := map[string]any{"zone": zoneA, "records": []map[string]any{target}}
			if code, _, raw := call(t, h, "/records/delete", request, permissions); code != http.StatusOK {
				t.Fatalf("delete returned %d: %v", code, raw)
			}

			_, results, _ := call(t, h, "/records/get", map[string]any{"zone": zoneA}, permissions)
			if len(results.Results) != 1 || len(results.Results[0].Records) != 0 {
				t.Fatalf("delete left records behind: %+v", results.Results)
			}
		})
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

// libdns treats the first two SRV name labels as service and transport and adds underscores when it
// serializes the parsed record. A grant for the unprefixed tuple must not authorize that other name.
func TestSRVGrantCannotWriteParserRewrittenName(t *testing.T) {
	h := newTestAPI(t)
	body := map[string]any{
		"zone": zoneA,
		"records": []map[string]any{{
			"name": "sip.tcp", "type": "SRV", "ttl": 60,
			"data": "10 5 5060 sip.example.com.",
		}},
	}
	code, _, raw := call(t, h, "/records/set", body, globalGrant("sip.tcp", "SRV", "rw"))
	if code != http.StatusBadRequest || raw["error"] != "invalid_record" {
		t.Fatalf("expected 400 invalid_record, got %d %v", code, raw)
	}

	_, results, _ := call(t, h, "/records/get", map[string]any{"zone": zoneA}, globalGrant("**", "**", "r"))
	if len(results.Results) != 1 || len(results.Results[0].Records) != 0 {
		t.Fatalf("parser-rewritten SRV record was written: %+v", results.Results)
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
				record := map[string]any{"name": "_acme-challenge.x", "type": "TXT", "ttl": 60}
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

func TestSetAndAppendRequirePresentInRangeIntegerTTL(t *testing.T) {
	invalid := []struct {
		name    string
		include bool
		value   any
	}{
		{name: "omitted"},
		{name: "null", include: true, value: nil},
		{name: "string", include: true, value: "60"},
		{name: "fraction", include: true, value: 1.5},
		{name: "zero", include: true, value: 0},
		{name: "negative", include: true, value: -1},
		{name: "below minimum", include: true, value: records.MinTTLSeconds - 1},
		{name: "above maximum", include: true, value: uint64(records.MaxTTLSeconds) + 1},
	}

	for _, path := range []string{"/records/set", "/records/append"} {
		for _, tt := range invalid {
			t.Run(path+"/"+tt.name, func(t *testing.T) {
				h := newTestAPI(t)
				record := map[string]any{
					"name": "_acme-challenge.ttl", "type": "TXT", "data": "value",
				}
				if tt.include {
					record["ttl"] = tt.value
				}
				body := map[string]any{"zone": zoneA, "records": []map[string]any{record}}
				code, _, raw := call(t, h, path, body, acmeGrant)
				if code != http.StatusBadRequest || raw["error"] != "invalid_record" {
					t.Fatalf("expected 400 invalid_record, got %d %v", code, raw)
				}
			})
		}
	}

	for _, path := range []string{"/records/set", "/records/append"} {
		for _, ttl := range []int64{records.MinTTLSeconds, records.MaxTTLSeconds} {
			t.Run(path+"/valid-bound", func(t *testing.T) {
				h := newTestAPI(t)
				body := map[string]any{
					"zone": zoneA,
					"records": []map[string]any{{
						"name": "_acme-challenge.ttl", "type": "TXT", "ttl": ttl, "data": "value",
					}},
				}
				code, results, raw := call(t, h, path, body, acmeGrant)
				if code != http.StatusOK || !results.OK {
					t.Fatalf("valid TTL %d returned %d: %v", ttl, code, raw)
				}
			})
		}
	}
}

func TestInvalidTTLIsBadRequestEvenWithoutAGrant(t *testing.T) {
	h := newTestAPI(t)
	body := map[string]any{
		"zone": zoneA,
		"records": []map[string]any{{
			"name": "home", "type": "A", "data": "192.0.2.1",
		}},
	}
	code, _, raw := call(t, h, "/records/set", body, "")
	if code != http.StatusBadRequest || raw["error"] != "invalid_record" {
		t.Fatalf("expected 400 invalid_record, got %d %v", code, raw)
	}
}

func TestDeleteTTLIsOptionalButValidatedWhenPresent(t *testing.T) {
	invalid := []struct {
		name  string
		value any
	}{
		{name: "null", value: nil},
		{name: "string", value: "60"},
		{name: "fraction", value: 1.5},
		{name: "zero", value: 0},
		{name: "negative", value: -1},
		{name: "below minimum", value: records.MinTTLSeconds - 1},
		{name: "above maximum", value: uint64(records.MaxTTLSeconds) + 1},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestAPI(t)
			body := map[string]any{
				"zone": zoneA,
				"records": []map[string]any{{
					"name": "_acme-challenge.ttl", "type": "TXT", "ttl": tt.value,
				}},
			}
			code, _, raw := call(t, h, "/records/delete", body, acmeGrant)
			if code != http.StatusBadRequest || raw["error"] != "invalid_record" {
				t.Fatalf("expected 400 invalid_record, got %d %v", code, raw)
			}
		})
	}

	for _, ttl := range []any{nil, records.MinTTLSeconds, records.MaxTTLSeconds} {
		name := "omitted"
		if ttl != nil {
			name = "present"
		}
		t.Run(name, func(t *testing.T) {
			h := newTestAPI(t)
			record := map[string]any{"name": "_acme-challenge.ttl", "type": "TXT"}
			if ttl != nil {
				record["ttl"] = ttl
			}
			body := map[string]any{"zone": zoneA, "records": []map[string]any{record}}
			code, results, raw := call(t, h, "/records/delete", body, acmeGrant)
			if code != http.StatusOK || !results.OK {
				t.Fatalf("valid delete TTL returned %d: %v", code, raw)
			}
		})
	}
}

func serviceTestZones(count int) []store.Zone {
	zones := make([]store.Zone, count)
	for index := range zones {
		zones[index].Zone = fmt.Sprintf("zone-%02d.example", index)
	}
	return zones
}

func serviceRequest(t *testing.T, path string, body any, permissions string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, &buf)
	request.Header.Set(auth.HeaderConsumerID, "consumer-app-id")
	request.Header.Set(auth.HeaderConsumerName, "consumer-app")
	request.Header.Set(auth.HeaderPermissions, permissions)
	return request
}

func receiveService[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for service test signal")
		var zero T
		return zero
	}
}

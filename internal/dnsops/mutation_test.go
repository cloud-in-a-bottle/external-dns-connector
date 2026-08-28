package dnsops

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/records"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
)

type providerRecord struct {
	rr     libdns.RR
	marker string
}

func (r *providerRecord) RR() libdns.RR { return r.rr }

type mutationCall struct {
	zone    string
	records []libdns.Record
}

type mutationProvider struct {
	records     []libdns.Record
	getCalls    []string
	setCalls    []mutationCall
	appendCalls []mutationCall
	deleteCalls []mutationCall
	setErr      error
	appendErr   error
	deleteErr   error
}

func (p *mutationProvider) GetRecords(_ context.Context, zone string) ([]libdns.Record, error) {
	p.getCalls = append(p.getCalls, zone)
	return copyRecords(p.records), nil
}

func (p *mutationProvider) AppendRecords(
	_ context.Context, zone string, recs []libdns.Record,
) ([]libdns.Record, error) {
	p.appendCalls = append(p.appendCalls, mutationCall{zone: zone, records: copyRecords(recs)})
	if p.appendErr != nil {
		return nil, p.appendErr
	}
	p.records = append(p.records, recs...)
	return misleadingProviderResult(), nil
}

func (p *mutationProvider) SetRecords(
	_ context.Context, zone string, recs []libdns.Record,
) ([]libdns.Record, error) {
	p.setCalls = append(p.setCalls, mutationCall{zone: zone, records: copyRecords(recs)})
	if p.setErr != nil {
		return nil, p.setErr
	}
	touched := map[rrsetKey]bool{}
	for _, rec := range recs {
		touched[keyForRecord(rec)] = true
	}
	next := make([]libdns.Record, 0, len(p.records)+len(recs))
	for _, rec := range p.records {
		if !touched[keyForRecord(rec)] {
			next = append(next, rec)
		}
	}
	p.records = append(next, recs...)
	return misleadingProviderResult(), nil
}

func (p *mutationProvider) DeleteRecords(
	_ context.Context, zone string, recs []libdns.Record,
) ([]libdns.Record, error) {
	p.deleteCalls = append(p.deleteCalls, mutationCall{zone: zone, records: copyRecords(recs)})
	if p.deleteErr != nil {
		return nil, p.deleteErr
	}
	targets := map[libdns.RR]bool{}
	for _, rec := range recs {
		targets[rec.RR()] = true
	}
	next := make([]libdns.Record, 0, len(p.records))
	for _, rec := range p.records {
		if !targets[rec.RR()] {
			next = append(next, rec)
		}
	}
	p.records = next
	return misleadingProviderResult(), nil
}

func misleadingProviderResult() []libdns.Record {
	return []libdns.Record{testRR("misleading", "TXT", "provider return", 1)}
}

func TestSetReplacesOnlyTouchedRRset(t *testing.T) {
	untouched := testRR("other", "TXT", "stay", 60)
	p := &mutationProvider{records: []libdns.Record{
		testRR("name", "TXT", "old-one", 60),
		testRR("name", "TXT", "old-two", 60),
		untouched,
	}}
	one := testRR("name", "TXT", "new-one", 300)
	two := testRR("NAME", "txt", "new-two", 300)

	got, err := runMutation(t, p, OpSet, []libdns.Record{one, two, one}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertRecords(t, got, []libdns.Record{one, two})
	assertRecords(t, p.records, []libdns.Record{untouched, one, two})
	assertProviderCalls(t, p, 1, 1, 0, 0)
	assertMutationCall(t, p.setCalls[0], []libdns.Record{one, two})
}

func TestAppendPreservesExistingProviderRecordsAndDeduplicates(t *testing.T) {
	existing := &providerRecord{
		rr:     libdns.RR{Name: "name", Type: "TXT", TTL: time.Minute, Data: "existing"},
		marker: "provider metadata",
	}
	untouched := testRR("other", "TXT", "stay", 60)
	p := &mutationProvider{records: []libdns.Record{existing, untouched}}
	duplicateExisting := testRR("NAME", "txt", "existing", 60)
	added := testRR("name", "TXT", "added", 60)

	got, err := runMutation(
		t,
		p,
		OpAppend,
		[]libdns.Record{duplicateExisting, added, added},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertRecords(t, got, []libdns.Record{added})
	assertRecords(t, p.records, []libdns.Record{existing, untouched, added})
	assertProviderCalls(t, p, 1, 0, 0, 1)
	assertMutationCall(t, p.appendCalls[0], []libdns.Record{added})
	if p.records[0] != existing {
		t.Error("append replaced the provider-specific existing record instead of preserving it")
	}
}

func TestExactDeleteIgnoresTTLAndPreservesSiblingValues(t *testing.T) {
	drop := testRR("name", "TXT", "drop", 60)
	keep := &providerRecord{
		rr:     libdns.RR{Name: "name", Type: "TXT", TTL: time.Minute, Data: "keep"},
		marker: "provider metadata",
	}
	untouched := testRR("other", "TXT", "stay", 60)
	p := &mutationProvider{records: []libdns.Record{drop, keep, untouched}}
	target := testRR("NAME", "txt", "drop", 999)

	got, err := runMutation(t, p, OpDelete, []libdns.Record{target}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertRecords(t, got, []libdns.Record{drop})
	assertRecords(t, p.records, []libdns.Record{keep, untouched})
	assertProviderCalls(t, p, 1, 0, 1, 0)
	assertMutationCall(t, p.deleteCalls[0], []libdns.Record{drop})
	if p.records[0] != keep {
		t.Error("exact delete did not preserve the provider-specific sibling record")
	}
}

func TestClearDeletesTheFreshCurrentRRset(t *testing.T) {
	one := testRR("name", "TXT", "one", 60)
	two := testRR("name", "TXT", "two", 60)
	untouched := testRR("other", "TXT", "stay", 60)
	p := &mutationProvider{records: []libdns.Record{one, two, untouched}}

	got, err := runMutation(t, p, OpDelete, nil, []records.RRset{{Name: "NAME", Type: "txt"}})
	if err != nil {
		t.Fatal(err)
	}
	assertRecords(t, got, []libdns.Record{one, two})
	assertRecords(t, p.records, []libdns.Record{untouched})
	assertProviderCalls(t, p, 1, 0, 1, 0)
	assertMutationCall(t, p.deleteCalls[0], []libdns.Record{one, two})
}

func TestMutationPreservesSameNameWithDifferentType(t *testing.T) {
	txt := testRR("same", "TXT", "old", 60)
	address := testRR("same", "A", "192.0.2.1", 60)
	p := &mutationProvider{records: []libdns.Record{txt, address}}
	replacement := testRR("same", "TXT", "new", 60)

	_, err := runMutation(t, p, OpSet, []libdns.Record{replacement}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertRecords(t, p.records, []libdns.Record{address, replacement})
	assertProviderCalls(t, p, 1, 1, 0, 0)
}

func TestClearDominatesOverlappingExactDeletesWithoutDuplicates(t *testing.T) {
	one := testRR("name", "TXT", "one", 60)
	two := testRR("name", "TXT", "two", 60)
	untouched := testRR("other", "TXT", "stay", 60)
	p := &mutationProvider{records: []libdns.Record{one, two, untouched}}
	exact := testRR("name", "TXT", "one", 999)
	clears := []records.RRset{
		{Name: "name", Type: "TXT"},
		{Name: "NAME", Type: "txt"},
	}

	got, err := runMutation(t, p, OpDelete, []libdns.Record{exact, exact}, clears)
	if err != nil {
		t.Fatal(err)
	}
	assertRecords(t, got, []libdns.Record{one, two})
	assertRecords(t, p.records, []libdns.Record{untouched})
	assertProviderCalls(t, p, 1, 0, 1, 0)
	assertMutationCall(t, p.deleteCalls[0], []libdns.Record{one, two})
}

func TestAppendRejectsConflictingRRsetTTLsBeforeWriting(t *testing.T) {
	existing := testRR("name", "TXT", "existing", 60)
	p := &mutationProvider{records: []libdns.Record{existing}}
	other := testRR("aaa", "TXT", "would-write-first", 60)
	conflict := testRR("name", "TXT", "new", 300)

	_, err := runMutation(t, p, OpAppend, []libdns.Record{other, conflict}, nil)
	if err == nil || !strings.Contains(err.Error(), "conflicting TTLs") {
		t.Fatalf("expected a conflicting TTL error, got %v", err)
	}
	assertRecords(t, p.records, []libdns.Record{existing})
	assertProviderCalls(t, p, 1, 0, 0, 0)
}

func TestNoOpMutationsDoNotCallProviderMutators(t *testing.T) {
	one := testRR("same", "TXT", "one", 60)
	two := testRR("same", "TXT", "two", 60)
	other := testRR("other", "TXT", "stay", 60)
	tests := []struct {
		name      string
		current   []libdns.Record
		op        WriteOp
		requested []libdns.Record
		clears    []records.RRset
		want      []libdns.Record
	}{
		{
			name:      "set already matches",
			current:   []libdns.Record{one, two, other},
			op:        OpSet,
			requested: []libdns.Record{testRR("SAME", "txt", "two", 60), one, one},
			want:      []libdns.Record{testRR("SAME", "txt", "two", 60), one},
		},
		{
			name:      "append value exists",
			current:   []libdns.Record{one, other},
			op:        OpAppend,
			requested: []libdns.Record{testRR("SAME", "txt", "one", 60)},
		},
		{
			name:      "exact delete has no match",
			current:   []libdns.Record{one, other},
			op:        OpDelete,
			requested: []libdns.Record{testRR("same", "TXT", "missing", 999)},
		},
		{
			name:    "clear RRset is empty",
			current: []libdns.Record{other},
			op:      OpDelete,
			clears:  []records.RRset{{Name: "same", Type: "TXT"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &mutationProvider{records: copyRecords(tt.current)}
			got, err := runMutation(t, p, tt.op, tt.requested, tt.clears)
			if err != nil {
				t.Fatal(err)
			}
			assertRecords(t, got, tt.want)
			assertRecords(t, p.records, tt.current)
			assertProviderCalls(t, p, 1, 0, 0, 0)
		})
	}
}

func TestAppendErrorLeavesExistingSiblingRecordsUntouched(t *testing.T) {
	existing := testRR("name", "TXT", "existing", 60)
	other := testRR("other", "TXT", "stay", 60)
	before := []libdns.Record{existing, other}
	failure := errors.New("append failed")
	p := &mutationProvider{records: copyRecords(before), appendErr: failure}
	added := testRR("name", "TXT", "added", 60)

	_, err := runMutation(t, p, OpAppend, []libdns.Record{added}, nil)
	if !errors.Is(err, failure) {
		t.Fatalf("append returned %v, want %v", err, failure)
	}
	assertRecords(t, p.records, before)
	assertProviderCalls(t, p, 1, 0, 0, 1)
	assertMutationCall(t, p.appendCalls[0], []libdns.Record{added})
}

func TestExactDeleteErrorLeavesExistingSiblingRecordsUntouched(t *testing.T) {
	drop := testRR("name", "TXT", "drop", 60)
	keep := testRR("name", "TXT", "keep", 60)
	other := testRR("other", "TXT", "stay", 60)
	before := []libdns.Record{drop, keep, other}
	failure := errors.New("delete failed")
	p := &mutationProvider{records: copyRecords(before), deleteErr: failure}
	target := testRR("name", "TXT", "drop", 999)

	_, err := runMutation(t, p, OpDelete, []libdns.Record{target}, nil)
	if !errors.Is(err, failure) {
		t.Fatalf("delete returned %v, want %v", err, failure)
	}
	assertRecords(t, p.records, before)
	assertProviderCalls(t, p, 1, 0, 1, 0)
	assertMutationCall(t, p.deleteCalls[0], []libdns.Record{drop})
}

func TestRequiredInterfaceIsCheckedBeforeMultiRRsetMutation(t *testing.T) {
	current := []libdns.Record{
		testRR("a", "TXT", "target-a", 60),
		testRR("a", "TXT", "keep-a", 60),
		testRR("b", "TXT", "target-b", 60),
		testRR("b", "TXT", "keep-b", 60),
	}
	tests := []struct {
		name      string
		op        WriteOp
		requested []libdns.Record
		without   func(*mutationProvider) any
	}{
		{
			name: "setter",
			op:   OpSet,
			requested: []libdns.Record{
				testRR("a", "TXT", "new-a", 60),
				testRR("b", "TXT", "new-b", 60),
			},
			without: func(p *mutationProvider) any {
				return struct {
					libdns.RecordGetter
					libdns.RecordAppender
					libdns.RecordDeleter
				}{p, p, p}
			},
		},
		{
			name: "appender",
			op:   OpAppend,
			requested: []libdns.Record{
				testRR("a", "TXT", "new-a", 60),
				testRR("b", "TXT", "new-b", 60),
			},
			without: func(p *mutationProvider) any {
				return struct {
					libdns.RecordGetter
					libdns.RecordSetter
					libdns.RecordDeleter
				}{p, p, p}
			},
		},
		{
			name: "deleter",
			op:   OpDelete,
			requested: []libdns.Record{
				testRR("a", "TXT", "target-a", 999),
				testRR("b", "TXT", "target-b", 999),
			},
			without: func(p *mutationProvider) any {
				return struct {
					libdns.RecordGetter
					libdns.RecordAppender
					libdns.RecordSetter
				}{p, p, p}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &mutationProvider{records: copyRecords(current)}
			_, err := runMutation(t, tt.without(p), tt.op, tt.requested, nil)
			if err == nil || !strings.Contains(err.Error(), "cannot "+string(tt.op)+" records") {
				t.Fatalf("expected missing %s error, got %v", tt.name, err)
			}
			assertRecords(t, p.records, current)
			assertProviderCalls(t, p, 1, 0, 0, 0)
		})
	}
}

func runMutation(
	t *testing.T,
	p any,
	op WriteOp,
	requested []libdns.Record,
	clears []records.RRset,
) ([]libdns.Record, error) {
	t.Helper()
	z := store.Zone{Zone: "example.com", Provider: "test"}
	return applySemanticMutation(t.Context(), p, z, op, requested, clears)
}

func testRR(name, rrtype, data string, ttlSeconds int) libdns.Record {
	return libdns.RR{
		Name: name,
		Type: rrtype,
		TTL:  time.Duration(ttlSeconds) * time.Second,
		Data: data,
	}
}

func assertProviderCalls(
	t *testing.T,
	p *mutationProvider,
	gets, sets, deletes, appends int,
) {
	t.Helper()
	if len(p.getCalls) != gets || len(p.setCalls) != sets || len(p.deleteCalls) != deletes ||
		len(p.appendCalls) != appends {
		t.Errorf(
			"provider calls = get:%d set:%d delete:%d append:%d; want get:%d set:%d delete:%d append:%d",
			len(p.getCalls),
			len(p.setCalls),
			len(p.deleteCalls),
			len(p.appendCalls),
			gets,
			sets,
			deletes,
			appends,
		)
	}
	for _, zone := range p.getCalls {
		if zone != "example.com." {
			t.Errorf("GetRecords zone = %q, want example.com.", zone)
		}
	}
}

func assertMutationCall(t *testing.T, got mutationCall, want []libdns.Record) {
	t.Helper()
	if got.zone != "example.com." {
		t.Errorf("mutation zone = %q, want example.com.", got.zone)
	}
	assertRecords(t, got.records, want)
}

func assertRecords(t *testing.T, got, want []libdns.Record) {
	t.Helper()
	gotRRs := sortedRRs(got)
	wantRRs := sortedRRs(want)
	if !reflect.DeepEqual(gotRRs, wantRRs) {
		t.Errorf("records = %+v, want %+v", gotRRs, wantRRs)
	}
}

func sortedRRs(recs []libdns.Record) []libdns.RR {
	out := make([]libdns.RR, 0, len(recs))
	for _, rec := range recs {
		out = append(out, rec.RR())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].Data != out[j].Data {
			return out[i].Data < out[j].Data
		}
		return out[i].TTL < out[j].TTL
	})
	return out
}

package dnsops

import (
	"context"
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

type mutationProvider struct {
	records     []libdns.Record
	getCalls    int
	setCalls    [][]libdns.Record
	deleteCalls [][]libdns.Record
	appendCalls int
}

func (p *mutationProvider) GetRecords(context.Context, string) ([]libdns.Record, error) {
	p.getCalls++
	return copyRecords(p.records), nil
}

func (p *mutationProvider) AppendRecords(
	context.Context, string, []libdns.Record,
) ([]libdns.Record, error) {
	p.appendCalls++
	return nil, nil
}

func (p *mutationProvider) SetRecords(
	_ context.Context, _ string, recs []libdns.Record,
) ([]libdns.Record, error) {
	p.setCalls = append(p.setCalls, copyRecords(recs))
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
	return []libdns.Record{testRR("misleading", "TXT", "setter return", 1)}, nil
}

func (p *mutationProvider) DeleteRecords(
	_ context.Context, _ string, recs []libdns.Record,
) ([]libdns.Record, error) {
	p.deleteCalls = append(p.deleteCalls, copyRecords(recs))
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
	return []libdns.Record{testRR("misleading", "TXT", "deleter return", 1)}, nil
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
	assertRecords(t, p.setCalls[0], []libdns.Record{one, two})
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
	assertProviderCalls(t, p, 1, 1, 0, 0)
	if p.setCalls[0][0] != existing {
		t.Error("append replaced the provider-specific existing record instead of preserving it")
	}
	assertRecords(t, p.setCalls[0], []libdns.Record{existing, added})
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
	assertProviderCalls(t, p, 1, 1, 0, 0)
	if p.setCalls[0][0] != keep {
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
	assertRecords(t, p.deleteCalls[0], []libdns.Record{one, two})
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
	assertRecords(t, p.deleteCalls[0], []libdns.Record{one, two})
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

func runMutation(
	t *testing.T,
	p *mutationProvider,
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
	if p.getCalls != gets || len(p.setCalls) != sets || len(p.deleteCalls) != deletes ||
		p.appendCalls != appends {
		t.Errorf(
			"provider calls = get:%d set:%d delete:%d append:%d; want get:%d set:%d delete:%d append:%d",
			p.getCalls,
			len(p.setCalls),
			len(p.deleteCalls),
			p.appendCalls,
			gets,
			sets,
			deletes,
			appends,
		)
	}
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

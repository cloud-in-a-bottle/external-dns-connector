package dnsops

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/libdns/libdns"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/records"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
)

type rrsetKey struct {
	name   string
	rrtype string
}

type rrsetPlan struct {
	key     rrsetKey
	records []libdns.Record
	result  []libdns.Record
	changed bool
}

// applySemanticMutation performs the provider-independent read-modify-write while its caller holds
// the zone lock. Existing records stay in their provider-specific types when an RRset is preserved.
func applySemanticMutation(
	ctx context.Context,
	p any,
	z store.Zone,
	op WriteOp,
	requested []libdns.Record,
	clears []records.RRset,
) ([]libdns.Record, error) {
	if op != OpSet && op != OpAppend && op != OpDelete {
		return nil, fmt.Errorf("unknown write operation %q", op)
	}
	current, err := fetch(ctx, p, z)
	if err != nil {
		return nil, err
	}
	plans, err := planRRsets(op, current, requested, clears)
	if err != nil {
		return nil, err
	}

	hasChanges := false
	for _, plan := range plans {
		if plan.changed {
			hasChanges = true
			break
		}
	}

	var (
		appender libdns.RecordAppender
		setter   libdns.RecordSetter
		deleter  libdns.RecordDeleter
	)
	if hasChanges {
		var ok bool
		switch op {
		case OpSet:
			setter, ok = p.(libdns.RecordSetter)
		case OpAppend:
			appender, ok = p.(libdns.RecordAppender)
		case OpDelete:
			deleter, ok = p.(libdns.RecordDeleter)
		}
		if !ok {
			return nil, fmt.Errorf("provider %s cannot %s records", z.Provider, op)
		}
	}

	fqdn := z.Zone + "."
	var result []libdns.Record
	for _, plan := range plans {
		if !plan.changed {
			result = append(result, plan.result...)
			continue
		}
		var err error
		switch op {
		case OpSet:
			_, err = setter.SetRecords(ctx, fqdn, plan.records)
		case OpAppend:
			_, err = appender.AppendRecords(ctx, fqdn, plan.records)
		case OpDelete:
			_, err = deleter.DeleteRecords(ctx, fqdn, plan.records)
		}
		if err != nil {
			return result, fmt.Errorf("%s RRset %s/%s: %w", op, plan.key.name, plan.key.rrtype, err)
		}
		result = append(result, plan.result...)
	}
	return result, nil
}

func planRRsets(
	op WriteOp,
	current []libdns.Record,
	requested []libdns.Record,
	clears []records.RRset,
) ([]rrsetPlan, error) {
	if op != OpDelete && len(clears) > 0 {
		return nil, fmt.Errorf("RRset clears are only valid for delete operations")
	}

	touched := map[rrsetKey]bool{}
	requestedByKey := map[rrsetKey][]libdns.Record{}
	for _, rec := range requested {
		key := keyForRecord(rec)
		touched[key] = true
		requestedByKey[key] = append(requestedByKey[key], rec)
	}
	clearByKey := map[rrsetKey]bool{}
	for _, clear := range clears {
		key := newRRsetKey(clear.Name, clear.Type)
		touched[key] = true
		clearByKey[key] = true
	}

	currentByKey := map[rrsetKey][]libdns.Record{}
	for _, rec := range current {
		key := keyForRecord(rec)
		if touched[key] {
			currentByKey[key] = append(currentByKey[key], rec)
		}
	}

	keys := make([]rrsetKey, 0, len(touched))
	for key := range touched {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name == keys[j].name {
			return keys[i].rrtype < keys[j].rrtype
		}
		return keys[i].name < keys[j].name
	})

	plans := make([]rrsetPlan, 0, len(keys))
	for _, key := range keys {
		currentSet := currentByKey[key]
		requestSet := requestedByKey[key]
		plan := rrsetPlan{key: key}

		switch op {
		case OpSet:
			if err := requireSharedTTL(key, requestSet); err != nil {
				return nil, err
			}
			plan.records = uniqueValues(requestSet)
			plan.result = copyRecords(plan.records)
			plan.changed = !sameRRset(currentSet, plan.records)

		case OpAppend:
			withRequests := append(copyRecords(currentSet), requestSet...)
			if err := requireSharedTTL(key, withRequests); err != nil {
				return nil, err
			}
			uniqueRequests := uniqueValues(requestSet)
			seen := recordValues(currentSet)
			for _, rec := range uniqueRequests {
				if seen[rec.RR().Data] {
					continue
				}
				seen[rec.RR().Data] = true
				plan.records = append(plan.records, rec)
			}
			plan.result = copyRecords(plan.records)
			plan.changed = len(plan.records) > 0

		case OpDelete:
			if clearByKey[key] {
				plan.records = copyRecords(currentSet)
			} else {
				targets := recordValues(uniqueValues(requestSet))
				for _, rec := range currentSet {
					if targets[rec.RR().Data] {
						plan.records = append(plan.records, rec)
					}
				}
			}
			plan.result = copyRecords(plan.records)
			plan.changed = len(plan.records) > 0
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

func newRRsetKey(name, rrtype string) rrsetKey {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		name = records.Apex
	}
	return rrsetKey{
		name:   name,
		rrtype: strings.ToUpper(strings.TrimSpace(rrtype)),
	}
}

func keyForRecord(rec libdns.Record) rrsetKey {
	rr := rec.RR()
	return newRRsetKey(rr.Name, rr.Type)
}

func uniqueValues(recs []libdns.Record) []libdns.Record {
	seen := map[string]bool{}
	out := make([]libdns.Record, 0, len(recs))
	for _, rec := range recs {
		value := rec.RR().Data
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, rec)
	}
	return out
}

func recordValues(recs []libdns.Record) map[string]bool {
	values := make(map[string]bool, len(recs))
	for _, rec := range recs {
		values[rec.RR().Data] = true
	}
	return values
}

type rrsetMember struct {
	data string
	ttl  time.Duration
}

func sameRRset(left, right []libdns.Record) bool {
	if len(left) != len(right) {
		return false
	}
	members := make(map[rrsetMember]int, len(left))
	for _, rec := range left {
		rr := rec.RR()
		members[rrsetMember{data: rr.Data, ttl: rr.TTL}]++
	}
	for _, rec := range right {
		rr := rec.RR()
		member := rrsetMember{data: rr.Data, ttl: rr.TTL}
		if members[member] == 0 {
			return false
		}
		members[member]--
	}
	return true
}

func requireSharedTTL(key rrsetKey, recs []libdns.Record) error {
	if len(recs) < 2 {
		return nil
	}
	ttl := recs[0].RR().TTL
	for _, rec := range recs[1:] {
		if got := rec.RR().TTL; got != ttl {
			return fmt.Errorf(
				"RRset %s/%s has conflicting TTLs %s and %s",
				key.name,
				key.rrtype,
				ttl,
				got,
			)
		}
	}
	return nil
}

func copyRecords(recs []libdns.Record) []libdns.Record {
	return append([]libdns.Record(nil), recs...)
}

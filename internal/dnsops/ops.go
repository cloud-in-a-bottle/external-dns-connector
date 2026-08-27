package dnsops

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libdns/libdns"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsprov"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/records"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
)

// AllZones is the value callers pass for `zone` to fan an operation out across every configured zone.
const AllZones = "*"

// ErrUnknownZone is returned for a zone the owner has not configured. Consumers can only address the
// zones in that set, so a typo fails loudly instead of silently doing nothing.
var ErrUnknownZone = errors.New("unknown zone")

// cacheTTL bounds how stale a read may be. Provider APIs are rate-limited (Cloudflare allows 1200
// requests per 5 minutes, Route 53 five per second), and without this a busy consumer polling records
// would exhaust that budget on its own.
const cacheTTL = 30 * time.Second

type cacheEntry struct {
	records []libdns.Record
	fetched time.Time
}

// Ops runs record operations against the configured providers.
type Ops struct {
	store *store.Store
	deps  dnsprov.Deps

	mu    sync.Mutex
	locks map[string]*sync.Mutex
	cache map[string]cacheEntry
	nowFn func() time.Time
}

func New(s *store.Store) *Ops {
	return &Ops{
		store: s,
		deps:  dnsprov.Deps{DB: s.DB()},
		locks: map[string]*sync.Mutex{},
		cache: map[string]cacheEntry{},
		nowFn: time.Now,
	}
}

// ZoneResult is the outcome of one operation against one zone. Fan-out reports per zone rather than
// collapsing to a single status, because one provider being down says nothing about the others.
// Records is always serialized, as [] rather than being omitted, so a client can read it the same way
// whether or not anything matched.
type ZoneResult struct {
	Zone    string         `json:"zone"`
	OK      bool           `json:"ok"`
	Records []records.Wire `json:"records"`
	Error   string         `json:"error,omitempty"`
}

// ResolveZones turns a requested zone into the concrete list to act on. "*" means every configured
// zone; anything else must be in the configured set.
func (o *Ops) ResolveZones(requested string) ([]store.Zone, error) {
	all, err := o.store.Zones()
	if err != nil {
		return nil, err
	}
	if requested == AllZones {
		return all, nil
	}
	want := records.NormalizeZone(requested)
	for _, z := range all {
		if z.Zone == want {
			return []store.Zone{z}, nil
		}
	}
	return nil, fmt.Errorf("%q: %w", requested, ErrUnknownZone)
}

// provider builds the libdns provider for a zone. Providers are constructed per call rather than
// cached: they are cheap value structs, and rebuilding means a credential edit takes effect at once.
func (o *Ops) provider(z store.Zone) (any, error) {
	acct, err := o.store.Account(z.AccountID)
	if err != nil {
		return nil, err
	}
	return dnsprov.Build(o.deps, acct.Provider, acct.Credentials)
}

func (o *Ops) zoneLock(zone string) *sync.Mutex {
	o.mu.Lock()
	defer o.mu.Unlock()
	if l, ok := o.locks[zone]; ok {
		return l
	}
	l := &sync.Mutex{}
	o.locks[zone] = l
	return l
}

func (o *Ops) cached(zone string) ([]libdns.Record, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	e, ok := o.cache[zone]
	if !ok || o.nowFn().Sub(e.fetched) > cacheTTL {
		return nil, false
	}
	return e.records, true
}

func (o *Ops) putCache(zone string, recs []libdns.Record) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cache[zone] = cacheEntry{records: recs, fetched: o.nowFn()}
}

// InvalidateZone drops the cached read for a zone. Called after every write, including writes made
// through the owner UI, so a subsequent read never reports the pre-write state.
func (o *Ops) InvalidateZone(zone string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.cache, zone)
}

// Get returns every record in a zone, from cache when fresh.
func (o *Ops) Get(ctx context.Context, z store.Zone) ([]libdns.Record, error) {
	if recs, ok := o.cached(z.Zone); ok {
		return recs, nil
	}
	lock := o.zoneLock(z.Zone)
	lock.Lock()
	defer lock.Unlock()
	// Another caller may have populated the cache while we waited for the lock.
	if recs, ok := o.cached(z.Zone); ok {
		return recs, nil
	}

	p, err := o.provider(z)
	if err != nil {
		return nil, err
	}
	getter, ok := p.(libdns.RecordGetter)
	if !ok {
		return nil, fmt.Errorf("provider %s cannot read records", z.Provider)
	}
	recs, err := getter.GetRecords(ctx, z.Zone+".")
	if err != nil {
		return nil, err
	}
	o.putCache(z.Zone, recs)
	return recs, nil
}

type WriteOp string

const (
	OpSet    WriteOp = "set"
	OpAppend WriteOp = "append"
	OpDelete WriteOp = "delete"
)

// Write applies one write operation to one zone under that zone's lock, so two callers doing
// read-modify-write on the same zone cannot interleave.
func (o *Ops) Write(ctx context.Context, z store.Zone, op WriteOp, recs []libdns.Record) ([]libdns.Record, error) {
	lock := o.zoneLock(z.Zone)
	lock.Lock()
	defer lock.Unlock()
	defer o.InvalidateZone(z.Zone)

	p, err := o.provider(z)
	if err != nil {
		return nil, err
	}
	fqdn := z.Zone + "."

	switch op {
	case OpSet:
		setter, ok := p.(libdns.RecordSetter)
		if !ok {
			return nil, fmt.Errorf("provider %s cannot set records", z.Provider)
		}
		return setter.SetRecords(ctx, fqdn, recs)
	case OpAppend:
		appender, ok := p.(libdns.RecordAppender)
		if !ok {
			return nil, fmt.Errorf("provider %s cannot append records", z.Provider)
		}
		return appender.AppendRecords(ctx, fqdn, recs)
	case OpDelete:
		deleter, ok := p.(libdns.RecordDeleter)
		if !ok {
			return nil, fmt.Errorf("provider %s cannot delete records", z.Provider)
		}
		return deleter.DeleteRecords(ctx, fqdn, recs)
	default:
		return nil, fmt.Errorf("unknown write operation %q", op)
	}
}

// ListProviderZones asks a provider which zones it can see, for the owner UI's zone picker. Not every
// provider supports it; callers fall back to manual entry.
func (o *Ops) ListProviderZones(ctx context.Context, acct store.Account) ([]string, error) {
	p, err := dnsprov.Build(o.deps, acct.Provider, acct.Credentials)
	if err != nil {
		return nil, err
	}
	lister, ok := p.(libdns.ZoneLister)
	if !ok {
		return nil, fmt.Errorf("provider %s cannot list zones", acct.Provider)
	}
	zones, err := lister.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(zones))
	for _, z := range zones {
		out = append(out, records.NormalizeZone(z.Name))
	}
	return out, nil
}

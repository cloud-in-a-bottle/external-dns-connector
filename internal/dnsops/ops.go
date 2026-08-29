package dnsops

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/libdns/libdns"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsprov"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/lifecycle"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/records"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
)

// AllZones is the value callers pass for `zone` to fan an operation out across every configured zone.
const AllZones = "*"

// ErrUnknownZone is returned for a zone the owner has not configured. Consumers can only address the
// zones in that set, so a typo fails loudly instead of silently doing nothing.
var ErrUnknownZone = errors.New("unknown zone")

// cacheTTL bounds how stale a read may be. Provider APIs are rate-limited, and without this a busy
// consumer polling records would exhaust that budget on its own.
const cacheTTL = 30 * time.Second

type contextLock struct {
	token chan struct{}
}

type zoneLockEntry struct {
	lock *contextLock
	refs int
}

func newContextLock() *contextLock {
	l := &contextLock{token: make(chan struct{}, 1)}
	l.token <- struct{}{}
	return l
}

func (l *contextLock) lock(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.token:
		select {
		case <-ctx.Done():
			l.unlock()
			return ctx.Err()
		default:
			return nil
		}
	}
}

func (l *contextLock) unlock() {
	l.token <- struct{}{}
}

type cacheKey struct {
	zone      string
	accountID int64
}

type cacheEntry struct {
	records []libdns.Record
	fetched time.Time
}

// Ops runs record operations against the configured providers.
type Ops struct {
	store         *store.Store
	buildProvider func(store.Account) (any, error)

	configMu sync.Mutex
	locksMu  sync.Mutex
	locks    map[string]*zoneLockEntry
	cacheMu  sync.Mutex
	cache    map[cacheKey]cacheEntry
	nowFn    func() time.Time
	timeout  time.Duration
}

// Option configures Ops.
type Option func(*Ops)

// WithProviderTimeout overrides the deadline applied to each provider operation.
func WithProviderTimeout(timeout time.Duration) Option {
	if timeout <= 0 {
		panic("provider timeout must be positive")
	}
	return func(o *Ops) {
		o.timeout = timeout
	}
}

func New(s *store.Store, options ...Option) *Ops {
	deps := dnsprov.Deps{DB: s.DB()}
	o := &Ops{
		store: s,
		buildProvider: func(acct store.Account) (any, error) {
			return dnsprov.Build(deps, acct.Provider, acct.Credentials)
		},
		locks:   map[string]*zoneLockEntry{},
		cache:   map[cacheKey]cacheEntry{},
		nowFn:   time.Now,
		timeout: lifecycle.ProviderTimeout,
	}
	for _, option := range options {
		option(o)
	}
	return o
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
	return o.buildProvider(acct)
}

func (o *Ops) acquireZoneLock(ctx context.Context, zone string) (func(), error) {
	zone = records.NormalizeZone(zone)
	o.locksMu.Lock()
	entry := o.locks[zone]
	if entry == nil {
		entry = &zoneLockEntry{lock: newContextLock()}
		o.locks[zone] = entry
	}
	entry.refs++
	o.locksMu.Unlock()

	if err := entry.lock.lock(ctx); err != nil {
		o.dropZoneLockRef(zone, entry)
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			// Unlock first so deleting the last reference can never expose an overlapping lock.
			entry.lock.unlock()
			o.dropZoneLockRef(zone, entry)
		})
	}, nil
}

func (o *Ops) dropZoneLockRef(zone string, entry *zoneLockEntry) {
	o.locksMu.Lock()
	defer o.locksMu.Unlock()
	entry.refs--
	if entry.refs == 0 && o.locks[zone] == entry {
		delete(o.locks, zone)
	}
}

// cached is called only while the corresponding zone lock is held. accountID keeps a stale entry
// from one binding from being reused if the zone is rebound before invalidation.
func (o *Ops) cached(z store.Zone) ([]libdns.Record, bool) {
	o.cacheMu.Lock()
	defer o.cacheMu.Unlock()
	e, ok := o.cache[cacheKey{zone: z.Zone, accountID: z.AccountID}]
	if !ok || o.nowFn().Sub(e.fetched) > cacheTTL {
		return nil, false
	}
	return e.records, true
}

func (o *Ops) putCache(z store.Zone, recs []libdns.Record) {
	o.cacheMu.Lock()
	defer o.cacheMu.Unlock()
	o.cache[cacheKey{zone: z.Zone, accountID: z.AccountID}] = cacheEntry{
		records: recs,
		fetched: o.nowFn(),
	}
}

func (o *Ops) invalidateZone(zone string) {
	o.cacheMu.Lock()
	defer o.cacheMu.Unlock()
	for key := range o.cache {
		if key.zone == zone {
			delete(o.cache, key)
		}
	}
}

func (o *Ops) lockZones(ctx context.Context, zones []string) (func(), error) {
	seen := make(map[string]bool, len(zones))
	names := make([]string, 0, len(zones))
	for _, zone := range zones {
		zone = records.NormalizeZone(zone)
		if seen[zone] {
			continue
		}
		seen[zone] = true
		names = append(names, zone)
	}
	sort.Strings(names)

	held := make([]func(), 0, len(names))
	for _, name := range names {
		release, err := o.acquireZoneLock(ctx, name)
		if err != nil {
			for i := len(held) - 1; i >= 0; i-- {
				held[i]()
			}
			return nil, err
		}
		held = append(held, release)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for i := len(held) - 1; i >= 0; i-- {
				held[i]()
			}
		})
	}, nil
}

// AddZone serializes one owner binding change with provider work for that zone.
func (o *Ops) AddZone(ctx context.Context, binding store.ZoneBinding) error {
	zone, err := records.ValidateZone(binding.Zone)
	if err != nil {
		return err
	}
	o.configMu.Lock()
	defer o.configMu.Unlock()

	unlock, err := o.lockZones(ctx, []string{zone})
	if err != nil {
		return err
	}
	defer unlock()

	if _, err := o.store.Zone(zone); err == nil {
		return fmt.Errorf("zone %s is already configured", zone)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err := o.store.AddZone(store.ZoneBinding{Zone: zone, AccountID: binding.AccountID}); err != nil {
		return err
	}
	o.invalidateZone(zone)
	return nil
}

// DeleteZone serializes one owner binding removal with provider work for that zone.
func (o *Ops) DeleteZone(ctx context.Context, zone string) error {
	zone, err := records.ValidateZone(zone)
	if err != nil {
		return err
	}
	o.configMu.Lock()
	defer o.configMu.Unlock()

	unlock, err := o.lockZones(ctx, []string{zone})
	if err != nil {
		return err
	}
	defer unlock()

	if err := o.store.DeleteZone(zone); err != nil {
		return err
	}
	o.invalidateZone(zone)
	return nil
}

// ReplaceZones serializes a whole owner binding-set replacement with every possibly affected zone.
func (o *Ops) ReplaceZones(ctx context.Context, bindings []store.ZoneBinding) error {
	normalized := make([]store.ZoneBinding, 0, len(bindings))
	for _, binding := range bindings {
		zone, err := records.ValidateZone(binding.Zone)
		if err != nil {
			return err
		}
		normalized = append(normalized, store.ZoneBinding{Zone: zone, AccountID: binding.AccountID})
	}

	o.configMu.Lock()
	defer o.configMu.Unlock()

	existing, err := o.store.Zones()
	if err != nil {
		return err
	}
	affected := make([]string, 0, len(existing)+len(normalized))
	for _, zone := range existing {
		affected = append(affected, zone.Zone)
	}
	for _, binding := range normalized {
		affected = append(affected, binding.Zone)
	}
	unlock, err := o.lockZones(ctx, affected)
	if err != nil {
		return err
	}
	defer unlock()

	if err := o.store.ReplaceZones(normalized); err != nil {
		return err
	}
	for _, zone := range affected {
		o.invalidateZone(records.NormalizeZone(zone))
	}
	return nil
}

// DeleteAccount serializes its cascading zone removals with provider work for those zones.
func (o *Ops) DeleteAccount(ctx context.Context, id int64) error {
	o.configMu.Lock()
	defer o.configMu.Unlock()

	zones, err := o.store.Zones()
	if err != nil {
		return err
	}
	var affected []string
	for _, zone := range zones {
		if zone.AccountID == id {
			affected = append(affected, zone.Zone)
		}
	}
	unlock, err := o.lockZones(ctx, affected)
	if err != nil {
		return err
	}
	defer unlock()

	if err := o.store.DeleteAccount(id); err != nil {
		return err
	}
	for _, zone := range affected {
		o.invalidateZone(zone)
	}
	return nil
}

// Get returns every record in a zone, from cache when fresh.
func (o *Ops) Get(ctx context.Context, z store.Zone) ([]libdns.Record, error) {
	zone := records.NormalizeZone(z.Zone)
	unlock, err := o.acquireZoneLock(ctx, zone)
	if err != nil {
		return nil, err
	}
	defer unlock()

	current, err := o.store.Zone(zone)
	if err != nil {
		return nil, err
	}
	if recs, ok := o.cached(current); ok {
		return recs, nil
	}

	opCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	p, err := o.provider(current)
	if err != nil {
		return nil, err
	}
	recs, err := fetch(opCtx, p, current)
	if err != nil {
		return nil, err
	}
	o.putCache(current, recs)
	return recs, nil
}

// fetch reads a zone straight from its provider. Callers must already hold the zone lock.
func fetch(ctx context.Context, p any, z store.Zone) ([]libdns.Record, error) {
	getter, ok := p.(libdns.RecordGetter)
	if !ok {
		return nil, fmt.Errorf("provider %s cannot read records", z.Provider)
	}
	return getter.GetRecords(ctx, z.Zone+".")
}

type WriteOp string

const (
	OpSet    WriteOp = "set"
	OpAppend WriteOp = "append"
	OpDelete WriteOp = "delete"
)

// Write applies one write operation to one zone under that zone's lock, so two callers doing
// read-modify-write on the same zone cannot interleave.
func (o *Ops) Write(
	ctx context.Context, z store.Zone, op WriteOp, recs []libdns.Record,
) ([]libdns.Record, error) {
	return o.mutate(ctx, z, op, recs, nil)
}

// Delete removes exact values or whole RRsets. Exact matching deliberately ignores TTL because DNS
// stores one TTL for the RRset rather than a separate TTL for each value.
func (o *Ops) Delete(
	ctx context.Context, z store.Zone, exact []libdns.Record, clears []records.RRset,
) ([]libdns.Record, error) {
	return o.mutate(ctx, z, OpDelete, exact, clears)
}

func (o *Ops) mutate(
	ctx context.Context, z store.Zone, op WriteOp, recs []libdns.Record, clears []records.RRset,
) ([]libdns.Record, error) {
	zone := records.NormalizeZone(z.Zone)
	unlock, err := o.acquireZoneLock(ctx, zone)
	if err != nil {
		return nil, err
	}
	defer unlock()

	current, err := o.store.Zone(zone)
	if err != nil {
		return nil, err
	}
	defer o.invalidateZone(zone)

	opCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	p, err := o.provider(current)
	if err != nil {
		return nil, err
	}
	return applySemanticMutation(opCtx, p, current, op, recs, clears)
}

// ListProviderZones asks a provider which zones it can see, for the owner UI's zone picker. Not every
// provider supports it; callers fall back to manual entry.
func (o *Ops) ListProviderZones(ctx context.Context, acct store.Account) ([]string, error) {
	opCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	p, err := o.buildProvider(acct)
	if err != nil {
		return nil, err
	}
	lister, ok := p.(libdns.ZoneLister)
	if !ok {
		return nil, fmt.Errorf("provider %s cannot list zones", acct.Provider)
	}
	zones, err := lister.ListZones(opCtx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(zones))
	for _, z := range zones {
		out = append(out, records.NormalizeZone(z.Name))
	}
	return out, nil
}

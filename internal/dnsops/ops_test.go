package dnsops

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
)

type controlledProvider struct {
	mu sync.Mutex

	records []libdns.Record
	gets    int
	sets    int

	getStarted chan struct{}
	getRelease <-chan struct{}
	getOnce    sync.Once
	setStarted chan struct{}
	setRelease <-chan struct{}
	setOnce    sync.Once
}

func (p *controlledProvider) GetRecords(ctx context.Context, _ string) ([]libdns.Record, error) {
	p.mu.Lock()
	p.gets++
	p.mu.Unlock()
	p.getOnce.Do(func() {
		if p.getStarted != nil {
			close(p.getStarted)
		}
	})
	if p.getRelease != nil {
		select {
		case <-p.getRelease:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return copyRecords(p.records), nil
}

func (p *controlledProvider) SetRecords(
	ctx context.Context,
	_ string,
	records []libdns.Record,
) ([]libdns.Record, error) {
	p.mu.Lock()
	p.sets++
	p.mu.Unlock()
	p.setOnce.Do(func() {
		if p.setStarted != nil {
			close(p.setStarted)
		}
	})
	if p.setRelease != nil {
		select {
		case <-p.setRelease:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	p.mu.Lock()
	p.records = copyRecords(records)
	p.mu.Unlock()
	return records, nil
}

func (p *controlledProvider) callCounts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gets, p.sets
}

type observedContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *observedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

type operationResult struct {
	records []libdns.Record
	err     error
}

type zoneLockResult struct {
	release func()
	err     error
}

func TestConcurrentAddZonePreservesBothBindings(t *testing.T) {
	st := newOpsTestStore(t)
	accountID := newOpsTestAccount(t, st, "provider", "account")
	ops := New(st)

	start := make(chan struct{})
	ready := make(chan struct{}, 2)
	done := make(chan error, 2)
	for _, zone := range []string{"one.example", "two.example"} {
		go func(zone string) {
			ready <- struct{}{}
			<-start
			done <- ops.AddZone(t.Context(), store.ZoneBinding{Zone: zone, AccountID: accountID})
		}(zone)
	}
	receive(t, ready)
	receive(t, ready)
	close(start)
	for range 2 {
		if err := receive(t, done); err != nil {
			t.Fatal(err)
		}
	}

	zones, err := st.Zones()
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 || zones[0].Zone != "one.example" || zones[1].Zone != "two.example" {
		t.Fatalf("concurrent adds stored %+v", zones)
	}
}

func TestBlockedReadCompletesBeforeRebindAndNextReadUsesNewProvider(t *testing.T) {
	st := newOpsTestStore(t)
	oldID := newOpsTestAccount(t, st, "old", "old-account")
	newID := newOpsTestAccount(t, st, "new", "new-account")
	if err := st.AddZone(store.ZoneBinding{Zone: "example.com", AccountID: oldID}); err != nil {
		t.Fatal(err)
	}
	stale, err := st.Zone("example.com")
	if err != nil {
		t.Fatal(err)
	}

	oldStarted := make(chan struct{})
	oldRelease := make(chan struct{})
	oldProvider := &controlledProvider{
		records:    []libdns.Record{testRR("old", "TXT", "old-provider", 60)},
		getStarted: oldStarted,
		getRelease: oldRelease,
	}
	newRecord := testRR("new", "TXT", "new-provider", 60)
	newProvider := &controlledProvider{records: []libdns.Record{newRecord}}
	ops := New(st)
	ops.buildProvider = func(account store.Account) (any, error) {
		if account.ID == oldID {
			return oldProvider, nil
		}
		return newProvider, nil
	}

	readDone := make(chan operationResult, 1)
	go func() {
		records, err := ops.Get(t.Context(), stale)
		readDone <- operationResult{records: records, err: err}
	}()
	waitClosed(t, oldStarted)

	rebindObserved := make(chan struct{})
	rebindCtx := &observedContext{Context: t.Context(), observed: rebindObserved}
	rebindDone := make(chan error, 1)
	go func() {
		rebindDone <- ops.ReplaceZones(
			rebindCtx,
			[]store.ZoneBinding{{Zone: stale.Zone, AccountID: newID}},
		)
	}()
	waitClosed(t, rebindObserved)
	assertPending(t, rebindDone)
	assertZoneAccount(t, st, stale.Zone, oldID)

	close(oldRelease)
	first := receive(t, readDone)
	if first.err != nil {
		t.Fatal(first.err)
	}
	assertRecords(t, first.records, oldProvider.records)
	if err := receive(t, rebindDone); err != nil {
		t.Fatal(err)
	}

	second, err := ops.Get(t.Context(), stale)
	if err != nil {
		t.Fatal(err)
	}
	assertRecords(t, second, []libdns.Record{newRecord})
	oldGets, _ := oldProvider.callCounts()
	newGets, _ := newProvider.callCounts()
	if oldGets != 1 || newGets != 1 {
		t.Fatalf("provider gets = old:%d new:%d, want one each", oldGets, newGets)
	}
}

func TestBlockedReadCompletesBeforeAccountDeletion(t *testing.T) {
	st := newOpsTestStore(t)
	oldID := newOpsTestAccount(t, st, "old", "old-account")
	newID := newOpsTestAccount(t, st, "new", "new-account")
	if err := st.AddZone(store.ZoneBinding{Zone: "example.com", AccountID: oldID}); err != nil {
		t.Fatal(err)
	}
	stale, err := st.Zone("example.com")
	if err != nil {
		t.Fatal(err)
	}

	oldStarted := make(chan struct{})
	oldRelease := make(chan struct{})
	oldRecord := testRR("old", "TXT", "old-provider", 60)
	oldProvider := &controlledProvider{
		records:    []libdns.Record{oldRecord},
		getStarted: oldStarted,
		getRelease: oldRelease,
	}
	newRecord := testRR("new", "TXT", "new-provider", 60)
	newProvider := &controlledProvider{records: []libdns.Record{newRecord}}
	ops := New(st)
	ops.buildProvider = func(account store.Account) (any, error) {
		if account.ID == oldID {
			return oldProvider, nil
		}
		return newProvider, nil
	}

	readDone := make(chan operationResult, 1)
	go func() {
		records, err := ops.Get(t.Context(), stale)
		readDone <- operationResult{records: records, err: err}
	}()
	waitClosed(t, oldStarted)

	deleteObserved := make(chan struct{})
	deleteCtx := &observedContext{Context: t.Context(), observed: deleteObserved}
	deleteDone := make(chan error, 1)
	go func() { deleteDone <- ops.DeleteAccount(deleteCtx, oldID) }()
	waitClosed(t, deleteObserved)
	assertPending(t, deleteDone)
	assertZoneAccount(t, st, stale.Zone, oldID)

	close(oldRelease)
	result := receive(t, readDone)
	if result.err != nil {
		t.Fatal(result.err)
	}
	assertRecords(t, result.records, []libdns.Record{oldRecord})
	if err := receive(t, deleteDone); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Account(oldID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted account lookup returned %v", err)
	}
	if _, err := st.Zone(stale.Zone); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cascaded zone lookup returned %v", err)
	}
	ops.cacheMu.Lock()
	for key := range ops.cache {
		if key.zone == stale.Zone {
			ops.cacheMu.Unlock()
			t.Fatalf("account deletion left a cache entry for %s", stale.Zone)
		}
	}
	ops.cacheMu.Unlock()

	if err := ops.AddZone(
		t.Context(),
		store.ZoneBinding{Zone: stale.Zone, AccountID: newID},
	); err != nil {
		t.Fatal(err)
	}
	records, err := ops.Get(t.Context(), stale)
	if err != nil {
		t.Fatal(err)
	}
	assertRecords(t, records, []libdns.Record{newRecord})
}

func TestBlockedWriteCompletesBeforeRebindAndNextWriteUsesNewProvider(t *testing.T) {
	st := newOpsTestStore(t)
	oldID := newOpsTestAccount(t, st, "old", "old-account")
	newID := newOpsTestAccount(t, st, "new", "new-account")
	if err := st.AddZone(store.ZoneBinding{Zone: "example.com", AccountID: oldID}); err != nil {
		t.Fatal(err)
	}
	stale, err := st.Zone("example.com")
	if err != nil {
		t.Fatal(err)
	}

	oldSetStarted := make(chan struct{})
	oldSetRelease := make(chan struct{})
	oldProvider := &controlledProvider{setStarted: oldSetStarted, setRelease: oldSetRelease}
	newProvider := &controlledProvider{}
	ops := New(st)
	ops.buildProvider = func(account store.Account) (any, error) {
		if account.ID == oldID {
			return oldProvider, nil
		}
		return newProvider, nil
	}

	writeDone := make(chan error, 1)
	firstRecord := testRR("name", "TXT", "old-write", 60)
	go func() {
		_, err := ops.Write(t.Context(), stale, OpSet, []libdns.Record{firstRecord})
		writeDone <- err
	}()
	waitClosed(t, oldSetStarted)

	rebindObserved := make(chan struct{})
	rebindCtx := &observedContext{Context: t.Context(), observed: rebindObserved}
	rebindDone := make(chan error, 1)
	go func() {
		rebindDone <- ops.ReplaceZones(
			rebindCtx,
			[]store.ZoneBinding{{Zone: stale.Zone, AccountID: newID}},
		)
	}()
	waitClosed(t, rebindObserved)
	assertPending(t, rebindDone)
	assertZoneAccount(t, st, stale.Zone, oldID)

	close(oldSetRelease)
	if err := receive(t, writeDone); err != nil {
		t.Fatal(err)
	}
	if err := receive(t, rebindDone); err != nil {
		t.Fatal(err)
	}

	secondRecord := testRR("name", "TXT", "new-write", 60)
	if _, err := ops.Write(t.Context(), stale, OpSet, []libdns.Record{secondRecord}); err != nil {
		t.Fatal(err)
	}
	oldGets, oldSets := oldProvider.callCounts()
	newGets, newSets := newProvider.callCounts()
	if oldGets != 1 || oldSets != 1 || newGets != 1 || newSets != 1 {
		t.Fatalf(
			"provider calls = old get/set:%d/%d new get/set:%d/%d, want 1/1 for each",
			oldGets,
			oldSets,
			newGets,
			newSets,
		)
	}
}

func TestSameZoneLocksAreMutuallyExclusive(t *testing.T) {
	ops := New(newOpsTestStore(t))
	firstRelease, err := ops.acquireZoneLock(t.Context(), "Example.com.")
	if err != nil {
		t.Fatal(err)
	}

	waitObserved := make(chan struct{})
	waitCtx := &observedContext{Context: t.Context(), observed: waitObserved}
	secondDone := make(chan zoneLockResult, 1)
	go func() {
		release, err := ops.acquireZoneLock(waitCtx, "example.com")
		secondDone <- zoneLockResult{release: release, err: err}
	}()
	waitClosed(t, waitObserved)
	assertZoneLockRefs(t, ops, "example.com", 2)
	assertPending(t, secondDone)

	firstRelease()
	firstRelease()
	second := receive(t, secondDone)
	if second.err != nil {
		t.Fatal(second.err)
	}
	assertZoneLockRefs(t, ops, "example.com", 1)
	second.release()
	assertNoZoneLocks(t, ops)
}

func TestCanceledZoneLockWaiterCleansUp(t *testing.T) {
	ops := New(newOpsTestStore(t))
	heldRelease, err := ops.acquireZoneLock(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}

	waitObserved := make(chan struct{})
	baseCtx, cancel := context.WithCancel(t.Context())
	waitCtx := &observedContext{Context: baseCtx, observed: waitObserved}
	waitDone := make(chan zoneLockResult, 1)
	go func() {
		release, err := ops.acquireZoneLock(waitCtx, "example.com")
		waitDone <- zoneLockResult{release: release, err: err}
	}()
	waitClosed(t, waitObserved)
	assertZoneLockRefs(t, ops, "example.com", 2)
	cancel()
	waiter := receive(t, waitDone)
	if !errors.Is(waiter.err, context.Canceled) {
		t.Fatalf("waiting lock returned %v, want context cancellation", waiter.err)
	}
	if waiter.release != nil {
		t.Fatal("canceled lock acquisition returned a release function")
	}
	assertZoneLockRefs(t, ops, "example.com", 1)

	heldRelease()
	assertNoZoneLocks(t, ops)
}

func TestZoneLockRegistryDoesNotRetainIdleZones(t *testing.T) {
	ops := New(newOpsTestStore(t))
	for i := range 5000 {
		zone := "zone-" + strconv.Itoa(i) + ".example"
		release, err := ops.acquireZoneLock(t.Context(), zone)
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	assertNoZoneLocks(t, ops)
}

func TestZoneLockAcquisitionHonorsContext(t *testing.T) {
	st := newOpsTestStore(t)
	accountID := newOpsTestAccount(t, st, "provider", "account")
	if err := st.AddZone(store.ZoneBinding{Zone: "example.com", AccountID: accountID}); err != nil {
		t.Fatal(err)
	}
	zone, err := st.Zone("example.com")
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	provider := &controlledProvider{getStarted: started, getRelease: release}
	ops := New(st)
	ops.buildProvider = func(store.Account) (any, error) { return provider, nil }
	firstDone := make(chan error, 1)
	go func() {
		_, err := ops.Get(t.Context(), zone)
		firstDone <- err
	}()
	waitClosed(t, started)

	waitObserved := make(chan struct{})
	baseCtx, cancel := context.WithCancel(t.Context())
	waitCtx := &observedContext{Context: baseCtx, observed: waitObserved}
	secondDone := make(chan error, 1)
	go func() {
		_, err := ops.Get(waitCtx, zone)
		secondDone <- err
	}()
	waitClosed(t, waitObserved)
	cancel()
	if err := receive(t, secondDone); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting Get returned %v, want context cancellation", err)
	}

	close(release)
	if err := receive(t, firstDone); err != nil {
		t.Fatal(err)
	}
	assertNoZoneLocks(t, ops)
}

type deadlineProvider struct {
	getDeadline  chan time.Time
	setDeadline  chan time.Time
	listDeadline chan time.Time
	blockGet     bool
}

func (p *deadlineProvider) GetRecords(ctx context.Context, _ string) ([]libdns.Record, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("GetRecords received no deadline")
	}
	p.getDeadline <- deadline
	if !p.blockGet {
		return nil, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (p *deadlineProvider) SetRecords(
	ctx context.Context,
	_ string,
	records []libdns.Record,
) ([]libdns.Record, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("SetRecords received no deadline")
	}
	p.setDeadline <- deadline
	<-ctx.Done()
	return nil, ctx.Err()
}

func (p *deadlineProvider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("ListZones received no deadline")
	}
	p.listDeadline <- deadline
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestProviderDeadlineAppliesToRead(t *testing.T) {
	st := newOpsTestStore(t)
	accountID := newOpsTestAccount(t, st, "deadline", "account")
	if err := st.AddZone(store.ZoneBinding{Zone: "example.com", AccountID: accountID}); err != nil {
		t.Fatal(err)
	}
	zone, err := st.Zone("example.com")
	if err != nil {
		t.Fatal(err)
	}

	provider := &deadlineProvider{getDeadline: make(chan time.Time, 1), blockGet: true}
	ops := New(st, WithProviderTimeout(40*time.Millisecond))
	ops.buildProvider = func(store.Account) (any, error) { return provider, nil }
	done := make(chan error, 1)
	go func() {
		_, err := ops.Get(t.Context(), zone)
		done <- err
	}()
	receive(t, provider.getDeadline)
	if err := receive(t, done); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Get returned %v, want deadline exceeded", err)
	}
}

func TestMutationFetchAndWriteShareProviderDeadline(t *testing.T) {
	st := newOpsTestStore(t)
	accountID := newOpsTestAccount(t, st, "deadline", "account")
	if err := st.AddZone(store.ZoneBinding{Zone: "example.com", AccountID: accountID}); err != nil {
		t.Fatal(err)
	}
	zone, err := st.Zone("example.com")
	if err != nil {
		t.Fatal(err)
	}

	provider := &deadlineProvider{
		getDeadline: make(chan time.Time, 1),
		setDeadline: make(chan time.Time, 1),
	}
	ops := New(st, WithProviderTimeout(40*time.Millisecond))
	ops.buildProvider = func(store.Account) (any, error) { return provider, nil }
	done := make(chan error, 1)
	go func() {
		_, err := ops.Write(
			t.Context(),
			zone,
			OpSet,
			[]libdns.Record{testRR("name", "TXT", "value", 60)},
		)
		done <- err
	}()
	getDeadline := receive(t, provider.getDeadline)
	setDeadline := receive(t, provider.setDeadline)
	if !getDeadline.Equal(setDeadline) {
		t.Fatalf("fetch deadline %s differs from write deadline %s", getDeadline, setDeadline)
	}
	if err := receive(t, done); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Write returned %v, want deadline exceeded", err)
	}
}

func TestProviderDeadlineAppliesToZoneListing(t *testing.T) {
	st := newOpsTestStore(t)
	provider := &deadlineProvider{listDeadline: make(chan time.Time, 1)}
	ops := New(st, WithProviderTimeout(40*time.Millisecond))
	ops.buildProvider = func(store.Account) (any, error) { return provider, nil }
	done := make(chan error, 1)
	go func() {
		_, err := ops.ListProviderZones(t.Context(), store.Account{Provider: "deadline"})
		done <- err
	}()
	receive(t, provider.listDeadline)
	if err := receive(t, done); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ListProviderZones returned %v, want deadline exceeded", err)
	}
}

func newOpsTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func newOpsTestAccount(t *testing.T, st *store.Store, provider, label string) int64 {
	t.Helper()
	id, err := st.CreateAccount(provider, label, nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func assertZoneAccount(t *testing.T, st *store.Store, zone string, want int64) {
	t.Helper()
	got, err := st.Zone(zone)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccountID != want {
		t.Fatalf("zone %s account = %d, want %d", zone, got.AccountID, want)
	}
}

func assertZoneLockRefs(t *testing.T, ops *Ops, zone string, want int) {
	t.Helper()
	ops.locksMu.Lock()
	defer ops.locksMu.Unlock()
	entry := ops.locks[zone]
	if entry == nil {
		t.Fatalf("zone lock %q is missing", zone)
	}
	if entry.refs != want {
		t.Fatalf("zone lock %q refs = %d, want %d", zone, entry.refs, want)
	}
}

func assertNoZoneLocks(t *testing.T, ops *Ops) {
	t.Helper()
	ops.locksMu.Lock()
	defer ops.locksMu.Unlock()
	if len(ops.locks) != 0 {
		t.Fatalf("zone lock registry contains %d idle entries", len(ops.locks))
	}
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel")
		var zero T
		return zero
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	receive(t, ch)
}

func assertPending[T any](t *testing.T, ch <-chan T) {
	t.Helper()
	select {
	case value := <-ch:
		t.Fatalf("operation completed before its blocker was released: %v", value)
	default:
	}
}

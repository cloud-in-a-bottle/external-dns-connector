package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/records"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
)

// zoneDiscoveryTimeout bounds the best-effort provider lookups behind the add-zone form. It is short
// on purpose: the page is useful without them, and unusable if it waits.
const zoneDiscoveryTimeout = 4 * time.Second

type zonesPage struct {
	page
	Zones        []store.Zone
	Accounts     []store.Account
	Discoverable []string
}

func (s *Server) handleZones(w http.ResponseWriter, r *http.Request) {
	zones, err := s.store.Zones()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	accounts, err := s.store.Accounts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	configured := map[string]bool{}
	for _, z := range zones {
		configured[z.Zone] = true
	}
	discoverable := s.discoverZones(r.Context(), accounts, configured)

	s.render(w, "zones", zonesPage{
		page:         newPage(r, "Zones", "home"),
		Zones:        zones,
		Accounts:     accounts,
		Discoverable: discoverable,
	})
}

func (s *Server) handleZoneAdd(w http.ResponseWriter, r *http.Request) {
	accountID, err := strconv.ParseInt(r.FormValue("account_id"), 10, 64)
	if err != nil {
		redirectErr(w, r, "/", fmt.Errorf("pick a provider account"))
		return
	}
	zone := records.NormalizeZone(r.FormValue("zone"))
	if zone == "" {
		redirectErr(w, r, "/", errors.New("zone name is required"))
		return
	}

	if err := s.ops.AddZone(r.Context(), store.ZoneBinding{Zone: zone, AccountID: accountID}); err != nil {
		redirectErr(w, r, "/", err)
		return
	}
	s.store.Audit("owner", "", "zone_add", zone, nil, nil)
	redirectOK(w, r, "/", "Added "+zone)
}

func (s *Server) handleZoneDelete(w http.ResponseWriter, r *http.Request) {
	zone := records.NormalizeZone(r.FormValue("zone"))
	if err := s.ops.DeleteZone(r.Context(), zone); err != nil {
		redirectErr(w, r, "/", err)
		return
	}
	s.store.Audit("owner", "", "zone_remove", zone, nil, nil)
	redirectOK(w, r, "/", "Removed "+zone)
}

type replaceZonesRequest struct {
	Zones []store.ZoneBinding `json:"zones"`
}

type replaceZonesResponse struct {
	Zones []string `json:"zones"`
}

// handleZonesReplace is the single route that sets the zone set. It is owner-only by construction:
// ownerOnly rejects anything carrying a consumer identity, and the service API exposes no
// zone-mutating operation at all, so no permission grant can reach this.
func (s *Server) handleZonesReplace(w http.ResponseWriter, r *http.Request) {
	var req replaceZonesRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "invalid JSON body: must contain exactly one JSON value", http.StatusBadRequest)
		return
	}
	if req.Zones == nil {
		http.Error(w, "invalid JSON body: zones must be present and non-null", http.StatusBadRequest)
		return
	}
	for _, b := range req.Zones {
		if _, err := s.store.Account(b.AccountID); err != nil {
			http.Error(w, fmt.Sprintf("zone %q names unknown account %d", b.Zone, b.AccountID), http.StatusBadRequest)
			return
		}
	}
	if err := s.ops.ReplaceZones(r.Context(), req.Zones); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.store.Audit("owner", "", "zones_replace", "", req.Zones, nil)

	zones, err := s.store.Zones()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	names := make([]string, 0, len(zones))
	for _, z := range zones {
		names = append(names, z.Zone)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(replaceZonesResponse{Zones: names})
}

// discoverZones asks each provider which zones it can see, to prefill the add-zone form.
//
// Every lookup is a live call to a third-party API, so this is strictly best effort: the lookups run
// concurrently under a short shared deadline, and a provider that is slow, unreachable, holds stale
// credentials, or cannot list zones at all simply contributes nothing. Doing it serially and
// unbounded — as this first did — meant one unresponsive provider hung the whole page.
func (s *Server) discoverZones(
	ctx context.Context,
	accounts []store.Account,
	configured map[string]bool,
) []string {
	ctx, cancel := context.WithTimeout(ctx, zoneDiscoveryTimeout)
	defer cancel()

	results := make(chan zoneDiscoveryResult, len(accounts))
	for _, a := range accounts {
		go s.discoverAccountZones(ctx, a, results)
	}

	var found []string
	remaining := len(accounts)
collect:
	for remaining > 0 {
		select {
		case result := <-results:
			remaining--
			if result.err == nil {
				found = append(found, result.zones...)
			}
		case <-ctx.Done():
			break collect
		}
	}

	seen := map[string]bool{}
	var out []string
	for _, z := range found {
		if !configured[z] && !seen[z] {
			seen[z] = true
			out = append(out, z)
		}
	}
	sort.Strings(out)
	return out
}

type zoneDiscoveryResult struct {
	zones []string
	err   error
}

func (s *Server) discoverAccountZones(
	ctx context.Context,
	account store.Account,
	results chan<- zoneDiscoveryResult,
) {
	zones, err := s.listProviderZones(ctx, account)
	// The channel has room for every worker, so a provider that ignores cancellation can finish late
	// without blocking after the page has already returned.
	results <- zoneDiscoveryResult{zones: zones, err: err}
}

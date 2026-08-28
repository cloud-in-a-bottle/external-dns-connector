package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/libdns/libdns"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/auth"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsops"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/grants"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/records"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
)

type API struct {
	store *store.Store
	ops   *dnsops.Ops
}

func New(s *store.Store, ops *dnsops.Ops) *API {
	return &API{store: s, ops: ops}
}

// Handler mounts the service routes. Everything here is reachable only through the router's service
// proxy: requireConsumer rejects anything without a router-injected consumer identity, which is what
// keeps provider credentials and zone-binding mutations outside any grant's reach.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /zones", a.requireConsumer(a.handleZones))
	mux.Handle("POST /records/get", a.requireConsumer(a.handleGet))
	mux.Handle("POST /records/set", a.requireConsumer(a.write(dnsops.OpSet)))
	mux.Handle("POST /records/append", a.requireConsumer(a.write(dnsops.OpAppend)))
	mux.Handle("POST /records/delete", a.requireConsumer(a.write(dnsops.OpDelete)))
	return mux
}

type consumerHandler func(http.ResponseWriter, *http.Request, auth.Caller)

func (a *API) requireConsumer(h consumerHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := auth.Classify(r)
		if !caller.IsConsumer() {
			// An owner session reaching here means someone browsed to a service path directly. These
			// routes act on behalf of a calling app and have no meaning without one.
			writeError(w, http.StatusForbidden, "not_a_service_call",
				"this endpoint is only reachable through the OpenHost service proxy")
			return
		}
		h(w, r, caller)
	})
}

// ─── zones ───

type zonesResponse struct {
	Zones []string `json:"zones"`
}

func (a *API) handleZones(w http.ResponseWriter, r *http.Request, caller auth.Caller) {
	// Which domains the owner runs is not something an app with no DNS access should learn. Returning
	// an empty list avoids both that disclosure and a permission response asking for broad access.
	if caller.Grants.Empty() {
		writeJSON(w, http.StatusOK, zonesResponse{Zones: []string{}})
		return
	}
	zones, err := a.store.Zones()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	names := make([]string, 0, len(zones))
	for _, z := range zones {
		names = append(names, z.Zone)
	}
	writeJSON(w, http.StatusOK, zonesResponse{Zones: names})
}

// ─── reads ───

type getRequest struct {
	Zone string `json:"zone"`
	Name string `json:"name"`
	Type string `json:"type"`
}

func (a *API) handleGet(w http.ResponseWriter, r *http.Request, caller auth.Caller) {
	var req getRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	// Reads default to every zone: a consumer is filtered to its own grants anyway, so the broad
	// default costs it nothing and saves it from having to know the owner's domain names.
	zone := req.Zone
	if strings.TrimSpace(zone) == "" {
		zone = dnsops.AllZones
	}
	// An app with no grants can read nothing, so resolving the zone first would only tell it which
	// zones exist.
	if caller.Grants.Empty() {
		writeResults(w, nil)
		return
	}
	zones, err := a.ops.ResolveZones(zone)
	if err != nil {
		writeZoneError(w, err)
		return
	}

	nameFilter := strings.ToLower(strings.TrimSpace(req.Name))
	typeFilter := strings.ToUpper(strings.TrimSpace(req.Type))

	results := make([]dnsops.ZoneResult, 0, len(zones))
	for _, z := range zones {
		recs, err := a.ops.Get(r.Context(), z)
		if err != nil {
			results = append(results, dnsops.ZoneResult{Zone: z.Zone, OK: false, Error: err.Error()})
			continue
		}
		visible := []records.Wire{}
		for _, rec := range recs {
			wire := records.FromLibDNS(rec)
			if nameFilter != "" && wire.Name != nameFilter {
				continue
			}
			if typeFilter != "" && wire.Type != typeFilter {
				continue
			}
			if !caller.Grants.CanRead(wire.Name, wire.Type) {
				continue
			}
			visible = append(visible, wire)
		}
		results = append(results, dnsops.ZoneResult{Zone: z.Zone, OK: true, Records: visible})
	}
	writeResults(w, results)
}

// ─── writes ───

type writeRequest struct {
	Zone    string          `json:"zone"`
	Records []recordRequest `json:"records"`
}

type recordRequest struct {
	Name string          `json:"name"`
	Type string          `json:"type"`
	TTL  requestTTL      `json:"ttl"`
	Data json.RawMessage `json:"data,omitempty"`
}

type requestTTL struct {
	raw json.RawMessage
}

func (t *requestTTL) UnmarshalJSON(data []byte) error {
	t.raw = append(t.raw[:0], data...)
	return nil
}

func (t requestTTL) MarshalJSON() ([]byte, error) {
	if t.raw == nil {
		return []byte("null"), nil
	}
	return t.raw, nil
}

func (t requestTTL) seconds(required bool) (int64, error) {
	if t.raw == nil {
		if required {
			return 0, fmt.Errorf("must be explicitly present")
		}
		return records.MinTTLSeconds, nil
	}
	var seconds *int64
	if err := json.Unmarshal(t.raw, &seconds); err != nil || seconds == nil {
		return 0, fmt.Errorf("must be a non-null integer")
	}
	if *seconds < records.MinTTLSeconds || *seconds > records.MaxTTLSeconds {
		return 0, fmt.Errorf(
			"must be between %d and %d seconds",
			records.MinTTLSeconds,
			records.MaxTTLSeconds,
		)
	}
	return *seconds, nil
}

func (r recordRequest) toWire(op dnsops.WriteOp) (records.Wire, bool, error) {
	ttl, err := r.TTL.seconds(op != dnsops.OpDelete)
	if err != nil {
		return records.Wire{}, false, fmt.Errorf("record %s/%s ttl %w", r.Name, r.Type, err)
	}
	wire := records.Wire{Name: r.Name, Type: r.Type, TTL: ttl}
	if r.Data == nil {
		return wire, false, nil
	}

	var data *string
	if err := json.Unmarshal(r.Data, &data); err != nil || data == nil {
		return records.Wire{}, true, fmt.Errorf("record %s/%s data must be a non-null string", r.Name, r.Type)
	}
	wire.Data = *data
	return wire, true, nil
}

func (a *API) write(op dnsops.WriteOp) consumerHandler {
	return func(w http.ResponseWriter, r *http.Request, caller auth.Caller) {
		var req writeRequest
		if err := decode(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		// Unlike reads, a missing zone on a write is an error rather than a fan-out. Defaulting to
		// every zone would let a caller that forgot the field rewrite records across all of them.
		if strings.TrimSpace(req.Zone) == "" {
			writeError(w, http.StatusBadRequest, "zone_required",
				fmt.Sprintf("writes must name a zone, or %q for all configured zones", dnsops.AllZones))
			return
		}
		if len(req.Records) == 0 {
			writeError(w, http.StatusBadRequest, "invalid_request", "no records given")
			return
		}
		// Authorize before resolving the zone. Doing it the other way round would let an app with no
		// grants learn which zones the owner has configured by reading the error it gets back.
		// Authorizing the whole batch up front also means a partially-permitted request fails
		// outright rather than applying its permitted half and then erroring.
		for _, rec := range req.Records {
			if _, err := rec.TTL.seconds(op != dnsops.OpDelete); err != nil {
				writeError(w, http.StatusBadRequest, "invalid_record",
					fmt.Sprintf("record %s/%s ttl %s", rec.Name, rec.Type, err))
				return
			}
			name, err := records.NormalizeName(rec.Name, "")
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_record", err.Error())
				return
			}
			rrtype, err := records.NormalizeType(rec.Type)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_record", err.Error())
				return
			}
			if !caller.Grants.CanWrite(name, rrtype) {
				writeRequiredGrant(w, grants.Grant{Name: name, Type: rrtype, Access: grants.AccessWrite})
				return
			}
		}

		zones, err := a.ops.ResolveZones(req.Zone)
		if err != nil {
			writeZoneError(w, err)
			return
		}
		if len(zones) == 0 {
			writeError(w, http.StatusBadRequest, "no_zones_configured",
				"no DNS zones are configured; the owner must add one first")
			return
		}

		// Parse for every target zone before writing to any of them. The zone-relative name check is
		// zone-dependent, so a fan-out could otherwise accept a name for one zone and reject it for
		// another, leaving the write half-applied across the owner's domains.
		parsed := make(map[string]batch, len(zones))
		for _, z := range zones {
			b, err := parseBatch(req.Records, z.Zone, op)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_record", err.Error())
				return
			}
			parsed[z.Zone] = b
		}

		results := make([]dnsops.ZoneResult, 0, len(zones))
		for _, z := range zones {
			b := parsed[z.Zone]
			var (
				applied []libdns.Record
				err     error
			)
			if op == dnsops.OpDelete {
				applied, err = a.ops.Delete(r.Context(), z, b.exact, b.clears)
			} else {
				applied, err = a.ops.Write(r.Context(), z, op, b.exact)
			}
			if err != nil {
				results = append(results, dnsops.ZoneResult{Zone: z.Zone, OK: false, Error: err.Error()})
				continue
			}
			results = append(results, dnsops.ZoneResult{
				Zone: z.Zone, OK: true, Records: records.FromLibDNSAll(applied),
			})
		}
		a.audit(caller, string(op), req.Zone, req.Records, results)
		writeResults(w, results)
	}
}

// batch is one request's records resolved against one zone. On a delete, a record given without
// data selects the whole (name, type) RRset instead of one exact record.
type batch struct {
	exact  []libdns.Record
	clears []records.RRset
}

func parseBatch(requests []recordRequest, zone string, op dnsops.WriteOp) (batch, error) {
	var b batch
	for _, request := range requests {
		wire, dataPresent, err := request.toWire(op)
		if err != nil {
			return batch{}, err
		}
		// Omitting data means "whatever is there now", which only makes sense when removing records.
		// A set or append with no data is a mistake, not a wildcard.
		if !dataPresent && op == dnsops.OpDelete {
			set, err := wire.ToRRset(zone)
			if err != nil {
				return batch{}, err
			}
			b.clears = append(b.clears, set)
			continue
		}
		rec, err := wire.ToLibDNS(zone)
		if err != nil {
			return batch{}, err
		}
		b.exact = append(b.exact, rec)
	}
	return b, nil
}

func (a *API) audit(caller auth.Caller, op, zone string, detail any, results []dnsops.ZoneResult) {
	var failures []string
	for _, r := range results {
		if !r.OK {
			failures = append(failures, r.Zone+": "+r.Error)
		}
	}
	var err error
	if len(failures) > 0 {
		err = errors.New(strings.Join(failures, "; "))
	}
	a.store.Audit(caller.Actor(), caller.ConsumerID, op, zone, detail, err)
}

// ─── responses ───

type resultsResponse struct {
	OK      bool                `json:"ok"`
	Results []dnsops.ZoneResult `json:"results"`
}

// writeResults reports per-zone outcomes with a status that reflects the whole: 200 when every zone
// succeeded, 207 when some did, 502 when none did. A blanket 200 would let a caller treat a total
// provider outage as success.
func writeResults(w http.ResponseWriter, results []dnsops.ZoneResult) {
	if results == nil {
		results = []dnsops.ZoneResult{}
	}
	ok := 0
	for i, r := range results {
		if r.OK {
			ok++
		}
		if r.Records == nil {
			results[i].Records = []records.Wire{}
		}
	}
	status := http.StatusOK
	switch {
	case len(results) == 0:
		status = http.StatusOK
	case ok == 0:
		status = http.StatusBadGateway
	case ok < len(results):
		status = http.StatusMultiStatus
	}
	writeJSON(w, status, resultsResponse{OK: ok == len(results), Results: results})
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type requiredGrant struct {
	Grant grants.Grant `json:"grant"`
	Scope string       `json:"scope"`
}

type permissionRequiredResponse struct {
	Error         string        `json:"error"`
	Message       string        `json:"message"`
	RequiredGrant requiredGrant `json:"required_grant"`
}

// writeRequiredGrant returns the 403 shape the router understands. For a global-scoped grant the
// router rewrites the response to add a grant_url pointing at its own owner-facing approval page, so
// the consumer can hand the user off and retry.
func writeRequiredGrant(w http.ResponseWriter, g grants.Grant) {
	writeJSON(w, http.StatusForbidden, permissionRequiredResponse{
		Error:         "permission_required",
		Message:       fmt.Sprintf("this app has no grant covering %s records named %q", g.Type, g.Name),
		RequiredGrant: requiredGrant{Grant: g, Scope: "global"},
	})
}

func writeZoneError(w http.ResponseWriter, err error) {
	if errors.Is(err, dnsops.ErrUnknownZone) {
		writeError(w, http.StatusBadRequest, "unknown_zone", err.Error())
		return
	}
	writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: code, Message: message})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func decode(w http.ResponseWriter, r *http.Request, into any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid JSON body: must contain exactly one JSON value")
	}
	return nil
}

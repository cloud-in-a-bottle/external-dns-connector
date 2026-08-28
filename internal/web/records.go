package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/libdns/libdns"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsops"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/records"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
)

type recordRow struct {
	records.Wire
	// Writable is false for record types this connector will not change. Reads pass through whatever
	// the provider returns, so a zone can contain types the editor deliberately leaves alone.
	Writable bool
}

type recordsPage struct {
	page
	Zone          store.Zone
	Records       []recordRow
	Types         []string
	WritableTypes string
}

func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	zone, err := s.store.Zone(r.PathValue("zone"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	recs, err := s.ops.Get(r.Context(), zone)
	if err != nil {
		redirectErr(w, r, "/", err)
		return
	}
	rows := make([]recordRow, 0, len(recs))
	for _, rec := range recs {
		wire := records.FromLibDNS(rec)
		rows = append(rows, recordRow{Wire: wire, Writable: records.WritableTypes[wire.Type]})
	}
	types := records.SortedWritableTypes()
	s.render(w, "records", recordsPage{
		page:          newPage(r, zone.Zone, "home"),
		Zone:          zone,
		Records:       rows,
		Types:         types,
		WritableTypes: strings.Join(types, ", "),
	})
}

func (s *Server) handleRecordAdd(w http.ResponseWriter, r *http.Request) {
	zone, err := s.store.Zone(r.PathValue("zone"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	dest := "/zones/" + zone.Zone

	rec, err := formRecord(r, zone.Zone)
	if err != nil {
		redirectErr(w, r, dest, err)
		return
	}
	// Append rather than set: the editor adds one record at a time, and SetRecords would silently
	// drop the other members of that name's RRset.
	if _, err := s.ops.Write(r.Context(), zone, dnsops.OpAppend, []libdns.Record{rec}); err != nil {
		s.store.Audit("owner", "", "append", zone.Zone, rec.RR(), err)
		redirectErr(w, r, dest, err)
		return
	}
	s.store.Audit("owner", "", "append", zone.Zone, rec.RR(), nil)
	redirectOK(w, r, dest, "Added "+rec.RR().Name+" "+rec.RR().Type)
}

func (s *Server) handleRecordDelete(w http.ResponseWriter, r *http.Request) {
	zone, err := s.store.Zone(r.PathValue("zone"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	dest := "/zones/" + zone.Zone

	rec, err := formRecord(r, zone.Zone)
	if err != nil {
		redirectErr(w, r, dest, err)
		return
	}
	deleted, err := s.ops.Write(r.Context(), zone, dnsops.OpDelete, []libdns.Record{rec})
	if err != nil {
		s.store.Audit("owner", "", "delete", zone.Zone, rec.RR(), err)
		redirectErr(w, r, dest, err)
		return
	}
	if len(deleted) == 0 {
		// libdns silently ignores a delete that matches nothing; saying so beats a success message
		// for an operation that did not happen.
		err := errors.New("no matching record was found, so nothing was deleted")
		s.store.Audit("owner", "", "delete", zone.Zone, rec.RR(), err)
		redirectErr(w, r, dest, err)
		return
	}
	s.store.Audit("owner", "", "delete", zone.Zone, rec.RR(), nil)
	redirectOK(w, r, dest, "Deleted "+rec.RR().Name+" "+rec.RR().Type)
}

func formRecord(r *http.Request, zone string) (libdns.Record, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	ttl, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("ttl")), 10, 64)
	if err != nil {
		return nil, errors.New("TTL must be a whole number of seconds")
	}
	wire := records.Wire{
		Name: r.FormValue("name"),
		Type: r.FormValue("type"),
		TTL:  ttl,
		Data: strings.TrimSpace(r.FormValue("data")),
	}
	return wire.ToLibDNS(zone)
}

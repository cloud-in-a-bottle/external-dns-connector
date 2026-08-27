package records

import (
	"fmt"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// Wire is the record shape the service API and the owner UI both speak. It maps one-to-one onto
// libdns.RR, so no record type needs its own request schema.
type Wire struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  int    `json:"ttl"`
	Data string `json:"data"`
}

// ToLibDNS validates a wire record and converts it to the concrete libdns type for its RR type.
// Providers expect typed records (libdns.Address, libdns.TXT, ...) rather than the opaque RR.
func (w Wire) ToLibDNS(zone string) (libdns.Record, error) {
	name, err := NormalizeName(w.Name, zone)
	if err != nil {
		return nil, err
	}
	rrtype, err := NormalizeType(w.Type)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(w.Data) == "" {
		return nil, fmt.Errorf("record %s/%s has empty data", name, rrtype)
	}
	if w.TTL < 0 {
		return nil, fmt.Errorf("record %s/%s has a negative ttl", name, rrtype)
	}
	rr := libdns.RR{
		Name: name,
		Type: rrtype,
		TTL:  time.Duration(w.TTL) * time.Second,
		Data: w.Data,
	}
	rec, err := rr.Parse()
	if err != nil {
		return nil, fmt.Errorf("record %s/%s has invalid data %q: %w", name, rrtype, w.Data, err)
	}
	// Parsing can quietly change the type: libdns.Address derives A vs AAAA from the address family,
	// so an "A" record carrying an IPv6 literal comes back out as AAAA. Since callers are authorized
	// against the type they asked for, a record that changed type here would be written under a type
	// the caller may not hold a grant for. Reject rather than reinterpret.
	if got := strings.ToUpper(rec.RR().Type); got != rrtype {
		return nil, fmt.Errorf("record %s/%s has data %q that is not valid for a %s record (it parses as %s)",
			name, rrtype, w.Data, rrtype, got)
	}
	return rec, nil
}

// RRset names every record sharing a name and type. Deleting one is how a caller clears a name
// without knowing what is currently there — an ACME solver cleaning up after a run that crashed
// before it recorded the token it wrote cannot delete by exact value.
type RRset struct {
	Name string
	Type string
}

// ToRRset validates a wire record as an RRset selector. Only the name and type are meaningful; the
// TTL and data are ignored, since the point is to match whatever happens to be there.
func (w Wire) ToRRset(zone string) (RRset, error) {
	name, err := NormalizeName(w.Name, zone)
	if err != nil {
		return RRset{}, err
	}
	rrtype, err := NormalizeType(w.Type)
	if err != nil {
		return RRset{}, err
	}
	return RRset{Name: name, Type: rrtype}, nil
}

// Matches reports whether a record belongs to this RRset.
func (r RRset) Matches(rec libdns.Record) bool {
	rr := rec.RR()
	name := rr.Name
	if name == "" {
		name = Apex
	}
	return strings.EqualFold(name, r.Name) && strings.EqualFold(rr.Type, r.Type)
}

// FromLibDNS reduces any libdns record to the wire shape.
func FromLibDNS(rec libdns.Record) Wire {
	rr := rec.RR()
	name := rr.Name
	if name == "" {
		name = Apex
	}
	return Wire{
		Name: strings.ToLower(name),
		Type: strings.ToUpper(rr.Type),
		TTL:  int(rr.TTL / time.Second),
		Data: rr.Data,
	}
}

func FromLibDNSAll(recs []libdns.Record) []Wire {
	out := make([]Wire, 0, len(recs))
	for _, r := range recs {
		out = append(out, FromLibDNS(r))
	}
	return out
}

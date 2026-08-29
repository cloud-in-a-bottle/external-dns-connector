package grants

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/records"
)

type Access string

const (
	// AccessRead permits reading matching records. AccessWrite permits reading and changing them —
	// spelled "rw" so that the read half is visible in the grant rather than implied.
	AccessRead  Access = "r"
	AccessWrite Access = "rw"
)

// Grant is one permission entry as it appears in a consumer app's manifest. Zones are deliberately
// absent: a grant applies to matching records in every configured zone. Only the owner can change
// zone bindings. A consumer with a valid nonempty grant can list configured zone names; one without
// a grant receives an empty list.
type Grant struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Access Access `json:"access"`
}

func (g Grant) Validate() error {
	_, err := g.normalized()
	return err
}

func (g Grant) normalized() (Grant, error) {
	name, err := normalizeNamePattern(g.Name)
	if err != nil {
		return Grant{}, err
	}
	rrtype, err := normalizeTypePattern(g.Type)
	if err != nil {
		return Grant{}, err
	}
	if g.Access != AccessRead && g.Access != AccessWrite {
		return Grant{}, fmt.Errorf(
			"grant has invalid access %q (want %q or %q)",
			g.Access,
			AccessRead,
			AccessWrite,
		)
	}
	return Grant{Name: name, Type: rrtype, Access: g.Access}, nil
}

func normalizeNamePattern(pattern string) (string, error) {
	if pattern == "" {
		return "", fmt.Errorf("grant is missing \"name\"")
	}
	if pattern != strings.TrimSpace(pattern) {
		return "", fmt.Errorf("grant name %q has surrounding whitespace", pattern)
	}
	const wildcardPlaceholder = "grant-wildcard"
	candidate := strings.ReplaceAll(pattern, Wildcard, wildcardPlaceholder)
	if _, err := records.NormalizeName(candidate, ""); err != nil {
		return "", fmt.Errorf("grant has invalid name pattern %q: %w", pattern, err)
	}
	return strings.ToLower(pattern), nil
}

func normalizeTypePattern(pattern string) (string, error) {
	if pattern == Wildcard {
		return Wildcard, nil
	}
	if pattern == "" {
		return "", fmt.Errorf("grant is missing \"type\"")
	}
	for index, char := range []byte(pattern) {
		letter := (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z')
		if !letter && (index == 0 || char < '0' || char > '9') {
			return "", fmt.Errorf("grant has invalid record type pattern %q", pattern)
		}
	}
	return strings.ToUpper(pattern), nil
}

func (g Grant) matches(name, rrtype string) bool {
	return Match(g.Name, name) && Match(g.Type, rrtype)
}

func (g Grant) String() string {
	return fmt.Sprintf("%s %s %s", g.Access, g.Type, g.Name)
}

// Set is the collection of grants the router says apply to the calling app.
type Set []Grant

func (s Set) Empty() bool { return len(s) == 0 }

func (s Set) CanRead(name, rrtype string) bool {
	for _, g := range s {
		if g.matches(name, rrtype) {
			return true
		}
	}
	return false
}

func (s Set) CanWrite(name, rrtype string) bool {
	for _, g := range s {
		if g.Access == AccessWrite && g.matches(name, rrtype) {
			return true
		}
	}
	return false
}

// routerGrant is one entry of the X-OpenHost-Permissions array the router injects.
type routerGrant struct {
	Grant json.RawMessage `json:"grant"`
	Scope string          `json:"scope"`
}

// Parse reads the X-OpenHost-Permissions header.
//
// Only scope "global" is honored. This service defines grants that are independent of any provider's
// own data — they name a record pattern, not a zone — which is exactly what global scope is for, and
// it means an owner can approve them at install time from the consumer's manifest.
//
// Malformed entries are skipped rather than failing the request: the header is router-authored, and a
// single unparseable grant should narrow access, never widen it or break an otherwise valid call.
func Parse(header string) Set {
	if strings.TrimSpace(header) == "" {
		return nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal([]byte(header), &entries); err != nil {
		return nil
	}
	out := Set{}
	for _, raw := range entries {
		e, err := decodeRouterGrant(raw)
		if err != nil {
			continue
		}
		if e.Scope != "global" {
			continue
		}
		g, err := decodeGrant(e.Grant)
		if err != nil {
			continue
		}
		normalized, err := g.normalized()
		if err != nil {
			continue
		}
		out = append(out, normalized)
	}
	return out
}

func decodeRouterGrant(raw json.RawMessage) (routerGrant, error) {
	var entry routerGrant
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entry); err != nil {
		return routerGrant{}, err
	}
	return entry, nil
}

func decodeGrant(raw json.RawMessage) (Grant, error) {
	var grant Grant
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&grant); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

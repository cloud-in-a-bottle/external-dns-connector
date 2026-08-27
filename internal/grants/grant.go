package grants

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Access string

const (
	// AccessRead permits reading matching records. AccessWrite permits reading and changing them —
	// spelled "rw" so that the read half is visible in the grant rather than implied.
	AccessRead  Access = "r"
	AccessWrite Access = "rw"
)

// Grant is one permission entry as it appears in a consumer app's manifest. Zones are deliberately
// absent: which zones exist is owner-only configuration that no consumer can see or influence.
type Grant struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Access Access `json:"access"`
}

func (g Grant) Validate() error {
	if strings.TrimSpace(g.Name) == "" {
		return fmt.Errorf("grant is missing \"name\"")
	}
	if strings.TrimSpace(g.Type) == "" {
		return fmt.Errorf("grant is missing \"type\"")
	}
	if g.Access != AccessRead && g.Access != AccessWrite {
		return fmt.Errorf("grant has invalid access %q (want %q or %q)", g.Access, AccessRead, AccessWrite)
	}
	return nil
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
	var entries []routerGrant
	if err := json.Unmarshal([]byte(header), &entries); err != nil {
		return nil
	}
	out := Set{}
	for _, e := range entries {
		if e.Scope != "global" {
			continue
		}
		var g Grant
		if err := json.Unmarshal(e.Grant, &g); err != nil {
			continue
		}
		if g.Validate() != nil {
			continue
		}
		out = append(out, Grant{Name: strings.ToLower(g.Name), Type: strings.ToUpper(g.Type), Access: g.Access})
	}
	return out
}

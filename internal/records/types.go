package records

import (
	"fmt"
	"sort"
	"strings"
)

// WritableTypes is the allowlist for record types this connector will create, change, or delete.
// It covers the basics plus everything a mail setup needs: MX for delivery, TXT for SPF/DKIM/DMARC,
// SRV for autodiscover/autoconfig, and CNAME for delegated DKIM selectors.
//
// Reads are not restricted — whatever a provider returns is passed through — so an owner can still
// see record types the service API refuses to write.
var WritableTypes = map[string]bool{
	"A":     true,
	"AAAA":  true,
	"CAA":   true,
	"CNAME": true,
	"MX":    true,
	"NS":    true,
	"SRV":   true,
	"TXT":   true,
}

// NormalizeType uppercases an RR type and checks it against the write allowlist.
func NormalizeType(rrtype string) (string, error) {
	t := strings.ToUpper(strings.TrimSpace(rrtype))
	if t == "" {
		return "", fmt.Errorf("record type is empty")
	}
	if !WritableTypes[t] {
		return "", fmt.Errorf("record type %q is not writable (supported: %s)", t, strings.Join(SortedWritableTypes(), ", "))
	}
	return t, nil
}

func SortedWritableTypes() []string {
	out := make([]string, 0, len(WritableTypes))
	for t := range WritableTypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

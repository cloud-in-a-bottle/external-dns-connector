package records

import (
	"fmt"
	"strings"
)

// Apex is the zone-relative name of the zone itself, matching libdns's convention.
const Apex = "@"

// NormalizeZone lowercases a zone and strips the trailing dot, giving the form used as a
// primary key in the store and in the service API. libdns.Zone carries the trailing dot;
// everything on our side does not.
func NormalizeZone(zone string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
}

// NormalizeName validates and canonicalizes a zone-relative record name.
//
// Fully-qualified input is rejected rather than fixed up: libdns reads "www.example.com" inside zone
// "example.com" as "www.example.com.example.com", so silently accepting it would point a record at a
// name the caller did not intend.
func NormalizeName(name, zone string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return "", fmt.Errorf("record name is empty (use %q for the zone apex)", Apex)
	}
	if n == Apex {
		return Apex, nil
	}
	if strings.HasSuffix(n, ".") {
		return "", fmt.Errorf("record name %q is fully qualified; names are relative to the zone (use %q for the apex)", name, Apex)
	}
	if z := NormalizeZone(zone); z != "" && (n == z || strings.HasSuffix(n, "."+z)) {
		return "", fmt.Errorf("record name %q already includes the zone %q; names are relative (did you mean %q?)",
			name, z, strings.TrimSuffix(strings.TrimSuffix(n, z), "."))
	}
	for _, label := range strings.Split(n, ".") {
		if err := validateLabel(label, name); err != nil {
			return "", err
		}
	}
	return n, nil
}

func validateLabel(label, fullName string) error {
	if label == "" {
		return fmt.Errorf("record name %q has an empty label", fullName)
	}
	if len(label) > 63 {
		return fmt.Errorf("record name %q has a label longer than 63 characters", fullName)
	}
	// "*" is a real DNS wildcard label and stays literal here; the grant matcher treats it the same way.
	if label == "*" {
		return nil
	}
	for _, c := range label {
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return fmt.Errorf("record name %q contains an invalid character %q", fullName, c)
		}
	}
	return nil
}

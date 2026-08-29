package records

import (
	"math"
	"strings"
	"testing"
)

func TestNormalizeName(t *testing.T) {
	const zone = "example.com"
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"www", "www", false},
		{"WWW", "www", false},
		{"  www  ", "www", false},
		{"@", "@", false},
		{"sub.dept", "sub.dept", false},
		{"_acme-challenge.www", "_acme-challenge.www", false},
		{"*", "*", false},
		{"*.app", "*.app", false},

		{"", "", true},
		{"www.", "", true},            // fully qualified
		{"www.example.com", "", true}, // would resolve to www.example.com.example.com
		{"example.com", "", true},
		{"WWW.EXAMPLE.COM", "", true},
		{"a..b", "", true},
		{"bad!label", "", true},
		{"-bad", "", true},
		{"bad-", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeName(c.in, zone)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeName(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeName(%q) errored: %v", c.in, err)
		} else if got != c.want {
			t.Errorf("NormalizeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeZone(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":   "example.com",
		"example.com.":  "example.com",
		"EXAMPLE.COM.":  "example.com",
		" example.com ": "example.com",
	} {
		if got := NormalizeZone(in); got != want {
			t.Errorf("NormalizeZone(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateZone(t *testing.T) {
	maxLength := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 61),
	}, ".")
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "ordinary", input: "example.com", want: "example.com"},
		{name: "one trailing dot", input: "Example.COM.", want: "example.com"},
		{name: "surrounding whitespace", input: "  Example.COM.  ", want: "example.com"},
		{name: "punycode", input: "XN--BCHER-KVA.Example", want: "xn--bcher-kva.example"},
		{name: "interior hyphens", input: "some-zone.example", want: "some-zone.example"},
		{name: "maximum name length", input: maxLength, want: maxLength},
		{name: "empty", input: "", wantErr: true},
		{name: "root", input: ".", wantErr: true},
		{name: "empty interior label", input: "a..example", wantErr: true},
		{name: "multiple trailing dots", input: "example.com..", wantErr: true},
		{name: "reserved wildcard", input: "*", wantErr: true},
		{name: "wildcard label", input: "*.example.com", wantErr: true},
		{name: "underscore", input: "bad_name.example", wantErr: true},
		{name: "non ASCII", input: "b\u00fccher.example", wantErr: true},
		{name: "leading hyphen", input: "-bad.example", wantErr: true},
		{name: "trailing hyphen", input: "bad-.example", wantErr: true},
		{name: "overlong label", input: strings.Repeat("a", 64) + ".example", wantErr: true},
		{name: "overlong name", input: maxLength + "a", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateZone(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ValidateZone(%q) = %q, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateZone(%q): %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("ValidateZone(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeType(t *testing.T) {
	for _, ok := range []string{"a", "A", "aaaa", "TXT", "mx", "ns", "srv", "caa", "cname"} {
		if _, err := NormalizeType(ok); err != nil {
			t.Errorf("NormalizeType(%q) errored: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "SOA", "DNSKEY", "HTTPS", "nonsense"} {
		if _, err := NormalizeType(bad); err == nil {
			t.Errorf("NormalizeType(%q) should be rejected for writes", bad)
		}
	}
}

func TestWireRoundTrip(t *testing.T) {
	const zone = "example.com"
	cases := []Wire{
		{Name: "www", Type: "A", TTL: 300, Data: "192.0.2.1"},
		{Name: "www", Type: "AAAA", TTL: 300, Data: "2001:db8::1"},
		{Name: "@", Type: "MX", TTL: 3600, Data: "10 mail.example.com."},
		{Name: "@", Type: "TXT", TTL: 60, Data: "v=spf1 -all"},
		{Name: "_dmarc", Type: "TXT", TTL: 60, Data: "v=DMARC1; p=reject"},
		{Name: "@", Type: "NS", TTL: 86400, Data: "ns1.example.net."},
		{Name: "mail", Type: "CNAME", TTL: 300, Data: "ghs.example.net."},
		{Name: "_autodiscover._tcp", Type: "SRV", TTL: 300, Data: "10 5 443 mail.example.com."},
		{Name: "@", Type: "CAA", TTL: 300, Data: `0 issue "letsencrypt.org"`},
	}
	for _, w := range cases {
		rec, err := w.ToLibDNS(zone)
		if err != nil {
			t.Errorf("ToLibDNS(%+v) errored: %v", w, err)
			continue
		}
		got := FromLibDNS(rec)
		if got.Name != w.Name || got.Type != w.Type || got.TTL != w.TTL {
			t.Errorf("round trip of %+v gave %+v", w, got)
		}
	}
}

func TestWireRejectsBadRecords(t *testing.T) {
	const zone = "example.com"
	cases := map[string]Wire{
		"empty data":          {Name: "www", Type: "A", TTL: 300, Data: ""},
		"bad ip":              {Name: "www", Type: "A", TTL: 300, Data: "not-an-ip"},
		"ipv6 in an A record": {Name: "www", Type: "A", TTL: 300, Data: "2001:db8::1"},
		"zero ttl":            {Name: "www", Type: "A", TTL: 0, Data: "192.0.2.1"},
		"negative ttl":        {Name: "www", Type: "A", TTL: -1, Data: "192.0.2.1"},
		"below minimum ttl":   {Name: "www", Type: "A", TTL: 59, Data: "192.0.2.1"},
		"ttl above maximum":   {Name: "www", Type: "A", TTL: MaxTTLSeconds + 1, Data: "192.0.2.1"},
		"duration overflow":   {Name: "www", Type: "A", TTL: math.MaxInt64, Data: "192.0.2.1"},
		"unwritable type":     {Name: "www", Type: "SOA", TTL: 300, Data: "ns1. root. 1 2 3 4 5"},
		"fqdn name":           {Name: "www.example.com", Type: "A", TTL: 300, Data: "192.0.2.1"},
		"malformed mx":        {Name: "@", Type: "MX", TTL: 300, Data: "mail.example.com."},
		"rewritten SRV name": {
			Name: "sip.tcp", Type: "SRV", TTL: 300, Data: "10 5 5060 sip.example.com.",
		},
	}
	for name, w := range cases {
		if _, err := w.ToLibDNS(zone); err == nil {
			t.Errorf("%s: ToLibDNS(%+v) should have failed", name, w)
		}
	}
}

func TestWireAcceptsTTLBounds(t *testing.T) {
	if MaxTTLSeconds != 2147483647 {
		t.Fatalf("MaxTTLSeconds = %d, want Hetzner maximum 2147483647", MaxTTLSeconds)
	}
	for _, ttl := range []int64{MinTTLSeconds, MaxTTLSeconds} {
		wire := Wire{Name: "www", Type: "A", TTL: ttl, Data: "192.0.2.1"}
		if _, err := wire.ToLibDNS("example.com"); err != nil {
			t.Errorf("ToLibDNS rejected TTL %d: %v", ttl, err)
		}
	}
}

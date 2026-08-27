package records

import "testing"

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
		"negative ttl":        {Name: "www", Type: "A", TTL: -1, Data: "192.0.2.1"},
		"unwritable type":     {Name: "www", Type: "SOA", TTL: 300, Data: "ns1. root. 1 2 3 4 5"},
		"fqdn name":           {Name: "www.example.com", Type: "A", TTL: 300, Data: "192.0.2.1"},
		"malformed mx":        {Name: "@", Type: "MX", TTL: 300, Data: "mail.example.com."},
	}
	for name, w := range cases {
		if _, err := w.ToLibDNS(zone); err == nil {
			t.Errorf("%s: ToLibDNS(%+v) should have failed", name, w)
		}
	}
}

package grants

import (
	"strings"
	"testing"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern string
		value   string
		want    bool
	}{
		// Exact names.
		{"home", "home", true},
		{"home", "HOME", true},
		{"home", "home2", false},
		{"home", "a.home", false},
		{"home", "hom", false},

		// "**" matches any run of characters, including none.
		{"**", "home", true},
		{"**", "@", true},
		{"**", "a.b.c", true},
		{"**", "*", true},
		{"**", "", true},

		// A single "*" stays literal: it is a real DNS wildcard label, not a metacharacter.
		{"*.app", "*.app", true},
		{"*.app", "x.app", false},
		{"*", "*", true},
		{"*", "www", false},
		{"*", "", false},

		// Prefix patterns.
		{"_acme-challenge.**", "_acme-challenge.a", true},
		{"_acme-challenge.**", "_acme-challenge.a.b", true},
		{"_acme-challenge.**", "_acme-challenge.", true},
		{"_acme-challenge.**", "_acme-challenge", false},
		{"_acme-challenge.**", "other.a", false},
		{"_acme-challenge.**", "x._acme-challenge.a", false},

		// Suffix patterns.
		{"**.app", "x.app", true},
		{"**.app", "a.b.app", true},
		{"**.app", ".app", true},
		{"**.app", "app", false},
		{"**.app", "x.apple", false},

		// Interior segments must appear in order and must not have to overlap.
		{"a**b", "ab", true},
		{"a**b", "axxb", true},
		{"a**b", "a", false},
		{"a**a", "a", false},
		{"a**a", "aa", true},
		{"**x**", "axb", true},
		{"**x**", "ab", false},
		{"a**b**c", "a1b2c", true},
		{"a**b**c", "a1c2b", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.value); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}

func TestSetAuthorization(t *testing.T) {
	acme := Grant{Name: "_acme-challenge.**", Type: "TXT", Access: AccessWrite}
	readAll := Grant{Name: "**", Type: "**", Access: AccessRead}

	cases := []struct {
		name             string
		set              Set
		recName, recType string
		wantRead         bool
		wantWrite        bool
	}{
		{"write grant covers read", Set{acme}, "_acme-challenge.www", "TXT", true, true},
		{"wrong type", Set{acme}, "_acme-challenge.www", "A", false, false},
		{"wrong name", Set{acme}, "home", "TXT", false, false},
		{"read grant does not permit write", Set{readAll}, "home", "A", true, false},
		{"read-all matches every type", Set{readAll}, "@", "MX", true, false},
		{"empty set permits nothing", Set{}, "home", "A", false, false},
		{"union of grants", Set{acme, readAll}, "home", "A", true, false},
		{"union still writes the covered one", Set{acme, readAll}, "_acme-challenge.a", "TXT", true, true},
		{"type matching is case-insensitive", Set{acme}, "_acme-challenge.a", "txt", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.set.CanRead(c.recName, c.recType); got != c.wantRead {
				t.Errorf("CanRead(%q, %q) = %v, want %v", c.recName, c.recType, got, c.wantRead)
			}
			if got := c.set.CanWrite(c.recName, c.recType); got != c.wantWrite {
				t.Errorf("CanWrite(%q, %q) = %v, want %v", c.recName, c.recType, got, c.wantWrite)
			}
		})
	}
}

func TestParseOnlyHonorsGlobalScope(t *testing.T) {
	header := `[
	  {"grant": {"name": "home", "type": "A", "access": "rw"}, "scope": "global"},
	  {"grant": {"name": "**", "type": "**", "access": "rw"}, "scope": "app"},
	  {"grant": {"name": "bad", "type": "A", "access": "write"}, "scope": "global"},
	  {"grant": {"name": "", "type": "A", "access": "r"}, "scope": "global"},
	  {"grant": "not-an-object", "scope": "global"}
	]`
	got := Parse(header)
	if len(got) != 1 {
		t.Fatalf("Parse kept %d grants (%v), want only the one valid global grant", len(got), got)
	}
	if got[0] != (Grant{Name: "home", Type: "A", Access: AccessWrite}) {
		t.Errorf("Parse returned %+v", got[0])
	}
	// The app-scoped write-all entry must not have leaked through.
	if got.CanWrite("anything", "TXT") {
		t.Error("an app-scoped grant was honored; only global scope should be")
	}
}

func TestParseDegradesToNoAccess(t *testing.T) {
	for _, header := range []string{"", "   ", "[]", "not json", "{}", "null"} {
		if got := Parse(header); !got.Empty() {
			t.Errorf("Parse(%q) = %v, want empty", header, got)
		}
	}
}

func TestGrantValidate(t *testing.T) {
	tests := []struct {
		name    string
		grant   Grant
		wantErr bool
	}{
		{name: "exact", grant: Grant{Name: "home", Type: "A", Access: AccessRead}},
		{name: "lowercase type", grant: Grant{Name: "HOME", Type: "txt", Access: AccessWrite}},
		{name: "generic type token", grant: Grant{Name: "@", Type: "TYPE65", Access: AccessRead}},
		{name: "all wildcard", grant: Grant{Name: "**", Type: "**", Access: AccessRead}},
		{
			name:  "name wildcard fragments",
			grant: Grant{Name: "_acme-**.service", Type: "TXT", Access: AccessWrite},
		},
		{
			name:  "literal wildcard labels",
			grant: Grant{Name: "*.app.*", Type: "CNAME", Access: AccessWrite},
		},
		{name: "missing name", grant: Grant{Type: "A", Access: AccessRead}, wantErr: true},
		{name: "name whitespace", grant: Grant{Name: " home", Type: "A", Access: AccessRead}, wantErr: true},
		{name: "empty name label", grant: Grant{Name: "bad..name", Type: "A", Access: AccessRead}, wantErr: true},
		{name: "qualified name", grant: Grant{Name: "name.", Type: "A", Access: AccessRead}, wantErr: true},
		{
			name: "invalid name character", grant: Grant{Name: "bad!name", Type: "A", Access: AccessRead},
			wantErr: true,
		},
		{
			name: "embedded single star", grant: Grant{Name: "bad*name", Type: "A", Access: AccessRead},
			wantErr: true,
		},
		{name: "three stars", grant: Grant{Name: "***", Type: "A", Access: AccessRead}, wantErr: true},
		{name: "leading hyphen", grant: Grant{Name: "-bad", Type: "A", Access: AccessRead}, wantErr: true},
		{name: "trailing hyphen", grant: Grant{Name: "bad-", Type: "A", Access: AccessRead}, wantErr: true},
		{
			name: "overlong name label",
			grant: Grant{
				Name: strings.Repeat("a", 64), Type: "A", Access: AccessRead,
			},
			wantErr: true,
		},
		{name: "missing type", grant: Grant{Name: "home", Access: AccessRead}, wantErr: true},
		{name: "single type star", grant: Grant{Name: "home", Type: "*", Access: AccessRead}, wantErr: true},
		{name: "type wildcard suffix", grant: Grant{Name: "home", Type: "A**", Access: AccessRead}, wantErr: true},
		{name: "type wildcard prefix", grant: Grant{Name: "home", Type: "**A", Access: AccessRead}, wantErr: true},
		{name: "numeric type", grant: Grant{Name: "home", Type: "65", Access: AccessRead}, wantErr: true},
		{name: "type punctuation", grant: Grant{Name: "home", Type: "A-B", Access: AccessRead}, wantErr: true},
		{name: "type whitespace", grant: Grant{Name: "home", Type: " A", Access: AccessRead}, wantErr: true},
		{name: "invalid access", grant: Grant{Name: "home", Type: "A", Access: "write"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.grant.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate accepted invalid grant")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate rejected valid grant: %v", err)
			}
		})
	}
}

func TestParseRejectsUnknownFieldsPerEntry(t *testing.T) {
	header := `[
  {"grant":{"name":"home","type":"txt","access":"rw"},"scope":"global"},
  {"grant":{"name":"**","type":"**","access":"rw"},"scope":"global","extra":true},
  {"grant":{"name":"**","type":"**","access":"rw","extra":true},"scope":"global"}
]`
	got := Parse(header)
	if len(got) != 1 {
		t.Fatalf("Parse kept %d grants (%v), want only the strict valid entry", len(got), got)
	}
	want := Grant{Name: "home", Type: "TXT", Access: AccessWrite}
	if got[0] != want {
		t.Fatalf("Parse returned %+v, want %+v", got[0], want)
	}
	if got.CanWrite("other", "A") {
		t.Fatal("an entry with an unknown field widened access")
	}
}

func TestParseSkipsMalformedPatternsWithoutDroppingValidEntries(t *testing.T) {
	header := `[
  {"grant":{"name":"allowed","type":"A","access":"r"},"scope":"global"},
  {"grant":{"name":"**","type":"A**","access":"rw"},"scope":"global"},
  {"grant":{"name":"bad*name","type":"A","access":"rw"},"scope":"global"},
  {"grant":{"name":"**","type":"**","access":"write"},"scope":"global"}
]`
	got := Parse(header)
	if len(got) != 1 || !got.CanRead("allowed", "A") {
		t.Fatalf("valid narrow grant was not retained: %v", got)
	}
	if got.CanWrite("allowed", "A") || got.CanRead("anything", "TXT") {
		t.Fatalf("malformed entries widened access: %v", got)
	}
}

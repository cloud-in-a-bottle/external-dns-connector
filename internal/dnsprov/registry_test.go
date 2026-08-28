package dnsprov

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestFieldKeysReachTheProviderStruct guards the one thing the registry can silently get wrong: a
// credential key that does not correspond to a real field on the provider's struct. json.Unmarshal
// ignores unknown keys, so a typo would store an owner's API token into nothing and fail only at the
// first real API call, with an error pointing at the credentials rather than at us.
//
// This checks the property through encoding/json itself rather than by walking struct tags with
// reflection, because Go's own promotion rules for embedded structs decide the actual wire shape.
func TestFieldKeysReachTheProviderStruct(t *testing.T) {
	for _, e := range All() {
		t.Run(e.Key, func(t *testing.T) {
			values := map[string]string{}
			for i, f := range e.Fields {
				values[f.Key] = sentinel(i)
			}
			creds, err := e.CredentialsFromForm(values, nil)
			if err != nil {
				t.Fatalf("CredentialsFromForm: %v", err)
			}
			p, err := e.New(Deps{}, creds)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			// Re-marshalling the populated provider shows which keys the struct actually accepted.
			roundTripped, err := json.Marshal(p)
			if err != nil {
				t.Fatalf("marshal provider: %v", err)
			}
			for i, f := range e.Fields {
				if !strings.Contains(string(roundTripped), sentinel(i)) {
					t.Errorf("field %q never reached the provider struct (check the json tag); got %s",
						f.Key, roundTripped)
				}
			}
		})
	}
}

func sentinel(i int) string { return "sentinel-value-" + string(rune('a'+i)) }

func TestProductionProvidersArePinnedAndImplementSemanticInterfaces(t *testing.T) {
	want := map[string]string{
		"route53": "https://github.com/libdns/route53/blob/" +
			"840c6120709b2f9da6d74dc5d562e2625334aecc/provider.go",
		"hetzner": "https://github.com/libdns/hetzner/blob/" +
			"36dd896cea1474c0cbb7a6a9bf6dbc0f14a0c178/provider.go",
	}
	if got := len(All()); got != len(want) {
		t.Fatalf("expected exactly %d production providers, got %d", len(want), got)
	}

	for _, e := range All() {
		source, ok := want[e.Key]
		if !ok {
			t.Errorf("unexpected production provider %q", e.Key)
			continue
		}
		delete(want, e.Key)
		if e.SourceURL != source {
			t.Errorf("%s: source URL = %q, want exact pinned source %q", e.Key, e.SourceURL, source)
		}
		p, err := e.New(Deps{}, nil)
		if err != nil {
			t.Fatalf("%s: New(nil) errored: %v", e.Key, err)
		}
		if c := CapabilitiesOf(p); !c.Get || !c.Set || !c.Delete {
			t.Errorf("%s: missing an interface required by semantic mutations: %+v", e.Key, c)
		}
	}
	for key := range want {
		t.Errorf("production provider %q is not registered", key)
	}
}

func TestMockIsLookupableButHidden(t *testing.T) {
	e, err := Lookup(MockKey)
	if err != nil {
		t.Fatalf("Lookup(%q): %v", MockKey, err)
	}
	if !e.Hidden {
		t.Error("mock registry entry must be hidden from production provider lists")
	}
	for _, production := range All() {
		if production.Key == MockKey {
			t.Error("mock appeared in the production provider list")
		}
	}
	p, err := e.New(Deps{}, nil)
	if err != nil {
		t.Fatalf("build mock: %v", err)
	}
	if c := CapabilitiesOf(p); !c.Get || !c.Set || !c.Delete {
		t.Errorf("mock is missing an interface required by semantic mutations: %+v", c)
	}
}

func TestEveryProviderHasAtLeastOneRequiredCredential(t *testing.T) {
	for _, e := range All() {
		hasRequired := false
		for _, f := range e.Fields {
			if f.Required {
				hasRequired = true
			}
		}
		if !hasRequired {
			t.Errorf("%s has no required credential field, so an empty form would be accepted", e.Key)
		}
	}
}

func TestCredentialsFromFormKeepsExistingSecretWhenBlank(t *testing.T) {
	e, err := Lookup("hetzner")
	if err != nil {
		t.Fatal(err)
	}
	creds, err := e.CredentialsFromForm(
		map[string]string{"api_token": ""},
		json.RawMessage(`{"api_token":"kept"}`),
	)
	if err != nil {
		t.Fatalf("a blank secret with a stored value should be retained, not rejected: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(creds, &got); err != nil {
		t.Fatal(err)
	}
	if got["api_token"] != "kept" {
		t.Errorf("got %q, want the previously stored token", got["api_token"])
	}

	if _, err := e.CredentialsFromForm(map[string]string{"api_token": ""}, nil); err == nil {
		t.Error("a blank required secret with nothing stored should be rejected")
	}
}

func TestRedactedHidesSecretsButNotPublicFields(t *testing.T) {
	e, err := Lookup("route53")
	if err != nil {
		t.Fatal(err)
	}
	got := e.Redacted(json.RawMessage(
		`{"access_key_id":"AKID","secret_access_key":"SEC","region":"us-east-1"}`,
	))
	if strings.Contains(got["secret_access_key"], "SEC") || strings.Contains(got["access_key_id"], "AKID") {
		t.Errorf("secrets leaked into the redacted view: %v", got)
	}
	if got["region"] != "us-east-1" {
		t.Errorf("public field should survive redaction, got %q", got["region"])
	}
}

func TestLookupRejectsUnknownProvider(t *testing.T) {
	if _, err := Lookup("not-a-provider"); err == nil {
		t.Error("Lookup should reject an unknown provider key")
	}
}

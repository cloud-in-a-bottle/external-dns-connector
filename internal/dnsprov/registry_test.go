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
	providers := All()
	if len(providers) != 1 {
		t.Fatalf("expected Hetzner to be the only production provider, got %+v", providers)
	}
	e := providers[0]
	if e.Key != "hetzner" {
		t.Fatalf("production provider = %q, want hetzner", e.Key)
	}
	wantSource := "https://github.com/libdns/hetzner/blob/" +
		"36dd896cea1474c0cbb7a6a9bf6dbc0f14a0c178/provider.go"
	if e.SourceURL != wantSource {
		t.Errorf("source URL = %q, want exact pinned source %q", e.SourceURL, wantSource)
	}
	p, err := e.New(Deps{}, nil)
	if err != nil {
		t.Fatalf("New(nil): %v", err)
	}
	if c := CapabilitiesOf(p); !c.Get || !c.Append || !c.Set || !c.Delete {
		t.Errorf("Hetzner is missing an interface required by semantic mutations: %+v", c)
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
	if c := CapabilitiesOf(p); !c.Get || !c.Append || !c.Set || !c.Delete {
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
	e := Entry{Fields: []Field{
		{Key: "token", Secret: true},
		{Key: "region"},
	}}
	got := e.Redacted(json.RawMessage(
		`{"token":"SEC","region":"eu-central"}`,
	))
	if strings.Contains(got["token"], "SEC") {
		t.Errorf("secrets leaked into the redacted view: %v", got)
	}
	if got["region"] != "eu-central" {
		t.Errorf("public field should survive redaction, got %q", got["region"])
	}
}

func TestLookupRejectsUnknownProvider(t *testing.T) {
	for _, key := range []string{"route53", "not-a-provider"} {
		if _, err := Lookup(key); err == nil {
			t.Errorf("Lookup should reject unsupported provider %q", key)
		}
	}
}

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
// reflection, because Go's own promotion rules for embedded structs are what actually decide the
// wire shape (libdns/alidns embeds its CredentialInfo, so its keys are flat, not nested).
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

// TestEveryProviderImplementsTheCoreInterfaces checks that each registered provider can actually do
// what the service API asks of it, rather than failing at runtime with a confusing "unsupported".
func TestEveryProviderImplementsTheCoreInterfaces(t *testing.T) {
	real := 0
	for _, e := range All() {
		if e.Key != MockKey {
			real++
		}
	}
	if real != 20 {
		t.Errorf("expected 20 real providers registered, got %d", real)
	}
	for _, e := range All() {
		p, err := e.New(Deps{}, nil)
		if err != nil {
			t.Fatalf("%s: New(nil) errored: %v", e.Key, err)
		}
		if c := CapabilitiesOf(p); !c.Get || !c.Append || !c.Set || !c.Delete {
			t.Errorf("%s: missing a core interface: %+v", e.Key, c)
		}
	}
}

func TestEveryProviderHasAtLeastOneRequiredCredential(t *testing.T) {
	for _, e := range All() {
		if e.Key == MockKey {
			continue // the mock genuinely needs no credentials
		}
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
	e, err := Lookup("cloudflare")
	if err != nil {
		t.Fatal(err)
	}
	creds, err := e.CredentialsFromForm(map[string]string{"api_token": ""}, json.RawMessage(`{"api_token":"kept"}`))
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
	got := e.Redacted(json.RawMessage(`{"access_key_id":"AKID","secret_access_key":"SEC","region":"us-east-1"}`))
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

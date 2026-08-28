package dnsprov

import (
	"encoding/json"

	"github.com/libdns/hetzner/v2"
)

// unmarshalInto builds the New function for a provider whose credentials are just the JSON form of
// its libdns Provider struct — which is every provider here.
func unmarshalInto[T any]() func(Deps, json.RawMessage) (any, error) {
	return func(_ Deps, creds json.RawMessage) (any, error) {
		p := new(T)
		if len(creds) > 0 {
			if err := json.Unmarshal(creds, p); err != nil {
				return nil, err
			}
		}
		return p, nil
	}
}

func secret(key, label, help string) Field {
	return Field{Key: key, Label: label, Required: true, Secret: true, Help: help}
}

func init() {
	register(Entry{
		Key: "hetzner", Label: "Hetzner",
		DocURL:    "https://docs.hetzner.cloud/#getting-started",
		SourceURL: "https://github.com/libdns/hetzner/blob/36dd896cea1474c0cbb7a6a9bf6dbc0f14a0c178/provider.go",
		Fields:    []Field{secret("api_token", "API token", "")},
		New:       unmarshalInto[hetzner.Provider](),
	})
}

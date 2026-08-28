package dnsprov

import (
	"encoding/json"

	"github.com/libdns/hetzner/v2"
	"github.com/libdns/route53"
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

func public(key, label, help string) Field {
	return Field{Key: key, Label: label, Secret: false, Help: help}
}

func init() {
	register(Entry{
		Key: "route53", Label: "AWS Route 53",
		DocURL: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/" +
			"access-control-managing-permissions.html",
		SourceURL: "https://github.com/libdns/route53/blob/840c6120709b2f9da6d74dc5d562e2625334aecc/provider.go",
		Fields: []Field{
			secret("access_key_id", "Access key ID", ""),
			secret("secret_access_key", "Secret access key", ""),
			public("region", "Region", "Defaults to the AWS_REGION environment variable if blank."),
			Field{
				Key: "session_token", Label: "Session token", Secret: true,
				Help: "Only for temporary STS credentials.",
			},
			public("hosted_zone_id", "Hosted zone ID", "Optional; pins operations to one hosted zone."),
		},
		New: unmarshalInto[route53.Provider](),
	})

	register(Entry{
		Key: "hetzner", Label: "Hetzner",
		DocURL:    "https://docs.hetzner.cloud/#getting-started",
		SourceURL: "https://github.com/libdns/hetzner/blob/36dd896cea1474c0cbb7a6a9bf6dbc0f14a0c178/provider.go",
		Fields:    []Field{secret("api_token", "API token", "")},
		New:       unmarshalInto[hetzner.Provider](),
	})
}

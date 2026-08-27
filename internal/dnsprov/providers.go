package dnsprov

import (
	"encoding/json"

	"github.com/libdns/alidns"
	"github.com/libdns/bunny"
	"github.com/libdns/cloudflare"
	"github.com/libdns/desec"
	"github.com/libdns/digitalocean"
	"github.com/libdns/dnsimple"
	"github.com/libdns/gandi"
	"github.com/libdns/godaddy"
	"github.com/libdns/googleclouddns"
	"github.com/libdns/hetzner/v2"
	"github.com/libdns/inwx"
	"github.com/libdns/linode"
	"github.com/libdns/luadns"
	"github.com/libdns/namecheap"
	"github.com/libdns/netlify"
	"github.com/libdns/ovh"
	"github.com/libdns/porkbun"
	"github.com/libdns/route53"
	"github.com/libdns/scaleway"
	"github.com/libdns/vultr/v2"
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
		Key: "cloudflare", Label: "Cloudflare",
		DocURL: "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
		Fields: []Field{
			secret("api_token", "API token", "Scoped API token with Zone.DNS:Edit. Use a token, not the global API key."),
			Field{Key: "zone_token", Label: "Zone token", Secret: true,
				Help: "Optional Zone:Read token, needed only when the API token above is scoped to a single zone."},
		},
		New: unmarshalInto[cloudflare.Provider](),
	})

	register(Entry{
		Key: "route53", Label: "AWS Route 53",
		DocURL: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/access-control-managing-permissions.html",
		Fields: []Field{
			secret("access_key_id", "Access key ID", ""),
			secret("secret_access_key", "Secret access key", ""),
			public("region", "Region", "Defaults to the AWS_REGION environment variable if blank."),
			Field{Key: "session_token", Label: "Session token", Secret: true, Help: "Only for temporary STS credentials."},
			public("hosted_zone_id", "Hosted zone ID", "Optional; pins operations to one hosted zone."),
		},
		New: unmarshalInto[route53.Provider](),
	})

	register(Entry{
		Key: "digitalocean", Label: "DigitalOcean",
		DocURL: "https://docs.digitalocean.com/reference/api/create-personal-access-token/",
		Fields: []Field{secret("auth_token", "API token", "Personal access token with write scope.")},
		New:    unmarshalInto[digitalocean.Provider](),
	})

	register(Entry{
		Key: "googleclouddns", Label: "Google Cloud DNS",
		DocURL: "https://cloud.google.com/dns/docs/reference/v1",
		Fields: []Field{
			public("gcp_project", "Project ID", ""),
			secret("gcp_application_default", "Service account JSON", "Path to the service account key file, or the key JSON itself."),
		},
		New: unmarshalInto[googleclouddns.Provider](),
	})

	register(Entry{
		Key: "namecheap", Label: "Namecheap",
		DocURL: "https://www.namecheap.com/support/api/intro/",
		Fields: []Field{
			secret("api_key", "API key", ""),
			public("user", "API user", "Your Namecheap username."),
			public("client_ip", "Client IP", "The IP allowlisted in your Namecheap API settings."),
			public("api_endpoint", "API endpoint", "Leave blank for production; set for the sandbox."),
		},
		New: unmarshalInto[namecheap.Provider](),
	})

	register(Entry{
		Key: "godaddy", Label: "GoDaddy",
		DocURL: "https://developer.godaddy.com/keys",
		Fields: []Field{secret("api_token", "API token", `Formatted as "KEY:SECRET".`)},
		New:    unmarshalInto[godaddy.Provider](),
	})

	register(Entry{
		Key: "gandi", Label: "Gandi",
		DocURL: "https://api.gandi.net/docs/authentication/",
		Fields: []Field{secret("bearer_token", "Personal access token", "")},
		New:    unmarshalInto[gandi.Provider](),
	})

	register(Entry{
		Key: "hetzner", Label: "Hetzner",
		DocURL: "https://docs.hetzner.cloud/#getting-started",
		Fields: []Field{secret("api_token", "API token", "")},
		New:    unmarshalInto[hetzner.Provider](),
	})

	register(Entry{
		Key: "vultr", Label: "Vultr",
		DocURL: "https://www.vultr.com/api/",
		Fields: []Field{secret("api_token", "API key", "")},
		New:    unmarshalInto[vultr.Provider](),
	})

	register(Entry{
		Key: "linode", Label: "Linode",
		DocURL: "https://techdocs.akamai.com/linode-api/reference/get-started",
		Fields: []Field{
			secret("api_token", "API token", "Personal access token with read/write on Domains."),
			public("api_version", "API version", "Optional; defaults to v4."),
		},
		New: unmarshalInto[linode.Provider](),
	})

	register(Entry{
		Key: "dnsimple", Label: "DNSimple",
		DocURL: "https://developer.dnsimple.com/v2/",
		Fields: []Field{
			secret("api_access_token", "API access token", ""),
			public("account_id", "Account ID", "Optional; looked up from the token if blank."),
			public("api_url", "API URL", "Optional; set for the sandbox environment."),
		},
		New: unmarshalInto[dnsimple.Provider](),
	})

	register(Entry{
		Key: "porkbun", Label: "Porkbun",
		DocURL: "https://porkbun.com/api/json/v3/documentation",
		Fields: []Field{
			secret("api_key", "API key", ""),
			secret("api_secret_key", "Secret API key", ""),
		},
		New: unmarshalInto[porkbun.Provider](),
	})

	register(Entry{
		Key: "ovh", Label: "OVH",
		DocURL: "https://api.ovh.com/createToken/",
		Fields: []Field{
			public("endpoint", "Endpoint", `Region endpoint, eg "ovh-eu" or "ovh-us".`),
			secret("application_key", "Application key", ""),
			secret("application_secret", "Application secret", ""),
			secret("consumer_key", "Consumer key", ""),
		},
		New: unmarshalInto[ovh.Provider](),
	})

	register(Entry{
		Key: "netlify", Label: "Netlify",
		DocURL: "https://docs.netlify.com/api/get-started/",
		Fields: []Field{secret("personal_access_token", "Personal access token", "")},
		New:    unmarshalInto[netlify.Provider](),
	})

	register(Entry{
		Key: "desec", Label: "deSEC",
		DocURL: "https://desec.readthedocs.io/en/latest/auth/tokens.html",
		Fields: []Field{secret("token", "API token", "")},
		New:    unmarshalInto[desec.Provider](),
	})

	register(Entry{
		Key: "alidns", Label: "Alibaba Cloud DNS",
		DocURL: "https://www.alibabacloud.com/help/en/alidns/",
		Fields: []Field{
			secret("access_key_id", "Access key ID", ""),
			secret("access_key_secret", "Access key secret", ""),
			public("region_id", "Region ID", "Optional; defaults to cn-hangzhou."),
		},
		New: unmarshalInto[alidns.Provider](),
	})

	register(Entry{
		Key: "bunny", Label: "Bunny.net",
		DocURL: "https://docs.bunny.net/reference/bunnynet-api-overview",
		Fields: []Field{secret("access_key", "API access key", "")},
		New:    unmarshalInto[bunny.Provider](),
	})

	register(Entry{
		Key: "luadns", Label: "LuaDNS",
		DocURL: "https://www.luadns.com/api.html",
		Fields: []Field{
			public("email", "Account email", ""),
			secret("api_key", "API key", ""),
		},
		New: unmarshalInto[luadns.Provider](),
	})

	register(Entry{
		Key: "inwx", Label: "INWX",
		DocURL: "https://www.inwx.de/en/help/apidoc",
		Fields: []Field{
			public("username", "Username", ""),
			secret("password", "Password", ""),
			Field{Key: "shared_secret", Label: "Shared secret", Secret: true, Help: "Only if two-factor auth is enabled."},
			public("endpoint_url", "Endpoint URL", "Optional; set for the OT&E test environment."),
		},
		New: unmarshalInto[inwx.Provider](),
	})

	register(Entry{
		Key: "scaleway", Label: "Scaleway",
		DocURL: "https://www.scaleway.com/en/docs/iam/how-to/create-api-keys/",
		Fields: []Field{
			secret("secret_key", "Secret key", ""),
			public("organization_id", "Organization ID", ""),
		},
		New: unmarshalInto[scaleway.Provider](),
	})
}

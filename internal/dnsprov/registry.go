package dnsprov

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/libdns/libdns"
)

// Field describes one credential input for a provider. Key is the JSON key on that provider's libdns
// Provider struct, so the stored blob is always valid JSON for the struct it is unmarshalled into.
type Field struct {
	Key      string
	Label    string
	Required bool
	// Secret fields are masked in the UI and never sent back to the browser. The default is secret;
	// a field is only marked public when it plainly is (a region, an account id, an endpoint URL).
	Secret bool
	Help   string
}

// Deps are runtime dependencies a provider needs beyond its credentials. Only the built-in mock uses
// them; every real provider talks to its own remote API.
type Deps struct {
	DB *sql.DB
}

// Entry is one supported DNS provider.
type Entry struct {
	Key       string
	Label     string
	DocURL    string
	SourceURL string
	Fields    []Field
	Hidden    bool
	// New builds a libdns provider from the stored credentials blob. It returns `any` because each
	// provider implements a different subset of the libdns interfaces; use Capabilities to see which.
	New func(deps Deps, creds json.RawMessage) (any, error)
}

// Capabilities reports which libdns interfaces a built provider implements. Not every provider can
// list zones, so the UI asks for zone names by hand in that case rather than failing.
type Capabilities struct {
	Get    bool
	Append bool
	Set    bool
	Delete bool
	List   bool
}

func CapabilitiesOf(p any) Capabilities {
	var c Capabilities
	_, c.Get = p.(libdns.RecordGetter)
	_, c.Append = p.(libdns.RecordAppender)
	_, c.Set = p.(libdns.RecordSetter)
	_, c.Delete = p.(libdns.RecordDeleter)
	_, c.List = p.(libdns.ZoneLister)
	return c
}

var registry = map[string]Entry{}

func register(e Entry) {
	if _, dup := registry[e.Key]; dup {
		panic("duplicate provider registration: " + e.Key)
	}
	registry[e.Key] = e
}

func Lookup(key string) (Entry, error) {
	e, ok := registry[strings.ToLower(strings.TrimSpace(key))]
	if !ok {
		return Entry{}, fmt.Errorf("unknown DNS provider %q", key)
	}
	return e, nil
}

// All returns the production providers available in the owner UI, sorted by display label.
func All() []Entry {
	out := make([]Entry, 0, len(registry))
	for _, e := range registry {
		if e.Hidden {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// Build constructs the libdns provider for an account's stored credentials.
func Build(deps Deps, providerKey string, creds json.RawMessage) (any, error) {
	e, err := Lookup(providerKey)
	if err != nil {
		return nil, err
	}
	p, err := e.New(deps, creds)
	if err != nil {
		return nil, fmt.Errorf("configure %s provider: %w", e.Label, err)
	}
	return p, nil
}

// CredentialsFromForm turns form values keyed by Field.Key into the JSON the provider struct expects,
// checking that required fields are present.
//
// A blank value for an already-stored secret means "leave it alone", so an owner can edit a
// non-secret field without re-typing their API token; `existing` supplies the retained value.
func (e Entry) CredentialsFromForm(
	values map[string]string, existing json.RawMessage,
) (json.RawMessage, error) {
	prev := map[string]any{}
	if len(existing) > 0 {
		_ = json.Unmarshal(existing, &prev)
	}

	out := map[string]any{}
	for _, f := range e.Fields {
		v := strings.TrimSpace(values[f.Key])
		if v == "" {
			if kept, ok := prev[f.Key].(string); ok && kept != "" {
				out[f.Key] = kept
				continue
			}
			if f.Required {
				return nil, fmt.Errorf("%s is required", f.Label)
			}
			continue
		}
		out[f.Key] = v
	}
	return json.Marshal(out)
}

// Redacted returns the stored credentials with every secret field replaced by a placeholder, safe to
// render in the owner UI.
func (e Entry) Redacted(creds json.RawMessage) map[string]string {
	parsed := map[string]any{}
	if len(creds) > 0 {
		_ = json.Unmarshal(creds, &parsed)
	}
	out := map[string]string{}
	for _, f := range e.Fields {
		v, ok := parsed[f.Key].(string)
		switch {
		case !ok || v == "":
			out[f.Key] = ""
		case f.Secret:
			out[f.Key] = "••••••••"
		default:
			out[f.Key] = v
		}
	}
	return out
}

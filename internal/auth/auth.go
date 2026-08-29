package auth

import (
	"net/http"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/grants"
)

// The router is the sole authority for these headers: it strips every inbound X-OpenHost-* header
// before injecting its own (see _sanitize_forwarded_headers in the compute_space proxy helper), and
// app container ports are published on host loopback only, so no app can reach us directly to forge
// them.
const (
	HeaderIsOwner      = "X-OpenHost-Is-Owner"
	HeaderConsumerID   = "X-OpenHost-Consumer-Id"
	HeaderConsumerName = "X-OpenHost-Consumer-Name"
	HeaderPermissions  = "X-OpenHost-Permissions"
)

type Kind int

const (
	// Anonymous requests reached the container without going through the router's authenticated
	// paths — the health probe, essentially.
	Anonymous Kind = iota
	// Owner requests came through the router's owner-authenticated front door.
	Owner
	// Consumer requests came through the router's service proxy on behalf of another app.
	Consumer
)

type Caller struct {
	Kind         Kind
	ConsumerID   string
	ConsumerName string
	Grants       grants.Set
}

func (c Caller) IsOwner() bool    { return c.Kind == Owner }
func (c Caller) IsConsumer() bool { return c.Kind == Consumer }

// Actor labels the caller for the audit log.
func (c Caller) Actor() string {
	switch c.Kind {
	case Owner:
		return "owner"
	case Consumer:
		if c.ConsumerName != "" {
			return c.ConsumerName
		}
		return c.ConsumerID
	default:
		return "anonymous"
	}
}

// Classify determines who is calling from the router-injected headers.
//
// A consumer id takes precedence over the owner flag. A service call carries both when the owner's
// browser is what triggered it, and in that case the request must still be held to the calling app's
// grants — the owner being present does not widen what the app may do.
func Classify(r *http.Request) Caller {
	if id := r.Header.Get(HeaderConsumerID); id != "" {
		return Caller{
			Kind:         Consumer,
			ConsumerID:   id,
			ConsumerName: r.Header.Get(HeaderConsumerName),
			Grants:       grants.Parse(r.Header.Get(HeaderPermissions)),
		}
	}
	if r.Header.Get(HeaderIsOwner) == "true" {
		return Caller{Kind: Owner}
	}
	return Caller{Kind: Anonymous}
}

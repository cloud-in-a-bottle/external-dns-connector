# external-dns-connector

An OpenHost app that manages DNS records at external providers, and exposes them to other apps on
the space through the OpenHost service interface.

The point is the service API: an ACME solver, a dynamic-DNS updater, or a mail app can create and
update exactly the records it needs, scoped by record name and type, without ever being handed the
owner's registrar credentials. The owner-facing web UI configures providers and zones and can edit
records by hand.

Record operations go through [libdns](https://github.com/libdns/libdns). Production support is
limited to the exact adapter versions listed in [`docs/providers.md`](docs/providers.md), which are
pinned in `go.mod` and covered by this connector's behavior tests.

## Using the service from another app

Declare what you need in your `cloudinabottle.toml`. The owner approves these grants when they
install your app:

```toml
[[services.v2.consumes]]
service   = "github.com/cloud-in-a-bottle/external-dns-connector/services/dns"
shortname = "dns"
version   = ">=0.1.0"
grants    = [
  {name = "_acme-challenge.**", type = "TXT", access = "rw"},
]
```

Then call it through the router:

```bash
curl -X POST "$OPENHOST_ROUTER_URL/api/services/v2/call/dns/records/set" \
  -H "Authorization: Bearer $OPENHOST_APP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"zone": "example.com",
       "records": [{"name": "_acme-challenge.www", "type": "TXT", "ttl": 60, "data": "token"}]}'
```

### Grants

A grant is a record name pattern, a record type, and an access level:

| field    | meaning |
|----------|---------|
| `name`   | Matched against the **zone-relative** name (`@` is the apex). `**` matches any run of characters; a single `*` is **literal**, since it is a real DNS wildcard label. |
| `type`   | An uppercase RR type, or `**` for any. |
| `access` | `r` for read, `rw` for read and write. `rw` always includes read. |

Grants say nothing about zones — which zones exist is owner-only configuration that no grant can read
or change. "Read all" is `{name = "**", type = "**", access = "r"}`; "write all" is the same with
`rw`.

An app sees only the records its grants match: a read returns the matching records and silently omits
the rest, so a narrowly-scoped app sees a zone containing just its own records.

### Zones

Reads default to every configured zone. **Writes must name one** — either an exact zone or `"*"` to
apply the change to all of them. Omitting it is an error rather than a silent fan-out across every
domain the owner runs.

Since a write can fan out, responses report per zone, and the status reflects the whole: `200` when
every zone succeeded, `207` when some did, `502` when none did.

### Records

One flat shape covers every type, mirroring a zone file line:

```json
{"name": "www", "type": "A", "ttl": 300, "data": "192.0.2.1"}
```

`name` is relative to the zone — `www`, not `www.example.com`. `ttl` is in seconds. `data` is
unescaped zone-file RDATA, so `MX` is `"10 mail.example.com."` and `SRV` is
`"10 5 443 host.example.com."`.

Writable types: `A`, `AAAA`, `CAA`, `CNAME`, `MX`, `NS`, `SRV`, `TXT` — the basics plus what email
needs. Reads pass through whatever the provider returns.

### Clearing an RRset

On `records/delete`, omitting `data` clears the whole `(name, type)` RRset instead of matching one
exact record:

```json
{"zone": "example.com", "records": [{"name": "_acme-challenge", "type": "TXT"}]}
```

This is what an unconditional cleanup path needs — a process that died before recording the value it
wrote cannot delete by exact value. Clearing a name that holds nothing succeeds and reports nothing
deleted, so it is safe to call in a `finally` or on a retry. Grants are checked on `(name, type)`
either way.

For an exact delete, matching uses name, type, and data. TTL is ignored because DNS stores one TTL
for the entire RRset, not a separate TTL for each value.

The full spec is in [`services/dns/openapi.yaml`](services/dns/openapi.yaml).

## Development

```bash
just test-go   # Go unit and HTTP-level tests — fast, no podman needed
just test      # the above, then the containerized tests through a real router
just run       # run locally on http://localhost:8080 against ./local.db
just check     # gofmt, go vet, go build
```

`just test` builds the Dockerfile and runs the app under **podman** fronted by the real OpenHost
router, deploying real consumer apps to exercise the service proxy. `just setup` installs the Python
test dependencies and the playwright browser.

## Notes

- Provider credentials are stored as plaintext JSON in the app's private SQLite database. That is the
  same trust boundary as the app itself — anything that can read the database could equally read the
  process memory holding a decryption key — so this is stated plainly rather than dressed up.
  Switching to the OpenHost `secrets` service would move the boundary and is a reasonable change.
- Reads are cached per zone for 30 seconds and invalidated on write because provider APIs are
  rate-limited.
- Writes to a zone are serialized, so two apps doing read-modify-write on the same zone cannot
  interleave.

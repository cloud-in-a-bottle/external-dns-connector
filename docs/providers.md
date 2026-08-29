# Supported DNS providers

Production support is deliberately limited to the local semantic adapter and this exact API client:

- Provider: Hetzner
- Adapter: `internal/dnsprov/hetzner.go`
- Pinned API client: `github.com/hetznercloud/hcloud-go/v2 v2.27.0`
- Exact upstream release commit: [`7a591b7`][hcloud-source]

The adapter uses libdns interfaces and record types, but owns Hetzner conversion and mutation
semantics locally. It follows the DNS API implemented by the pinned hcloud release rather than
floating with either hcloud or the libdns provider catalog. The immutable link identifies the exact
`v2.27.0` hcloud release commit containing the RRset implementation.

Registry and adapter tests cover all five interfaces, paging, grouped actions, TXT conversion, and
non-destructive set sequencing. A built-in mock remains available to tests by registry key but is not
shown in the owner provider selector.

[hcloud-source]: https://github.com/hetznercloud/hcloud-go/commit/7a591b7c57103f451f85e797f8818b38f0c3d1aa

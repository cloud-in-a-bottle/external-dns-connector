# Supported DNS providers

Production support is deliberately limited to this exact libdns adapter version:

| Provider | Pinned module | Exact upstream source |
|----------|---------------|-----------------------|
| Hetzner | `github.com/libdns/hetzner/v2 v2.0.1` | [`36dd896`][hetzner-source] |

The version does not float with the upstream provider catalog. Registry tests verify the required
read, append, set, and delete interfaces, while connector tests exercise provider-independent RRset
mutation behavior. A built-in mock remains available to tests by registry key but is not shown in the
owner provider selector.

[hetzner-source]: https://github.com/libdns/hetzner/blob/36dd896cea1474c0cbb7a6a9bf6dbc0f14a0c178/provider.go

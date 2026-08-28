# Supported DNS providers

Production support is deliberately limited to these exact libdns adapter versions:

| Provider | Pinned module | Exact upstream source |
|----------|---------------|-----------------------|
| AWS Route 53 | `github.com/libdns/route53 v1.6.2` | [`840c612`][route53-source] |
| Hetzner | `github.com/libdns/hetzner/v2 v2.0.1` | [`36dd896`][hetzner-source] |

The versions do not float with the upstream provider catalog. Registry tests verify the required
read, set, and delete interfaces, while connector tests exercise provider-independent RRset mutation
behavior. A built-in mock remains available to tests by registry key but is not shown in the owner
provider selector.

[route53-source]: https://github.com/libdns/route53/blob/840c6120709b2f9da6d74dc5d562e2625334aecc/provider.go
[hetzner-source]: https://github.com/libdns/hetzner/blob/36dd896cea1474c0cbb7a6a9bf6dbc0f14a0c178/provider.go

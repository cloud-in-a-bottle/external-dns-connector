- read README.md and style_guide.md at the beginning of every session.
- this is an OpenHost app written in Go. `cloudinabottle.toml` is the app manifest (`openhost.toml`
  is the legacy alias for the same file).
- `just test-go` is the fast loop and needs nothing but Go. `just test` additionally builds the
  container and runs it under podman behind a real OpenHost router, which takes a couple of minutes.
- the app serves on port 8080 and exposes `/health`, which is the one route with no identity
  requirement — the router probes it directly on the container.

## how the two surfaces are kept apart

- `internal/auth` classifies every request from the headers the router injects. a request carrying
  `X-OpenHost-Consumer-Id` is a service call; `X-OpenHost-Is-Owner: true` without one is the owner.
- owner routes (`internal/web`) reject anything with a consumer identity. service routes
  (`internal/service`) reject anything without one. zone and credential configuration exists only on
  the owner side, which is what makes it unreachable by any permission grant — there is no service
  route that touches it.
- this rests on the router being the sole authority for `X-OpenHost-*` headers. it is:
  `_sanitize_forwarded_headers` in `compute_space/src/compute_space/web/helpers/proxy.py` strips all
  inbound ones before adding its own, and app ports are published on host loopback only. the
  exception is an app with `network_host = true`, which shares the host netns and can reach any app's
  port directly; that already defeats app isolation platform-wide and would need an upstream fix
  (a signed router→app header). don't work around it here.

## deploying & debugging on openhost

- there's context on openhost at `~/work/openhost`; read `docs/src/creating_an_app.md` and
  `docs/src/cross_app_services.md`.
- instances are managed via the `oh` cli. `oh instance list` shows them. the user will say which one
  to use; do not touch the others. most commands take `--instance <name>`.
- these instances face the public internet. be careful with anything that could open unsecured access
  — eg adding `public_paths` to the manifest. this app deliberately has none.
- typical deploy loop: commit + push, then `oh app reload <app> --update --wait --instance <name>`,
  then `oh app logs <app> --instance <name>`.

## gotchas worth remembering

- libdns provider module versions have nothing to do with the libdns version they target
  (`libdns/cloudflare` v0.2.2 requires libdns v1.1.0). several are `/v2` module paths. check
  `go.mod` at the tag before bumping.
- `libdns.RR.Parse()` derives A vs AAAA from the address family, so an "A" record holding an IPv6
  literal comes back as AAAA. `records.Wire.ToLibDNS` rejects any record whose type changed during
  parsing — without that, an app granted `A` could write an `AAAA`.
- `SetRecords` has RRset semantics: it replaces every record with the same (name, type). the owner
  UI's add-record form uses `append` for that reason.
- if the app test harness doesn't match real openhost behavior, stop and say so rather than working
  around it. same for openhost itself — that's an upstream PR, not a local hack.

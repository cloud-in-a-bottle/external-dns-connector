- prefer to write code that fails loudly, vs continuing in a best-effort manner. eg if you expect an
  env var to be set, fail if it doesn't exist instead of silently falling back to a default. the
  latter is harder to debug and causes unpleasant surprises. where best-effort *is* the right
  behavior (eg the zone discovery behind the add-zone form), say so in a comment and bound it.
- return named struct types, not `map[string]any`. the wire shapes are types in `internal/records`
  and `internal/grants`; keep them there rather than assembling maps at the call site.
- don't use `any` unless there's truly no better way. the one deliberate exception is the libdns
  provider handle: each provider implements a different subset of the libdns interfaces, so it is
  held as `any` and narrowed by type assertion in one place (`dnsprov.CapabilitiesOf`).
- don't write file-level docstrings unless the file is genuinely confusing. they get out of date.
  keep the file simple and readable instead. package comments are fine where the package's purpose
  isn't obvious from its name.
- comments explain *why*, not *what*. a comment that restates the code is worse than none. the ones
  worth writing are the ones that stop someone "simplifying" a deliberate choice back into a bug.
- prefer many small files in well-named folders over few long ones.
- line-wrap at 110 characters, comments included.
- every exported function that enforces a permission or validates untrusted input gets a
  table-driven test, including the cases that must be *rejected*. a test that can't fail is worse
  than no test — check that it does.

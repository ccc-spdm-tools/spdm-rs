# x509-limbo conformance fixtures

The `spdm_x509` tests use curated certificate-path cases from
[C2SP/x509-limbo](https://github.com/C2SP/x509-limbo). Tests never access the
network: fixtures are generated from a local checkout pinned by
`spdmlib/src/crypto/spdm_x509/etc/x509_limbo_capabilities.json` and committed to
the repository.

Each manifest entry has one of these statuses:

- `supported`: copied into its suite fixture and enforced by the Rust runner.
- `unsupported`: omitted with a required explanation of the missing capability.
- `not-applicable`: omitted with a required explanation of why the case is
  outside the SPDM certificate profile.

To regenerate the fixtures from a checkout at the pinned revision:

```sh
python3 sh_script/update_x509_limbo.py /path/to/x509-limbo/limbo.json
```

Use `--check` in automation to detect fixture drift without modifying files.
For a standalone `limbo.json`, pass its verified commit using
`--source-revision`. The importer rejects an unpinned or mismatched revision,
missing testcase IDs, duplicate classifications, unknown statuses, and outputs
that escape the manifest directory.

The current Rust adapter assembles a single leaf-to-root chain. Do not classify
path-building cases with alternate or unrelated intermediates as `supported`
until the runner can treat untrusted intermediates as a candidate pool.

## Current suites

- `name_constraints` isolates Name Constraints behavior by disabling signature
  and time validation.
- `rfc5280_core` keeps signature and extension validation enabled for linear
  Basic Constraints, Key Usage, and unknown critical extension cases. Its cases
  do not specify a validation time, so the suite disables time validation.

The capability manifest records known profile and implementation boundaries.
In particular, DSP0274 permits issuer certificates without Basic Constraints,
while RFC 5280 requires that extension for conforming CAs. Basic Constraints
criticality enforcement remains classified as unsupported until the validator
implements that RFC 5280 check.

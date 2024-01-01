❌ cargo-deny

We use in CI.

Create deny.yml file in .github/workflows/deny.yml.

```
name: CI
on: [push, pull_request]
jobs:
  cargo-deny:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        checks:
          - sources
          - bans 

    # Prevent sudden announcement of a new advisory from failing ci:
    continue-on-error: ${{ matrix.checks == 'sources' }}

    steps:
    - uses: actions/checkout@v2
    - uses: EmbarkStudios/cargo-deny-action@v1
      with:
        command: check ${{ matrix.checks }}

```

## Quick installation for local use

Installs cargo-deny, initializes your project with a default configuration, then runs all of the checks against your project.


`cargo install --locked cargo-deny && cargo deny init && cargo deny check`

### reference

[cargo-deny book](https://embarkstudios.github.io/cargo-deny/index.html)

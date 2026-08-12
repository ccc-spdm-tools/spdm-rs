# AWS-LC patches

These patches add the `no_std` and native build support required to use
AWS-LC on bare-metal targets such as `x86_64-unknown-none`. They also provide
the algorithm-scoped AWS-LC profile used by `spdmlib_crypto_aws_lc`.

## Pinned bases

- aws-lc-rs: `9232f4df246` (`v1.17.3`)
- AWS-LC: `683ebde4b` (`v5.2.0`)

The aws-lc-rs patch intentionally excludes the `aws-lc-sys/aws-lc` gitlink
change. This keeps the patch independent of private fork commits. The patches
use zero context because they target exact commits and are stored as new files
in this repository. Apply the native AWS-LC patch inside the nested submodule
before applying the aws-lc-rs patch:

```sh
git checkout 9232f4df246
git submodule update --init aws-lc-sys/aws-lc

git -C aws-lc-sys/aws-lc apply --unidiff-zero \
  ../../../patches/aws-lc-rs/aws-lc/0001-build-aws-lc-add-no-std-bare-metal-support.patch
git apply --unidiff-zero \
  ../patches/aws-lc-rs/0001-feat-aws-lc-rs-add-no-std-bare-metal-support.patch
```

Paths above assume the commands are run from `external/aws-lc-rs` in an
spdm-rs checkout.

## Readiness

The patches apply cleanly to the pinned public bases. The resulting source has
passed default debug and release tests, all four ML-KEM/ML-DSA feature
combinations, cc and CMake whole-archive links, FIPS checks, the final-linked
`x86_64-unknown-none` fixture, and a complete consumer build and test pipeline.

Treat the base commits as part of the production dependency lock. As of
2026-08-12, neither patch applies directly to current upstream `main`
(aws-lc-rs is 17 commits ahead of its base and AWS-LC is 40 commits ahead).
Rebase, regenerate bindings, and repeat the validation matrix before updating
either base or submitting the patches upstream.

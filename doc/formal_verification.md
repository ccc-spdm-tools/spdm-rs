# Formal Verification Tools for spdm-rs

This document describes the formal verification tools applicable to the spdm-rs codebase.

## Tool Selection Guide

| Verification Need | Recommended Tool |
|-------------------|-----------------|
| Protocol message format correctness (bounded) | **Kani** |
| Spec property verification (bounded, exhaustive) | **Kani** |
| Unbounded invariants (sessions, algorithms) | **Verus** |
| Cryptographic algorithm correctness | **Verus** |

These tools are complementary. Kani is used for spec-property formal verification of protocol logic, and Verus for unbounded proofs where needed.

## 1. Kani (Bounded Model Checker)

**Type**: Bounded model checking (formal verification)  
**Maintained by**: AWS  
**Requires code changes**: Proof harnesses only (separate from source)  
**Website**: https://model-checking.github.io/kani/

Kani verifies Rust programs by exhaustively checking all possible inputs up to a given bound using CBMC as its backend. It is ideal for verifying properties of protocol message parsing, bitfield validation, and finite-state logic.

### Usage

```bash
cargo install --locked kani-verifier
cargo kani setup
cargo kani --tests -p spdmlib
```

### What it verifies

- Absence of panics, overflows, and out-of-bounds access
- Custom assertions over ALL possible inputs (symbolic execution)
- Protocol specification properties (message format constraints, cross-field dependencies)
- Memory safety properties

### Strengths for spdm-rs

- Protocol messages have fixed, bounded structure — Kani exhaustively covers the entire input space
- Each spec property can be verified independently (parallelizable)
- Fully automated — no annotations needed in source code
- Produces counterexamples when a property fails

### Limitations

- Bounded — cannot prove properties over unbounded data (e.g., arbitrary-length certificate chains)
- Loop unrolling limited to a configurable bound
- Verification time grows with input size

## 2. Verus (Deductive Verifier)

**Type**: Deductive verification (SMT-based)  
**Maintained by**: VMware Research / Carnegie Mellon University  
**Requires code changes**: Yes — proof annotations in source  
**Website**: https://verus-lang.github.io/verus/guide/

Verus enables writing mathematical proofs alongside Rust code. It uses an SMT solver (Z3) to verify that the code satisfies its specification. Unlike bounded model checking, Verus can prove unbounded properties (e.g., "for all N").

### Usage

```bash
# Clone and build Verus
git clone https://github.com/verus-lang/verus.git
cd verus/source
# Build
./tools/get-z3.sh
source ../tools/activate
vargo build --release
# Verify a file
verus path/to/file.rs
```

### What it verifies

- Functional correctness with full mathematical proofs
- Loop invariants for arbitrary iteration counts
- Properties over unbounded data structures
- Pre/post-conditions (contracts)
- Type invariants

### Strengths for spdm-rs

- Can prove session-level invariants that hold for arbitrary message sequences
- Suitable for cryptographic algorithm correctness (unbounded key sizes)
- Provides the strongest guarantees (not bounded)

### Limitations

- Requires manual proof annotations in source code (higher effort)
- Steeper learning curve than Kani
- Annotations must be maintained alongside code changes

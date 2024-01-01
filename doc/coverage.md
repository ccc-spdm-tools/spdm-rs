### coverage

The Rust compiler includes two code coverage implementations:

**A GCC-compatible, gcov-based coverage implementation, enabled with -Z profile, which derives coverage data based on DebugInfo.**

[profile environment](https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/profile.html)

**A source-based code coverage implementation, enabled with -C instrument-coverage, which uses LLVM's native, efficient coverage instrumentation to generate very precise coverage data.**

  [instrument-coverage environment](https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/instrument-coverage.html)

**grcov has a bug in Windows, please run the command line with administrator**

 [bug issues](https://github.com/mozilla/grcov/issues/561)

First of all, install grcov

```
cargo install grcov
```

Second, install the llvm-tools Rust component (`llvm-tools-preview` for now, it might become `llvm-tools` soon):

```
rustup component add llvm-tools-preview
```

# source-based coverage

**Project is enables source-based coverage**

```bash
# Export the flags needed to instrument the program to collect code coverage.
export RUSTFLAGS="-Zinstrument-coverage"
export LLVM_PROFILE_FILE="rust-spdm-%p%m.profraw"

# Build the program
cargo build -p spdm-responder-emu -p spdm-requester-emu

# Run the program
cargo run -p spdm-responder-emu & 
cargo run -p spdm-requester-emu

# Generate a HTML report in the ./target/debug/gcov_coverage/ directory.
grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/source_coverage/
```

# gcov-based coverage

**Project is disables gcov-based coverage**

```bash
# Export the flags needed to instrument the program to collect code coverage.
export CARGO_INCREMENTAL=0
export RUSTDOCFLAGS="-Cpanic=abort"
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"

# Build the program
cargo build -p spdm-responder-emu -p spdm-requester-emu

# Run the program
cargo run -p spdm-responder-emu & 
cargo run -p spdm-requester-emu

# Generate a HTML report in the ./target/debug/gcov_coverage/ directory.
grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/gcov_coverage/
```



# The difference between source-based coverage and gcov-based coverage

1. RUSTFLAG set by source-based coverage and gcov-based coverage are different.
2. source-based coverage has no branch data.
3. Our project gcov-based coverage can't be run under Windows, and a library fails to build.

![image](https://user-images.githubusercontent.com/39472702/127297588-bbf91601-b6b1-4e33-973d-1bf1b2c3af1e.png)



Reference:

 [rust-code-coverage-sample](https://github.com/marco-c/rust-code-coverage-sample)

 [source_based_code_coverage](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/source-based-code-coverage.html#running-the-instrumented-binary-to-generate-raw-coverage-profiling-data)

 [grcov](https://github.com/mozilla/grcov)
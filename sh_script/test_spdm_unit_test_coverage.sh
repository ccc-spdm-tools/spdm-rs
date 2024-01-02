#!/bin/bash
cargo clean

if [[ ! $PWD =~ rust-spdm$ ]];then
    pushd ..
fi

git clean -f

rm -rf ./target *.prof*

export RUSTFLAGS="-Zinstrument-coverage"
export LLVM_PROFILE_FILE="your_name-%p-%m.profraw"

cargo build

cargo test

grcov . --binary-path ./target/debug/ -s . -t html --branch --ignore-not-existing -o ./target/debug/coverage/

grcov . --binary-path ./target/debug/ -s . -t lcov --branch --ignore-not-existing -o ./lcov.infoba
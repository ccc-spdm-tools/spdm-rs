#!/bin/bash

if [[ ! $PWD =~ rust-spdm$ ]];then
    pushd ..
fi

rm -rf ./target

export RUSTFLAGS="-Zinstrument-coverage"
export LLVM_PROFILE_FILE="rust-spdm-%p%m.profraw"

cargo build -p spdm-responder-emu -p spdm-requester-emu

cargo run -p spdm-responder-emu & 
cargo run -p spdm-requester-emu

grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/test_spdm_coverage/
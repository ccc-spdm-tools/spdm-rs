#!/bin/bash

set -euo pipefail

export RUST_MIN_STACK=10485760

usage() {
    cat <<EOM
Usage: $(basename "$0") [OPTION]...
  -c Run check
  -b Build target
  -r Build and run tests
  -h Show help info
EOM
}

echo_command() {
    set -x
    "$@"
    set +x
}

trap cleanup exit

cleanup() {
    kill -9 $(ps aux | grep spdm-responder | grep emu | awk '{print $2}') || true
    kill -9 $(ps aux | grep spdm_responder_emu | grep emu | awk '{print $2}') || true
}

check() {
    echo "Checking..."
    set -x
    cargo check
    cargo fmt --all -- --check
    cargo clippy -- -D warnings -A clippy::only-used-in-recursion -A incomplete-features -A clippy::bad_bit_mask -A clippy::derivable_impls
    
    if [ "${RUNNER_OS:-Linux}" == "Linux" ]; then
    pushd spdmlib_crypto_mbedtls
    cargo check
    cargo clippy -- -D warnings -A clippy::only-used-in-recursion -A incomplete-features -A clippy::bad_bit_mask -A clippy::derivable_impls
    popd
    fi
    set +x
}

RUSTFLAGS=${RUSTFLAGS:-}
build() {
    pushd spdmlib
    echo "Building Rust-SPDM..."
    cargo build
    
    echo "Building Rust-SPDM with no-default-features..."
    echo_command cargo build --release --no-default-features
    
    echo "Building Rust-SPDM with spdm-ring feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring

    echo "Building Rust-SPDM with spdm-ring,is_sync feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring,is_sync
    
    echo "Building Rust-SPDM with spdm-ring,hashed-transcript-data feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring,hashed-transcript-data

    echo "Building Rust-SPDM with spdm-ring,hashed-transcript-data,is_sync feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring,hashed-transcript-data,is_sync

    echo "Building Rust-SPDM with spdm-ring,hashed-transcript-data,mut-auth feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring,hashed-transcript-data,mut-auth

    echo "Building Rust-SPDM with spdm-ring,hashed-transcript-data,mut-auth,is_sync feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring,hashed-transcript-data,mut-auth,is_sync

    if [ -z "$RUSTFLAGS" ]; then
        echo "Building Rust-SPDM in no std with no-default-features..."
        echo_command cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features
    
        echo "Building Rust-SPDM in no std with spdm-ring feature..."
        echo_command cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features --features="spdm-ring"
    
        echo "Building Rust-SPDM in no std with spdm-ring,is_sync feature..."
        echo_command cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features --features="spdm-ring,is_sync"

        echo "Building Rust-SPDM in no std with spdm-ring,hashed-transcript-data feature..."
        echo_command cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features --features="spdm-ring,hashed-transcript-data"
    
        echo "Building Rust-SPDM in no std with spdm-ring,hashed-transcript-data,is_sync feature..."
        echo_command cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features --features="spdm-ring,hashed-transcript-data,is_sync"

        echo "Building Rust-SPDM in no std with spdm-ring,hashed-transcript-data,mut-auth feature..."
        echo_command cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features --features="spdm-ring,hashed-transcript-data,mut-auth"
    
        echo "Building Rust-SPDM in no std with spdm-ring,hashed-transcript-data,mut-auth,is_sync feature..."
        echo_command cargo build -Z build-std=core,alloc,compiler_builtins --target x86_64-unknown-none --release --no-default-features --features="spdm-ring,hashed-transcript-data,mut-auth,is_sync"
    fi

    popd
    
    echo "Building spdm-requester-emu..."
    echo_command cargo build -p spdm-requester-emu
    
    echo "Building spdm-responder-emu..."
    echo_command cargo build -p spdm-responder-emu
}

RUN_REQUESTER_FEATURES=${RUN_REQUESTER_FEATURES:-spdm-ring,hashed-transcript-data,async-executor}
RUN_RESPONDER_FEATURES=${RUN_RESPONDER_FEATURES:-spdm-ring,hashed-transcript-data,async-executor}
RUN_REQUESTER_MUTAUTH_FEATURES="${RUN_REQUESTER_FEATURES},mut-auth"
RUN_RESPONDER_MUTAUTH_FEATURES="${RUN_RESPONDER_FEATURES},mut-auth"
RUN_RESPONDER_MANDATORY_MUTAUTH_FEATURES="${RUN_RESPONDER_FEATURES},mandatory-mut-auth"

run_with_spdm_emu() {
    echo "Running with spdm-emu..."
    pushd test_key
    chmod +x ./spdm_responder_emu
    echo_command  ./spdm_responder_emu --trans PCI_DOE &
    popd
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_FEATURES"
    cleanup
    
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_FEATURES" &
    sleep 20
    pushd test_key
    chmod +x ./spdm_requester_emu
    echo_command  ./spdm_requester_emu --trans PCI_DOE --exe_conn DIGEST,CERT,CHAL,MEAS --exe_session KEY_EX,PSK,KEY_UPDATE,HEARTBEAT,MEAS,DIGEST,CERT
    popd
}

run_with_spdm_emu_mut_auth() {
    echo "Running mutual authentication with spdm-emu..."
    pushd test_key
    chmod +x ./spdm_responder_emu
    echo_command  ./spdm_responder_emu --trans PCI_DOE --mut_auth DIGESTS --req_asym ECDSA_P384 --basic_mut_auth NO &
    popd
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_MUTAUTH_FEATURES"
    cleanup
    
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_MUTAUTH_FEATURES" &
    sleep 20
    pushd test_key
    chmod +x ./spdm_requester_emu
    echo_command  ./spdm_requester_emu --trans PCI_DOE --req_asym ECDSA_P384 --exe_conn DIGEST,CERT,CHAL,MEAS --exe_session KEY_EX,PSK,KEY_UPDATE,HEARTBEAT,MEAS,DIGEST,CERT
    popd
}

run_with_spdm_emu_mandatory_mut_auth() {
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_MANDATORY_MUTAUTH_FEATURES" &
    sleep 20
    pushd test_key
    chmod +x ./spdm_requester_emu
    echo_command  ./spdm_requester_emu --trans PCI_DOE --req_asym ECDSA_P384 --exe_conn DIGEST,CERT,CHAL,MEAS --exe_session KEY_EX,PSK,KEY_UPDATE,HEARTBEAT,MEAS,DIGEST,CERT
    popd
}

run_basic_test() {
    echo "Running basic tests..."
    echo_command cargo test -- --test-threads=1
    echo_command cargo test --no-default-features --features "spdmlib/std,spdmlib/spdm-ring" -- --test-threads=1
    echo_command cargo test --no-default-features --features "spdmlib/std,spdmlib/spdm-ring,spdm-emu/is_sync,spdmlib/is_sync,maybe-async/is_sync,idekm/is_sync,tdisp/is_sync,mctp_transport/is_sync,pcidoe_transport/is_sync,spdm-requester-emu/is_sync,spdm-responder-emu/is_sync" -- --test-threads=1
    echo "Running basic tests finished..."

    echo "Running spdmlib-test..."
    pushd test/spdmlib-test
    echo_command cargo test -- --test-threads=1
    echo_command cargo test --no-default-features -- --test-threads=1
    popd
}

run_rust_spdm_emu() {
    echo "Running requester and responder..."
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_FEATURES" &
    sleep 20
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_FEATURES"
    cleanup
}

run_rust_spdm_emu_mut_auth() {
    echo "Running requester and responder mutual authentication..."
    echo $RUN_REQUESTER_MUTAUTH_FEATURES
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_MUTAUTH_FEATURES" &
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_MUTAUTH_FEATURES"
    cleanup
}

run_rust_spdm_emu_mandatory_mut_auth() {
    echo "Running requester and responder mandatory mutual authentication..."
    echo $RUN_REQUESTER_MUTAUTH_FEATURES
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_MANDATORY_MUTAUTH_FEATURES" &
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_MUTAUTH_FEATURES"
    cleanup
}

run() {
    run_basic_test
    run_rust_spdm_emu
    run_rust_spdm_emu_mut_auth
    run_rust_spdm_emu_mandatory_mut_auth
}

CHECK_OPTION=false
BUILD_OPTION=false
RUN_OPTION=false

process_args() {
    while getopts ":cbrfh" option; do
        case "${option}" in
            c)
                CHECK_OPTION=true
            ;;
            b)
                BUILD_OPTION=true
            ;;
            r)
                RUN_OPTION=true
            ;;
            h)
                usage
                exit 0
            ;;
            *)
                echo "Invalid option '-$OPTARG'"
                usage
                exit 1
            ;;
        esac
    done
}

main() {
    ./sh_script/pre-build.sh

    if [[ ${CHECK_OPTION} == true ]]; then
        check
        exit 0
    fi
    if [[ ${BUILD_OPTION} == true ]]; then
        build
        exit 0
    fi
    build
    if [[ ${RUN_OPTION} == true ]]; then
        run
        if [ "$RUNNER_OS" == "Linux" ]; then
            run_with_spdm_emu
            run_with_spdm_emu_mut_auth
            run_with_spdm_emu_mandatory_mut_auth
        fi
    fi
}

process_args "$@"
main
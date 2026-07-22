#!/bin/bash

set -euo pipefail

export RUST_MIN_STACK=10485760

usage() {
    cat <<EOM
Usage: $(basename "$0") [OPTION]...
  -c Run check
  -b Build target
  -t Specify target platform to be built
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
    cargo clippy -- -D warnings

    if [ "${RUNNER_OS:-Linux}" == "Linux" ]; then
    pushd spdmlib_crypto_mbedtls
    cargo check
    cargo clippy -- -D warnings
    popd
    fi
    set +x
}

RUSTFLAGS=${RUSTFLAGS:-}
build() {
    pushd spdmlib
    echo "Building spdm-rs..."
    cargo build

    echo "Building spdm-rs with no-default-features..."
    echo_command cargo build --release --no-default-features

    echo "Building spdm-rs with spdm-ring feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring

    echo "Building spdm-rs with spdm-ring,is_sync feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring,is_sync

    echo "Building spdm-rs with spdm-ring,hashed-transcript-data feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring,hashed-transcript-data

    echo "Building spdm-rs with spdm-ring,hashed-transcript-data,is_sync feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring,hashed-transcript-data,is_sync

    echo "Building spdm-rs with spdm-ring,hashed-transcript-data,mut-auth feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring,hashed-transcript-data,mut-auth

    echo "Building spdm-rs with spdm-ring,hashed-transcript-data,mut-auth,is_sync feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring,hashed-transcript-data,mut-auth,is_sync

    echo "Building spdm-rs with spdm-ring,hashed-transcript-data,mut-auth,is_sync,fips feature..."
    echo_command cargo build --release --no-default-features --features=spdm-ring,hashed-transcript-data,mut-auth,is_sync

    if [ -z "$RUSTFLAGS" ]; then
        echo "Building spdm-rs in no std with no-default-features..."
        echo_command cargo build --target ${TARGET_OPTION} --release --no-default-features

        echo "Building spdm-rs in no std with spdm-ring feature..."
        echo_command cargo build --target ${TARGET_OPTION} --release --no-default-features --features="spdm-ring"

        echo "Building spdm-rs in no std with spdm-ring,is_sync feature..."
        echo_command cargo build --target ${TARGET_OPTION} --release --no-default-features --features="spdm-ring,is_sync"

        echo "Building spdm-rs in no std with spdm-ring,hashed-transcript-data feature..."
        echo_command cargo build --target ${TARGET_OPTION} --release --no-default-features --features="spdm-ring,hashed-transcript-data"

        echo "Building spdm-rs in no std with spdm-ring,hashed-transcript-data,is_sync feature..."
        echo_command cargo build --target ${TARGET_OPTION} --release --no-default-features --features="spdm-ring,hashed-transcript-data,is_sync"

        echo "Building spdm-rs in no std with spdm-ring,hashed-transcript-data,mut-auth feature..."
        echo_command cargo build --target ${TARGET_OPTION} --release --no-default-features --features="spdm-ring,hashed-transcript-data,mut-auth"

        echo "Building spdm-rs in no std with spdm-ring,hashed-transcript-data,mut-auth,is_sync feature..."
        echo_command cargo build --target ${TARGET_OPTION} --release --no-default-features --features="spdm-ring,hashed-transcript-data,mut-auth,is_sync"

        echo "Building spdm-rs in no std with spdm-ring,hashed-transcript-data,mut-auth,is_sync,fips feature..."
        echo_command cargo build --target ${TARGET_OPTION} --release --no-default-features --features="spdm-ring,hashed-transcript-data,mut-auth,is_sync,fips"
    fi

    popd

    echo "Building spdm-requester-emu..."
    echo_command cargo build -p spdm-requester-emu

    echo "Building spdm-responder-emu..."
    echo_command cargo build -p spdm-responder-emu

    echo "Building spdm-requester-emu with PQC (spdm-aws-lc)..."
    echo_command export SPDM_CONFIG="etc/pqc_config.json"
    echo_command cargo build -p spdm-requester-emu --no-default-features --features="spdm-ring,hashed-transcript-data,async-executor,spdm-aws-lc"

    echo "Building spdm-responder-emu with PQC (spdm-aws-lc)..."
    echo_command cargo build -p spdm-responder-emu --no-default-features --features="spdm-ring,hashed-transcript-data,async-executor,spdm-aws-lc"
    echo_command unset SPDM_CONFIG

    # Standalone aws-lc backend (no ring, no mbedtls): aws-lc-rs supplies both
    # classical and PQC crypto. std-only. Compile-checked here on every build.
    echo "Building spdm-requester-emu with standalone aws-lc (spdm-aws-lc, no ring/mbedtls)..."
    echo_command cargo build -p spdm-requester-emu --no-default-features --features="spdm-aws-lc,hashed-transcript-data,async-executor"

    echo "Building spdm-responder-emu with standalone aws-lc (spdm-aws-lc, no ring/mbedtls)..."
    echo_command cargo build -p spdm-responder-emu --no-default-features --features="spdm-aws-lc,hashed-transcript-data,async-executor"
}

RUN_REQUESTER_FEATURES=${RUN_REQUESTER_FEATURES:-spdm-ring,hashed-transcript-data,async-executor}
RUN_RESPONDER_FEATURES=${RUN_RESPONDER_FEATURES:-spdm-ring,hashed-transcript-data,async-executor}
RUN_REQUESTER_MUTAUTH_FEATURES="${RUN_REQUESTER_FEATURES},mut-auth"
RUN_RESPONDER_MUTAUTH_FEATURES="${RUN_RESPONDER_FEATURES},mut-auth"
RUN_RESPONDER_MANDATORY_MUTAUTH_FEATURES="${RUN_RESPONDER_FEATURES},mandatory-mut-auth"
RUN_REQUESTER_CHUNK_CAP_FEATURES="${RUN_REQUESTER_FEATURES},chunk-cap"
RUN_RESPONDER_CHUNK_CAP_FEATURES="${RUN_RESPONDER_FEATURES},chunk-cap"
RUN_REQUESTER_PQC_FEATURES="${RUN_REQUESTER_FEATURES},spdm-aws-lc,chunk-cap"
RUN_RESPONDER_PQC_FEATURES="${RUN_RESPONDER_FEATURES},spdm-aws-lc,chunk-cap"
RUN_REQUESTER_PQC_MUTAUTH_FEATURES="${RUN_REQUESTER_PQC_FEATURES},mut-auth"
RUN_RESPONDER_PQC_MUTAUTH_FEATURES="${RUN_RESPONDER_PQC_FEATURES},mut-auth"
RUN_RESPONDER_PQC_MANDATORY_MUTAUTH_FEATURES="${RUN_RESPONDER_PQC_FEATURES},mandatory-mut-auth"


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
    # The spdm-rs Responder advertises ECDSA_P384 as its ReqBaseAsymAlg (REQ_USE_ECDSA);
    # the libspdm requester defaults to RSA, so ask it for ECDSA_P384 to match, otherwise
    # ALGORITHMS negotiation fails (libspdm_init_connection - NEGOTIATION_FAIL).
    echo_command  ./spdm_requester_emu --trans PCI_DOE --req_asym ECDSA_P384 --exe_conn DIGEST,CERT,CHAL,MEAS --exe_session KEY_EX,PSK,KEY_UPDATE,HEARTBEAT,MEAS,DIGEST,CERT
    popd
}

run_with_spdm_emu_supported_algs() {
    # DSP0274 1.3+ SUPPORTED_ALGOS_EXT_CAP cross-test: spdm-rs Requester asks the libspdm
    # (spdm-emu) Responder for its SupportedAlgorithms block in CAPABILITIES, then decodes and
    # consumes it. Requires CHUNK_CAP on both peers. Note: at SPDM 1.4 the SupportedAlgorithms
    # block plus the ALGORITHMS response can exceed libspdm's default VCA transcript buffer
    # (LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE = 200 + 2*LIBSPDM_MAX_VERSION_COUNT); build libspdm
    # with a larger LIBSPDM_MAX_VERSION_COUNT if the 1.4 handshake fails with BUFFER_FULL.
    echo "Running SupportedAlgorithms cross-test (spdm-rs requester vs libspdm responder)..."
    pushd test_key
    chmod +x ./spdm_responder_emu
    echo_command  ./spdm_responder_emu --trans PCI_DOE &
    popd
    sleep 5
    SPDMRS_USE_SUPPORTED_ALGOS=1 \
        echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_CHUNK_CAP_FEATURES"
    cleanup
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

    echo "Running basic FIPS self-test..."
    pushd test/spdmlib-fips-test
    echo_command cargo test --features=fips -- --test-threads=1
    popd

    echo "Running basic spdm_x509 tests..."
    echo_command cargo test -p spdm_x509 -- --test-threads=1
    echo_command cargo test -p spdm_x509 --no-default-features -- --test-threads=1
    echo "Running basic spdm_x509 tests finished..."

    # ML-DSA (FIPS 204) certificate-chain verification unit tests. These build
    # the aws-lc-rs backend, so they run only where that toolchain is available
    # (the spdm-aws-lc CI job). Covers the happy path (all ML-DSA variants
    # validate) and fail paths (tampered signature / intermediate rejected).
    if [[ "${RUN_REQUESTER_FEATURES}" == *"spdm-aws-lc"* ]]; then
        echo "Running ML-DSA certificate-chain tests (spdmlib_crypto_aws_lc)..."
        echo_command cargo test -p spdmlib_crypto_aws_lc -- --test-threads=1
        echo "Running ML-DSA certificate-chain tests finished..."
    fi

    echo "Running spdmlib-test..."
    pushd test/spdmlib-test
    echo_command cargo test -- --test-threads=1
    echo_command cargo test --no-default-features -- --test-threads=1
    popd

    echo "Running tests with chunk capability..."
    echo_command export SPDM_CONFIG="etc/chunk_test_config.json"
    echo_command cargo test --no-default-features --features "spdmlib/std,spdmlib/spdm-ring,spdm-emu/is_sync,spdmlib/is_sync,maybe-async/is_sync,idekm/is_sync,tdisp/is_sync,mctp_transport/is_sync,pcidoe_transport/is_sync,spdm-requester-emu/is_sync,spdm-responder-emu/is_sync,chunk-cap" -- --test-threads=1
    pushd test/spdmlib-test
    echo_command cargo test -- --test-threads=1
    echo_command cargo test --no-default-features --features "chunk-cap" -- --test-threads=1
    popd
    echo_command export SPDM_CONFIG="etc/config.json"

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

run_rust_spdm_emu_chunk_cap() {
    echo "Running requester and responder chunk capability..."
    echo_command export SPDM_CONFIG="etc/chunk_test_config.json"
    echo $RUN_REQUESTER_CHUNK_CAP_FEATURES
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_CHUNK_CAP_FEATURES" &
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_CHUNK_CAP_FEATURES"
    echo_command export SPDM_CONFIG="etc/config.json"
    cleanup
}

run_rust_spdm_emu_supported_algs() {
    # DSP0274 1.3 SUPPORTED_ALGOS_EXT_CAP end-to-end (spdm-rs requester <-> spdm-rs responder):
    # the Requester queries the Responder's SupportedAlgorithms block in CAPABILITIES, then the
    # full handshake (algorithms, cert, challenge, measurement, key exchange, session) proceeds
    # over the same transcript. Requires CHUNK_CAP on both peers.
    echo "Running requester and responder with SupportedAlgorithms (SUPPORTED_ALGOS_EXT_CAP)..."
    export SPDMRS_USE_SUPPORTED_ALGOS=1
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_CHUNK_CAP_FEATURES" &
    sleep 20
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_CHUNK_CAP_FEATURES"
    cleanup

    # Same exchange with a small DataTransferSize (chunk_test_config.json), so the block-bearing
    # CAPABILITIES response exceeds DataTransferSize and is transferred via the Large SPDM message
    # mechanism (ERROR/LargeResponse -> CHUNK_GET -> CHUNK_RESPONSE) before the rest of the flow.
    echo "Running requester and responder with SupportedAlgorithms over chunked CAPABILITIES..."
    echo_command export SPDM_CONFIG="etc/chunk_test_config.json"
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_CHUNK_CAP_FEATURES" &
    sleep 20
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_CHUNK_CAP_FEATURES"
    echo_command export SPDM_CONFIG="etc/config.json"
    unset SPDMRS_USE_SUPPORTED_ALGOS
    cleanup
}

run_rust_spdm_emu_raw_pub_key() {
    echo "Running requester and responder with raw public key..."
    export SPDMRS_USE_RAW_PUB_KEY=true
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_FEATURES" &
    sleep 20
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_FEATURES"
    unset SPDMRS_USE_RAW_PUB_KEY
    cleanup
}

run_rust_spdm_emu_pqc_raw_pub_key() {
    echo "Running requester and responder with PQC (ML-DSA + ML-KEM)..."
    echo_command export SPDM_CONFIG="etc/pqc_config.json"
    # Force build.rs to regenerate config.rs with PQC buffer sizes.
    # build.rs writes to spdmlib/src/config.rs (a shared source file),
    # which may have been overwritten by prior non-PQC test builds.
    rm -f spdmlib/src/config.rs
    export SPDMRS_USE_PQC=true
    export SPDMRS_USE_RAW_PUB_KEY=true
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_PQC_FEATURES" &
    sleep 20
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_PQC_FEATURES"
    unset SPDMRS_USE_PQC
    unset SPDMRS_USE_RAW_PUB_KEY
    echo_command unset SPDM_CONFIG
    cleanup
}

run_rust_spdm_emu_pqc_cert_chain() {
    echo "Running requester and responder with PQC (ML-DSA + ML-KEM) certificate chain..."
    echo_command export SPDM_CONFIG="etc/pqc_config.json"
    # Force build.rs to regenerate config.rs with PQC buffer sizes.
    # build.rs writes to spdmlib/src/config.rs (a shared source file),
    # which may have been overwritten by prior non-PQC test builds.
    rm -f spdmlib/src/config.rs
    export SPDMRS_USE_PQC=true
    # NOTE: SPDMRS_USE_RAW_PUB_KEY is intentionally NOT set, so ML-DSA
    # certificate chains are exchanged and validated (GET_DIGESTS /
    # GET_CERTIFICATE + chain verification), exercising the ML-DSA
    # certificate-signature path in spdm_x509 via the aws-lc backend.
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_PQC_FEATURES" &
    sleep 20
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_PQC_FEATURES"
    unset SPDMRS_USE_PQC
    echo_command unset SPDM_CONFIG
    cleanup
}

run_rust_spdm_emu_pqc_mut_auth() {
    echo "Running requester and responder with PQC (ML-DSA + ML-KEM) mutual authentication..."
    echo_command export SPDM_CONFIG="etc/pqc_config.json"
    # Force build.rs to regenerate config.rs with PQC buffer sizes.
    rm -f spdmlib/src/config.rs
    export SPDMRS_USE_PQC=true
    # Mutual auth requires certificate chains on both sides (raw public key not
    # set). The Responder advertises MUT_AUTH_CAP and drives the encapsulated
    # GET_DIGESTS/GET_CERTIFICATE flow to fetch and verify the Requester's
    # ML-DSA certificate chain; the Requester's FINISH carries an ML-DSA
    # signature the Responder verifies. Exercises ML-DSA cert verification on
    # BOTH peers (leaf + encapsulated requester cert) via spdm_x509 + aws-lc.
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_PQC_MUTAUTH_FEATURES" &
    sleep 20
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_PQC_MUTAUTH_FEATURES"
    unset SPDMRS_USE_PQC
    echo_command unset SPDM_CONFIG
    cleanup
}

run_rust_spdm_emu_pqc_mandatory_mut_auth() {
    echo "Running requester and responder with PQC (ML-DSA + ML-KEM) mandatory mutual authentication..."
    echo_command export SPDM_CONFIG="etc/pqc_config.json"
    rm -f spdmlib/src/config.rs
    export SPDMRS_USE_PQC=true
    # Responder mandates mutual auth; Requester advertises mut-auth. Same
    # ML-DSA verification on both peers as run_rust_spdm_emu_pqc_mut_auth, but
    # the Responder refuses the connection unless the Requester is mut-auth
    # capable.
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_PQC_MANDATORY_MUTAUTH_FEATURES" &
    sleep 20
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_PQC_MUTAUTH_FEATURES"
    unset SPDMRS_USE_PQC
    echo_command unset SPDM_CONFIG
    cleanup
}

run_with_spdm_emu_pqc_cert_chain() {
    echo "Running cross test with spdm-emu PQC (ML-DSA + ML-KEM) certificate chain..."
    echo_command export SPDM_CONFIG="etc/pqc_config.json"
    # Force build.rs to regenerate config.rs with PQC buffer sizes.
    rm -f spdmlib/src/config.rs

    # --- spdm-rs Requester <-> spdm-emu (libspdm) Responder ---
    pushd test_key
    chmod +x ./spdm_responder_emu
    # spdm-emu binaries are dynamically linked against a custom OpenSSL
    # (libcrypto.so.3) with PQC/ML-DSA support, shipped in test_key/.
    export LD_LIBRARY_PATH=$(pwd):${LD_LIBRARY_PATH:-}
    # CERT_CAP (not PUB_KEY_ID) so the Responder serves an ML-DSA certificate
    # chain; the spdm-rs Requester retrieves and validates it.
    echo_command ./spdm_responder_emu --trans PCI_DOE --cap CACHE,CERT,CHAL,MEAS_SIG,MEAS_FRESH,ENCRYPT,MAC,KEY_EX,ENCAP,HBEAT,KEY_UPD,HANDSHAKE_IN_CLEAR,CHUNK --mut_auth NO --pqc_asym ML_DSA_87 --kem ML_KEM_1024 --pqc_first TRUE &
    popd
    sleep 5
    export SPDMRS_USE_PQC=true
    # SPDMRS_USE_RAW_PUB_KEY intentionally unset -> certificate chain mode.
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_PQC_FEATURES"
    unset SPDMRS_USE_PQC
    cleanup

    # --- spdm-rs Responder <-> spdm-emu (libspdm) Requester ---
    export SPDMRS_USE_PQC=true
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_PQC_FEATURES" &
    sleep 20
    pushd test_key
    chmod +x ./spdm_requester_emu
    export LD_LIBRARY_PATH=$(pwd):${LD_LIBRARY_PATH:-}
    # CERT (not PUB_KEY_ID) + DIGEST,CERT in exe_conn so the libspdm Requester
    # fetches and validates the spdm-rs Responder's ML-DSA certificate chain.
    # CERT_CAP is required: the spdm-rs Responder rejects a Requester that
    # advertises CHAL_CAP without CERT_CAP or PUB_KEY_ID_CAP (DSP0274).
    # LARGE_RESP is required: at SPDM 1.4 the libspdm Requester issues the large
    # GET_CERTIFICATE format, which the spdm-rs Responder only accepts when
    # LARGE_RESP_CAP is negotiated on both peers.
    echo_command ./spdm_requester_emu --trans PCI_DOE --cap CERT,CHAL,ENCRYPT,MAC,KEY_EX,ENCAP,HBEAT,KEY_UPD,CHUNK,LARGE_RESP --mut_auth NO --pqc_asym ML_DSA_87 --kem ML_KEM_1024 --pqc_first TRUE --exe_conn DIGEST,CERT,CHAL,MEAS --exe_session KEY_EX,KEY_UPDATE,HEARTBEAT,MEAS
    popd
    unset SPDMRS_USE_PQC
    unset LD_LIBRARY_PATH
    echo_command unset SPDM_CONFIG
    cleanup
}

run_with_spdm_emu_pqc_mut_auth() {
    echo "Running cross test with spdm-emu PQC (ML-DSA + ML-KEM) mutual authentication..."
    echo_command export SPDM_CONFIG="etc/pqc_config.json"
    rm -f spdmlib/src/config.rs

    # --- spdm-rs Requester <-> spdm-emu (libspdm) Responder ---
    # The libspdm Responder requests mutual auth (--mut_auth DIGESTS) and
    # accepts an ML-DSA Requester signing algorithm (--req_pqc_asym ML_DSA_87);
    # the spdm-rs Requester serves and signs with its ML-DSA cert chain.
    pushd test_key
    chmod +x ./spdm_responder_emu
    export LD_LIBRARY_PATH=$(pwd):${LD_LIBRARY_PATH:-}
    echo_command ./spdm_responder_emu --trans PCI_DOE --cap CACHE,CERT,CHAL,MEAS_SIG,MEAS_FRESH,ENCRYPT,MAC,KEY_EX,ENCAP,HBEAT,KEY_UPD,HANDSHAKE_IN_CLEAR,CHUNK --mut_auth DIGESTS --basic_mut_auth NO --pqc_asym ML_DSA_87 --req_pqc_asym ML_DSA_87 --kem ML_KEM_1024 --pqc_first TRUE &
    popd
    sleep 5
    export SPDMRS_USE_PQC=true
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_PQC_MUTAUTH_FEATURES"
    unset SPDMRS_USE_PQC
    cleanup

    # --- spdm-rs Responder <-> spdm-emu (libspdm) Requester ---
    # The spdm-rs Responder requests mutual auth; the libspdm Requester serves
    # and signs with its ML-DSA cert chain (--req_pqc_asym ML_DSA_87), and
    # fetches the Responder's ML-DSA chain (DIGEST,CERT in exe_conn).
    export SPDMRS_USE_PQC=true
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_PQC_MUTAUTH_FEATURES" &
    sleep 20
    pushd test_key
    chmod +x ./spdm_requester_emu
    export LD_LIBRARY_PATH=$(pwd):${LD_LIBRARY_PATH:-}
    # LARGE_RESP is required: at SPDM 1.4 the libspdm Requester issues the large
    # GET_CERTIFICATE format, which the spdm-rs Responder only accepts when
    # LARGE_RESP_CAP is negotiated on both peers.
    # MUT_AUTH is required in --cap: the spdm-rs Responder (built with mut-auth)
    # asserts MutAuthRequested in KEY_EXCHANGE_RSP, which the libspdm Requester
    # only accepts (and reciprocates) when it also negotiated MUT_AUTH_CAP.
    echo_command ./spdm_requester_emu --trans PCI_DOE --cap CERT,CHAL,ENCRYPT,MAC,KEY_EX,MUT_AUTH,ENCAP,HBEAT,KEY_UPD,CHUNK,LARGE_RESP --mut_auth DIGESTS --basic_mut_auth NO --pqc_asym ML_DSA_87 --req_pqc_asym ML_DSA_87 --kem ML_KEM_1024 --pqc_first TRUE --exe_conn DIGEST,CERT,CHAL,MEAS --exe_session KEY_EX,KEY_UPDATE,HEARTBEAT,MEAS
    popd
    unset SPDMRS_USE_PQC
    unset LD_LIBRARY_PATH
    echo_command unset SPDM_CONFIG
    cleanup
}

run_with_spdm_emu_raw_pub_key() {
    echo "Running cross test with spdm-emu raw public key..."
    pushd test_key
    chmod +x ./spdm_responder_emu
    echo_command ./spdm_responder_emu --trans PCI_DOE --cap CACHE,CHAL,MEAS_SIG,MEAS_FRESH,ENCRYPT,MAC,KEY_EX,PSK,ENCAP,HBEAT,KEY_UPD,HANDSHAKE_IN_CLEAR,PUB_KEY_ID --slot_id 0xFF --mut_auth NO &
    popd
    sleep 5
    export SPDMRS_USE_RAW_PUB_KEY=true
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_FEATURES"
    unset SPDMRS_USE_RAW_PUB_KEY
    cleanup

    export SPDMRS_USE_RAW_PUB_KEY=true
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_FEATURES" &
    sleep 20
    pushd test_key
    chmod +x ./spdm_requester_emu
    echo_command ./spdm_requester_emu --trans PCI_DOE --cap CHAL,ENCRYPT,MAC,KEY_EX,PSK,ENCAP,HBEAT,KEY_UPD,PUB_KEY_ID --slot_id 0xFF --mut_auth NO --exe_conn CHAL,MEAS --exe_session KEY_EX,PSK,KEY_UPDATE,HEARTBEAT,MEAS
    popd
    unset SPDMRS_USE_RAW_PUB_KEY
}

run_with_spdm_emu_pqc_raw_pub_key() {
    echo "Running cross test with spdm-emu PQC (ML-DSA + ML-KEM) raw public key..."
    echo_command export SPDM_CONFIG="etc/pqc_config.json"
    # Force build.rs to regenerate config.rs with PQC buffer sizes.
    # build.rs writes to spdmlib/src/config.rs (a shared source file),
    # which may have been overwritten by prior non-PQC test builds.
    rm -f spdmlib/src/config.rs
    pushd test_key
    chmod +x ./spdm_responder_emu
    # spdm-emu binaries are dynamically linked against a custom OpenSSL
    # (libcrypto.so.3) with PQC/ML-DSA support, shipped in test_key/.
    export LD_LIBRARY_PATH=$(pwd):${LD_LIBRARY_PATH:-}
    echo_command ./spdm_responder_emu --trans PCI_DOE --cap CACHE,CHAL,MEAS_SIG,MEAS_FRESH,ENCRYPT,MAC,KEY_EX,ENCAP,HBEAT,KEY_UPD,HANDSHAKE_IN_CLEAR,PUB_KEY_ID,CHUNK --slot_id 0xFF --mut_auth NO --pqc_asym ML_DSA_87 --kem ML_KEM_1024 --pqc_first TRUE &
    popd
    sleep 5
    export SPDMRS_USE_PQC=true
    export SPDMRS_USE_RAW_PUB_KEY=true
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_PQC_FEATURES"
    unset SPDMRS_USE_PQC
    unset SPDMRS_USE_RAW_PUB_KEY
    cleanup

    export SPDMRS_USE_PQC=true
    export SPDMRS_USE_RAW_PUB_KEY=true
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_PQC_FEATURES" &
    sleep 20
    pushd test_key
    chmod +x ./spdm_requester_emu
    export LD_LIBRARY_PATH=$(pwd):${LD_LIBRARY_PATH:-}
    echo_command ./spdm_requester_emu --trans PCI_DOE --cap CHAL,ENCRYPT,MAC,KEY_EX,ENCAP,HBEAT,KEY_UPD,PUB_KEY_ID,CHUNK --slot_id 0xFF --mut_auth NO --pqc_asym ML_DSA_87 --kem ML_KEM_1024 --pqc_first TRUE --exe_conn CHAL,MEAS --exe_session KEY_EX,KEY_UPDATE,HEARTBEAT,MEAS
    popd
    unset SPDMRS_USE_PQC
    unset SPDMRS_USE_RAW_PUB_KEY
    unset LD_LIBRARY_PATH
    echo_command unset SPDM_CONFIG
}

run() {
    # Every crypto config — spdm-ring, spdm-mbedtls, spdm-ring+spdm-aws-lc,
    # spdm-mbedtls+spdm-aws-lc, and standalone spdm-aws-lc (no ring/mbedtls) —
    # runs the same matrix below. aws-lc is a full backend, so the standalone row
    # exercises the classical passes too; the *_pqc_* passes append spdm-aws-lc
    # and only do real work once PQC is negotiated.
    run_basic_test
    run_rust_spdm_emu
    run_rust_spdm_emu_supported_algs
    run_rust_spdm_emu_raw_pub_key
    run_rust_spdm_emu_mut_auth
    run_rust_spdm_emu_mandatory_mut_auth
    run_rust_spdm_emu_pqc_raw_pub_key
    run_rust_spdm_emu_pqc_cert_chain
    run_rust_spdm_emu_pqc_mut_auth
    run_rust_spdm_emu_pqc_mandatory_mut_auth
}

CHECK_OPTION=false
BUILD_OPTION=false
RUN_OPTION=false
TARGET_OPTION=x86_64-unknown-none
PREBUILD_ARGS=""

process_args() {
    while getopts ":cbt:rfh" option; do
        case "${option}" in
            c)
                CHECK_OPTION=true
            ;;
            b)
                BUILD_OPTION=true
            ;;
            t)
                TARGET_OPTION=${OPTARG}
                PREBUILD_ARGS="-t ${TARGET_OPTION}"
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
    ./sh_script/pre-build.sh ${PREBUILD_ARGS}

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
            run_with_spdm_emu_supported_algs
            run_with_spdm_emu_raw_pub_key
            run_with_spdm_emu_mut_auth
            run_with_spdm_emu_mandatory_mut_auth
            run_with_spdm_emu_pqc_raw_pub_key
            run_with_spdm_emu_pqc_cert_chain
            run_with_spdm_emu_pqc_mut_auth
        fi
    fi
}

process_args "$@"
main

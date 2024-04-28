#!/bin/bash

set -euo pipefail

export RUST_MIN_STACK=10485760
RUSTFLAGS=${RUSTFLAGS:-}

usage() {
    cat <<EOM
Usage: $(basename "$0") [OPTION]...
  -e EMU test
  -r Rust test
  -a Run all roll back test
  -h Show help info
EOM
}

echo_command() {
    set -x
    "$@"
    set +x
}

RUN_REQUESTER_FEATURES=${RUN_REQUESTER_FEATURES:-spdm-ring,hashed-transcript-data,async-executor}
RUN_RESPONDER_FEATURES=${RUN_RESPONDER_FEATURES:-spdm-ring,hashed-transcript-data,async-executor}
RUN_REQUESTER_UPDATE_KEYS_FEATURES="${RUN_REQUESTER_FEATURES},test_update_keys"
RUN_REQUESTER_VERIFY_KEYS_FEATURES="${RUN_REQUESTER_FEATURES},test_verify_keys"


run_with_spdm_emu_rsp_rust_req() {
    echo "Running spdm-rs requester to test spdm-emu responder..."
    pushd test_key
    chmod +x ./spdm_responder_emu
    echo_command  ./spdm_responder_emu --trans PCI_DOE &
    popd
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_UPDATE_KEYS_FEATURES"    
}

run_with_spdm_emu_rsp_rust_req_verify() {
    echo "Running spdm-rs requester to test spdm-emu responder..."
    pushd test_key
    chmod +x ./spdm_responder_emu
    echo_command  ./spdm_responder_emu --trans PCI_DOE &
    popd
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_VERIFY_KEYS_FEATURES"
}

run_rust_spdm_emu_test_rsp() {
    echo "Running spdm-rs requester to test spdm-rs responder..."
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_FEATURES" &
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_UPDATE_KEYS_FEATURES"
}

run_rust_spdm_emu_test_rsp_verify() {
    echo "Running spdm-rs requester to test spdm-rs responder..."
    echo_command cargo run -p spdm-responder-emu --no-default-features --features="$RUN_RESPONDER_FEATURES" &
    sleep 5
    echo_command cargo run -p spdm-requester-emu --no-default-features --features="$RUN_REQUESTER_VERIFY_KEYS_FEATURES"
}

EMU_OPTION=false
RUST_OPTION=false
ALL_OPTION=false


process_args() {
    while getopts ":erah" option; do
        case "${option}" in
            e)
                EMU_OPTION=true
            ;;
            r)
                RUST_OPTION=true
            ;;
            a)
                ALL_OPTION=true
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
    if [[ ${EMU_OPTION} == true ]]; then
        run_with_spdm_emu_rsp_rust_req
        run_with_spdm_emu_rsp_rust_req_verify
    fi
    if [[ ${RUST_OPTION} == true ]]; then
        run_rust_spdm_emu_test_rsp
        run_rust_spdm_emu_test_rsp_verify
    fi
    if [[ ${ALL_OPTION} == true ]]; then
        if [ "${RUNNER_OS:-Linux}" == "Linux" ]; then
            run_with_spdm_emu_rsp_rust_req
            run_with_spdm_emu_rsp_rust_req_verify
            run_rust_spdm_emu_test_rsp
            run_rust_spdm_emu_test_rsp_verify
        fi
    fi
}

process_args "$@"
main
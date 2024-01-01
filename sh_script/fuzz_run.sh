#!/bin/bash

# pkill screen

set -eo pipefail

usage() {
    cat <<EOM
Usage: $(basename "$0") [OPTION]...
  -c [Scoverage|Gcoverage]
  -b Build only
  -n <Fuzz crate Name> Run specific fuzz
  -h Show help info
EOM
    exit 0
}

EACH_FUZZ_TIMEOUT=${EACH_FUZZ_TIMEOUT:-10}
FUZZ_HASH_TRANSCRIPT_DATA_FEATURE=${FUZZ_HASH_TRANSCRIPT_DATA_FEATURE:-true}
FUZZ_MUT_AUTH_FEATURE=${FUZZ_MUT_AUTH_FEATURE:-true}
coverage_type=""

process_args() {
    while getopts ":bc:n:h" option; do
        case "${option}" in
        c) coverage_type=${OPTARG} ;;
        b) build_only="true" ;;
        n) fuzz_target_name=${OPTARG} ;;
        h) usage ;;
        *) ;;
        esac
    done
}

process_args "$@"

if [[ ! $PWD =~ rust-spdm$ ]]; then
    pushd ..
fi

if [ ! -d "fuzz-target/out" ]; then
    mkdir fuzz-target/out
else # add rm mkdir:
    rm -rf fuzz-target/out
    mkdir -p fuzz-target/out
fi

for i in fuzz-target/out/*; do

    if [[ ! -f $i/default/crashes ]]; then
        break
    fi

    if [[ "$(ls -A "$i"/default/crashes)" != "" ]]; then
        echo -e "\033[31m There are some crashes \033[0m"
        echo -e "\033[31m Path in fuzz-target/out/$i/default/crashes \033[0m"
        exit
    fi
done

if [ ! "${build_only}" ]; then
    if [ "core" != "$(cat /proc/sys/kernel/core_pattern)" ]; then
        if [ "$(id -u)" -ne 0 ]; then
            sudo su - root <<EOF
        echo core >/proc/sys/kernel/core_pattern;
        pushd /sys/devices/system/cpu;
        echo performance | tee cpu*/cpufreq/scaling_governor;
        popd;
        echo "root path is $PWD";
        exit;
EOF
        else
            echo core >/proc/sys/kernel/core_pattern
            pushd /sys/devices/system/cpu
            echo performance | tee cpu*/cpufreq/scaling_governor
            popd
        fi
    fi
fi

rm -rf fuzz-target/out/*
cmds=(
    "version_rsp"
    "capability_rsp"
    "algorithm_rsp"
    "digest_rsp"
    "certificate_rsp"
    "challenge_rsp"
    "measurement_rsp"
    "keyexchange_rsp"
    "pskexchange_rsp"
    "finish_rsp"
    "psk_finish_rsp"
    "heartbeat_rsp"
    "key_update_rsp"
    "end_session_rsp"
    "vendor_rsp"
    "version_req"
    "capability_req"
    "algorithm_req"
    "digest_req"
    "certificate_req"
    "challenge_req" #remove cert_chain = RSP_CERT_CHAIN_BUFF >> OK
    "measurement_req"
    "key_exchange_req" #remove cert_chain = RSP_CERT_CHAIN_BUFF >> OK
    "psk_exchange_req" #remove cert_chain = RSP_CERT_CHAIN_BUFF >> OK
    "finish_req"       #remove cert_chain = RSP_CERT_CHAIN_BUFF >> OK
    "psk_finish_req"
    "heartbeat_req"
    "key_update_req"
    "end_session_req"
    "vendor_req"
)

mut_auth_cmds=(
    "deliver_encapsulated_response_digest_rsp"
    "deliver_encapsulated_response_certificate_rsp"
    "get_encapsulated_request_rsp"
    "deliver_encapsulated_response_rsp"
    "encapsulated_request_digest_req"
    "encapsulated_request_certificate_req"
    "encapsulated_request_req"
)

buildpackage=''
for i in "${cmds[@]}"; do
    buildpackage="-p $i $buildpackage"
done

if [ "${FUZZ_MUT_AUTH_FEATURE}" == "true" ]; then
    for i in "${mut_auth_cmds[@]}"; do
        buildpackage="-p $i $buildpackage"
    done
fi

if [[ $coverage_type == "Scoverage" ]]; then
    echo "$coverage_type"
    export RUSTFLAGS="-C instrument-coverage"
    export LLVM_PROFILE_FILE='fuzz_run-%p-%m.profraw'
fi

if [[ $coverage_type == "Gcoverage" ]]; then
    echo "$coverage_type"
    export CARGO_INCREMENTAL=0
    export RUSTDOCFLAGS="-Cpanic=abort"
    export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"
fi

if [ "${FUZZ_HASH_TRANSCRIPT_DATA_FEATURE}" == "true" ]; then
    FUZZ_NO_DEFAULT_FEATURES=
else
    FUZZ_NO_DEFAULT_FEATURES="--no-default-features"
fi

if [ "${FUZZ_MUT_AUTH_FEATURE}" == "true" ]; then
    MUT_AUTH_FEATURE=mut-auth
else
    MUT_AUTH_FEATURE=
fi

if [[ $fuzz_target_name ]]; then
    set -x
    cargo afl build --features "fuzz ${MUT_AUTH_FEATURE}" ${FUZZ_NO_DEFAULT_FEATURES} -p "$fuzz_target_name"
    set +x
else
    set -x
    cargo afl build --features "fuzz ${MUT_AUTH_FEATURE}" ${FUZZ_NO_DEFAULT_FEATURES} $buildpackage
    set -x
fi

run_fuzz_target() {
    fuzz_target_name=$1
    fuzz_target_out_dir="${CARGO_TARGET_DIR:-target}"/fuzz-target/out/${fuzz_target_name}
    mkdir -p "$fuzz_target_out_dir"

    set -x
    cargo afl fuzz -V "${EACH_FUZZ_TIMEOUT}" -i fuzz-target/in/"${fuzz_target_name}" -o "$fuzz_target_out_dir" "${CARGO_TARGET_DIR:-target}"/debug/"${fuzz_target_name}"
    set +x

    # Test for crash
    if [ -z "$(ls -A "$fuzz_target_out_dir"/default/crashes)" ]; then
        echo "fuzzing ${fuzz_target_name} test PASS in ${EACH_FUZZ_TIMEOUT} seconds..."
    else
        echo "fuzzing ${fuzz_target_name} test FAILED in ${EACH_FUZZ_TIMEOUT} seconds..."
        for file in $(find $fuzz_target_out_dir/default/crashes -type f -name "id*" -print); do
            echo "Crash file [encode_base64_string]: (between ========= and =========)"
            echo "========="
            cat "$file" | base64
            echo "========="
            echo "Use echo -n "[encode_base64_string]" | base64 -d > seed.raw to decode, replace [encode_base64_string]"
            cargo run -p ${fuzz_target_name} --no-default-features -- $file
        done
        exit 1
    fi
}

if [ ! "${build_only}" ]; then
    if [[ $fuzz_target_name ]]; then
        run_fuzz_target "$fuzz_target_name"
    else
        for ((i = 0; i < ${#cmds[*]}; i++)); do
            run_fuzz_target "${cmds[$i]}"
        done
        if [ "${FUZZ_MUT_AUTH_FEATURE}" == "true" ]; then
            for ((i = 0; i < ${#mut_auth_cmds[*]}; i++)); do
                run_fuzz_target "${mut_auth_cmds[$i]}"
            done
        fi
        echo "All fuzzing tests PASS"
    fi
fi

if [[ $coverage_type == "Scoverage" || $coverage_type == "Gcoverage" ]]; then
    set -x
    rm -rf "${CARGO_TARGET_DIR:-target}"/debug/fuzz_coverage
    grcov --branch --guess-directory-when-missing --ignore-not-existing --llvm \
        --output-type html \
        --binary-path "${CARGO_TARGET_DIR:-target}"/debug/ \
        --source-dir ./ \
        --output-path "${CARGO_TARGET_DIR:-target}"/debug/fuzz_coverage \
        "$(find . -name "*.profraw")"
    set +x
    unset RUSTFLAGS
    unset LLVM_PROFILE_FILE
    unset CARGO_INCREMENTAL
    unset RUSTDOCFLAGS
    unset RUSTFLAGS
    echo "-------------------over--------------------------"
fi

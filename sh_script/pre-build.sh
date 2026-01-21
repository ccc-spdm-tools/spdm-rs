#!/bin/bash

TARGET_OPTION="x86_64-unknown-none"
process_args() {
    while getopts ":t:" option; do
        case "${option}" in
            t)
                TARGET_OPTION=${OPTARG}
            ;;
            *)
                echo "Invalid option '-$OPTARG'"
                exit 1
            ;;
        esac
    done
}

patch-ring() {
    # apply the patch set for ring
    pushd external/ring
    git reset --hard 2723abbca9e83347d82b056d5b239c6604f786df
    git clean -xdf
    case "$TARGET_OPTION" in
        "x86_64-unknown-none")
            git apply ../patches/ring/0001-Support-x86_64-unknown-none-target.patch
            git apply ../patches/ring/0002-Disable-checks-for-SSE-and-SSE2.patch
            git apply ../patches/ring/0003-EphemeralPrivateKey-from-bytes.patch
        ;;
        *)
            echo "Unsupported target for ring, builds may not work!"
        ;;
    esac
    popd
}

patch-webpki() {
  # apply the patch set for webpki
  pushd external/webpki
  git reset --hard v/0.103.6 # version set to 0.103.6
  git clean -xdf
  git apply ../patches/webpki/0001-src-x509.rs-add-skip-unsupported-critical-extensions-check.patch
  popd
}

format-patch() {
    patch-ring
    patch-webpki
}

process_args "$@"
format-patch

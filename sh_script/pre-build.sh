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
    git reset --hard 464d367252354418a2c17feb806876d4d89a8508
    git clean -xdf
    case "$TARGET_OPTION" in
        "x86_64-unknown-none")
            git apply ../patches/ring/0001-Support-x86_64-unknown-none-target.patch
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
    git reset --hard f84a538a5cd281ba1ffc0d54bbe5824cf5969703
    git clean -xdf

    # apply the patch to get rid of unused import warning during compilation
    # https://github.com/briansmith/webpki/commit/8f81719df5b47bda95f15a7655be811e52e12997
    git cherry-pick 8f81719df5b47bda95f15a7655be811e52e12997

    git apply ../patches/webpki/0001-Add-support-for-verifying-certificate-chain-with-EKU.patch
    popd
}

format-patch() {
    patch-ring
    patch-webpki
}

process_args "$@"
format-patch

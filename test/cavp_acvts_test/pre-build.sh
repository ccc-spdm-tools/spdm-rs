#!/bin/bash

patch-ring() {
    # apply the patch set for ring
    pushd ../../external/ring
    git apply ../../test/cavp_acvts_test/0001-Add-new-methods-for-private-key-handling-and-public-.patch
    popd
}

patch-ring

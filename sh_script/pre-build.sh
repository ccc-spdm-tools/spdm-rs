#!/bin/bash

format-patch() {
    # apply the patch set for ring
    pushd external/ring
    git reset --hard 464d367252354418a2c17feb806876d4d89a8508
    git clean -xdf
    git apply ../patches/ring/0001-Support-x86_64-unknown-none-target.patch
    popd
    
    # apply the patch set for webpki
    pushd external/webpki
    git reset --hard f84a538a5cd281ba1ffc0d54bbe5824cf5969703
    git clean -xdf
    git apply ../patches/webpki/0001-Add-support-for-verifying-certificate-chain-with-EKU.patch
    popd
}

format-patch

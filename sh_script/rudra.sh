#!/bin/bash

type rudra

if [[ $? != 0 ]]; then
    echo -e "\033[31m Please install rudra \033[0m"
    exit
fi

if [[ ! $PWD =~ rust-spdm$ ]];then
    pushd ..
fi

orgin=`cat rust-toolchain`
echo "nightly-2021-08-20" > rust-toolchain
echo $orgin

paths=(
    "codec"
    "spdmlib"
    "mctp_transport"
    "pcidoe_transport"
    
)

for i in ${paths[@]};do
echo $PWD/$i
pushd $PWD/$i
cargo rudra
popd
done

echo $orgin > rust-toolchain
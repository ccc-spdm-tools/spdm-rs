#!/bin/bash
# Auto gen cert script.

GENERATE_CERT_DIR=gen

mkdir $GENERATE_CERT_DIR
pushd $GENERATE_CERT_DIR

openssl req -nodes -x509 -days 3650 -newkey rsa:4096 -keyout ca.key -out ca.cert -sha256 -subj "/CN=DMTF libspdm RSA CA"
openssl rsa -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey rsa:3072 -keyout inter.key -out inter.req -sha256 -batch -subj "/CN=DMTF libspdm RSA intermediate cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha256 -days 3650 -set_serial 1

generate_cert() {
    cert_profile=$1
    mkdir -p $cert_profile
    pushd $cert_profile
    openssl req -nodes -newkey rsa:2048 -keyout cert.key -out cert.req -sha256 -batch -subj "/CN=DMTF libspdm RSA cert $cert_profile"
    openssl x509 -req -in cert.req -out cert.der -CA ../inter.cert -CAkey ../inter.key -sha256 -days 3650 -set_serial 2 -extensions $cert_profile -extfile ../../openssl.cnf
    popd
}

generate_cert v3_end_with_eku_spdm_oid_3
generate_cert v3_end_with_eku_spdm_oid_4
generate_cert v3_end_with_eku_spdm_oid_3_and_4
generate_cert v3_end_without_eku
generate_cert v3_end_with_eku_spdm_without_spdm_oid

popd

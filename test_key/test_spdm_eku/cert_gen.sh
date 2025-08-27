#!/bin/bash
# Auto gen cert script.

GENERATE_CERT_DIR=gen

mkdir $GENERATE_CERT_DIR
pushd $GENERATE_CERT_DIR

openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-384
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca.key -out ca.cert -sha384 -extensions v3_ca -config ../openssl.cnf -batch -subj "/CN=DMTF libspdm ECP384 CA" 
openssl req -nodes -newkey ec:param.pem -keyout inter.key -out inter.req -sha384 -batch -subj "/CN=DMTF libspdm ECP384 intermediate cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha384 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf

openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der

generate_cert() {
    cert_profile=$1
    mkdir -p $cert_profile
    pushd $cert_profile

    openssl req -nodes -newkey ec:../param.pem -keyout cert.key -out cert.req -sha384 -batch -subj "/C=CN/ST=Shanghai/L=Shanghai/O=DMTF/OU=Security/CN=SPDM RS RSA END"
    openssl x509 -req -in cert.req -out cert.pem -CA ../inter.cert -CAkey ../inter.key -sha384 -days 3650 -set_serial 2 -extensions $cert_profile -extfile ../../openssl.cnf
    openssl asn1parse -in cert.pem -out cert.pem.der
    cat ../ca.cert.der ../inter.cert.der cert.pem.der > cert.der
    popd
}

generate_cert v3_end_with_eku_spdm_oid_3
generate_cert v3_end_with_eku_spdm_oid_4
generate_cert v3_end_with_eku_spdm_oid_3_and_4
generate_cert v3_end_without_eku
generate_cert v3_end_with_eku_spdm_without_spdm_oid

popd

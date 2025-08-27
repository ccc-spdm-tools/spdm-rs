Some certs for test spdm extended Key usage authentication OIDs.

See [SPDM Spec 1.2](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.2.1.pdf)  
Extended Key Usage authentication OIDs

How to generate:

openssl --version
OpenSSL 3.5.1 1

pushd test_key/test_spdm_eku
./cert_gen.sh
popd

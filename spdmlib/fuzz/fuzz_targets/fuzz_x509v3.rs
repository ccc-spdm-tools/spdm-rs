#![no_main]

use libfuzzer_sys::fuzz_target;

pub use fuzzlib::*;

include!("../../src/crypto/x509v3.rs");

fuzz_target!(|cert: &[u8]| {
    for f in [
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072,
        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096,
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072,
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096,
    ] {
        let _ = check_cert_chain_format(cert, f);
        let _ = check_leaf_certificate(cert, true);
        let _ = check_leaf_certificate(cert, false);
        let _ = is_root_certificate(cert);
    }
});

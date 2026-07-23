// Copyright (c) 2023, 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use spdmlib::crypto::SpdmCertOperation;
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_CERT};

// =============================================================================
// spdm_x509 implementation
//
// The certificate-chain operations delegate to the spdm_x509 library rather
// than to the mbedtls C X.509 verifier. spdm_x509 is built here with its
// mbedtls backend, so classical (RSA/ECC) certificate signatures are verified
// by mbedtls and no ring is linked. spdm_x509 parses the chain itself and
// dispatches classical signatures to that mbedtls backend and post-quantum
// (ML-DSA / FIPS 204) signatures to the registered PQC verifier hook — mbedtls
// cannot verify ML-DSA, so delegating here is what lets PQC certificate chains
// work with the mbedtls backend.
// =============================================================================

pub static DEFAULT: SpdmCertOperation = SpdmCertOperation {
    get_cert_from_cert_chain_cb: get_cert_from_cert_chain_x509,
    verify_cert_chain_cb: verify_cert_chain_x509,
};

fn get_cert_from_cert_chain_x509(cert_chain: &[u8], index: isize) -> SpdmResult<(usize, usize)> {
    spdm_x509::x509::chain::get_cert_from_cert_chain(cert_chain, index)
        .map_err(|_| SPDM_STATUS_INVALID_CERT)
}

fn verify_cert_chain_x509(
    cert_chain: &[u8],
    base_asym_algo: Option<u32>,
    base_hash_algo: Option<u32>,
) -> SpdmResult {
    spdm_x509::x509::chain::verify_cert_chain_with_options(
        cert_chain,
        base_asym_algo,
        base_hash_algo,
    )
    .map_err(|_| SPDM_STATUS_INVALID_CERT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_cert_chain_rsa3072() {
        let cert_chain =
            &include_bytes!("../../test_key/rsa3072/bundle_responder.certchain.der")[..];
        assert!(verify_cert_chain_x509(cert_chain, None, None).is_ok());
    }

    #[test]
    fn test_verify_cert_chain_ecp384() {
        let cert_chain =
            &include_bytes!("../../test_key/ecp384/bundle_responder.certchain.der")[..];
        assert!(verify_cert_chain_x509(cert_chain, None, None).is_ok());
    }

    #[test]
    fn test_get_cert_from_cert_chain_leaf() {
        let cert_chain =
            &include_bytes!("../../test_key/ecp384/bundle_responder.certchain.der")[..];
        assert!(get_cert_from_cert_chain_x509(cert_chain, -1).is_ok());
    }
}

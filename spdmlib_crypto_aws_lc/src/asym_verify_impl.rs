// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Traditional (RSA/ECDSA) SPDM message-signature verification via aws-lc-rs,
// for the standalone aws-lc backend. Ported from the ring backend; aws-lc-rs
// exposes a ring-compatible signature API.

use aws_lc_rs::signature::{self, UnparsedPublicKey};
use log::error;
use spdmlib::crypto::SpdmAsymVerify;
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_CERT, SPDM_STATUS_VERIF_FAIL};
use spdmlib::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmDer, SpdmSignatureStruct};

// Parse DER length field. Returns (bytes_consumed_for_length, value)
fn parse_der_length(input: &[u8]) -> Option<(usize, usize)> {
    if input.is_empty() {
        return None;
    }
    let first = input[0] as usize;
    if (first & 0x80) == 0 {
        // short form
        return Some((1, first));
    }
    let num = first & 0x7f;
    if input.len() < 1 + num {
        return None;
    }
    let mut val: usize = 0;
    for i in 0..num {
        val = (val << 8) | (input[1 + i] as usize);
    }
    Some((1 + num, val))
}

// Extract the BIT STRING payload (skipping the unused-bits byte) from a SubjectPublicKeyInfo
// or any DER blob containing a BIT STRING. Returns the slice containing the raw public key
// (for uncompressed EC points this will start with 0x04 followed by X||Y).
pub(crate) fn extract_spki_pubkey(spki: &[u8]) -> Option<&[u8]> {
    let mut i = 0usize;
    while i < spki.len() {
        // look for BIT STRING tag (0x03)
        if spki[i] == 0x03 {
            // parse length starting at i+1
            if let Some((len_of_len, content_len)) = parse_der_length(&spki[i + 1..]) {
                let content_start = i + 1 + len_of_len;
                if content_start + content_len <= spki.len() && content_len >= 1 {
                    // first byte of BIT STRING is number of unused bits
                    let unused = spki[content_start];
                    if unused <= 7 {
                        let key_start = content_start + 1;
                        let key_len = content_len - 1;
                        if key_start + key_len <= spki.len() {
                            return Some(&spki[key_start..(key_start + key_len)]);
                        }
                    }
                }
            }
        }
        i += 1;
    }
    None
}

pub static DEFAULT: SpdmAsymVerify = SpdmAsymVerify {
    verify_cb: asym_verify,
};

fn asym_verify(
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    der: SpdmDer,
    data: &[u8],
    signature: &SpdmSignatureStruct,
) -> SpdmResult {
    if signature.data_size != base_asym_algo.get_sig_size() {
        return Err(SPDM_STATUS_VERIF_FAIL);
    }

    match der {
        SpdmDer::SpdmDerPubKeyRfc7250(raw_pub_key) => {
            // Extract the public key bytes from an RFC7250 SubjectPublicKeyInfo DER
            let pub_key = match extract_spki_pubkey(raw_pub_key) {
                Some(pk) => pk,
                None => return Err(SPDM_STATUS_VERIF_FAIL),
            };

            // RFC7250 uses FIXED signature format (not ASN.1 DER) for ECDSA
            match base_asym_algo {
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256
                | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384 => {
                    // RFC7250 uses FIXED format. Ring only supports matching curve+hash:
                    // P256+SHA256 and P384+SHA384. Cross-combinations only exist in ASN1 format.
                    let sign_algorithm = match (base_hash_algo, base_asym_algo) {
                        (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                        ) => &signature::ECDSA_P256_SHA256_FIXED,
                        (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                        ) => &signature::ECDSA_P384_SHA384_FIXED,
                        _ => {
                            // Unsupported combination for RFC7250
                            return Err(SPDM_STATUS_VERIF_FAIL);
                        }
                    };
                    let pk = UnparsedPublicKey::new(sign_algorithm, pub_key);
                    pk.verify(data, &signature.data[..signature.data_size as usize])
                        .map_err(|_| SPDM_STATUS_VERIF_FAIL)
                }
                SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048
                | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072
                | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096
                | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048
                | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
                | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096 => {
                    let sign_algorithm = match (base_hash_algo, base_asym_algo) {
                        (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
                        )
                        | (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072,
                        )
                        | (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096,
                        ) => &signature::RSA_PKCS1_2048_8192_SHA256,
                        (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048,
                        )
                        | (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072,
                        )
                        | (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096,
                        ) => &signature::RSA_PSS_2048_8192_SHA256,
                        (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
                        )
                        | (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072,
                        )
                        | (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096,
                        ) => &signature::RSA_PKCS1_2048_8192_SHA384,
                        (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048,
                        )
                        | (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072,
                        )
                        | (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096,
                        ) => &signature::RSA_PSS_2048_8192_SHA384,
                        (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_512,
                            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
                        )
                        | (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_512,
                            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072,
                        )
                        | (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_512,
                            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096,
                        ) => &signature::RSA_PKCS1_2048_8192_SHA512,
                        (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_512,
                            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048,
                        )
                        | (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_512,
                            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072,
                        )
                        | (
                            SpdmBaseHashAlgo::TPM_ALG_SHA_512,
                            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096,
                        ) => &signature::RSA_PSS_2048_8192_SHA512,
                        _ => {
                            return Err(SPDM_STATUS_VERIF_FAIL);
                        }
                    };
                    let pk = UnparsedPublicKey::new(sign_algorithm, pub_key);
                    pk.verify(data, &signature.data[..signature.data_size as usize])
                        .map_err(|_| SPDM_STATUS_VERIF_FAIL)
                }
                _ => Err(SPDM_STATUS_VERIF_FAIL),
            }
        }
        SpdmDer::SpdmDerCertChain(public_cert_der) => asym_verify_with_spdm_x509(
            base_hash_algo,
            base_asym_algo,
            public_cert_der,
            data,
            signature,
        ),
    }
}

// =============================================================================
// spdm_x509 implementation
// =============================================================================

fn asym_verify_with_spdm_x509(
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    public_cert_der: &[u8],
    data: &[u8],
    signature: &SpdmSignatureStruct,
) -> SpdmResult {
    // Get the leaf certificate using spdm_x509
    let (leaf_begin, leaf_end) =
        spdm_x509::x509::chain::get_cert_from_cert_chain(public_cert_der, -1).map_err(|e| {
            error!("Failed to get leaf cert: {:?}", e);
            SPDM_STATUS_INVALID_CERT
        })?;

    let leaf_cert_der = &public_cert_der[leaf_begin..leaf_end];

    // Parse the certificate using spdm_x509 to get the public key
    let cert = spdm_x509::Certificate::from_der(leaf_cert_der).map_err(|e| {
        error!("Failed to parse certificate: {:?}", e);
        SPDM_STATUS_INVALID_CERT
    })?;

    let pub_key_info = &cert.tbs_certificate.subject_public_key_info;
    let pub_key_bytes = pub_key_info.subject_public_key.raw_bytes();

    match base_asym_algo {
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256
        | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384 => {
            // For ECDSA, we need to convert the signature from FIXED format to ASN.1 DER format
            // Ring verifies ECDSA signatures in ASN.1 DER format

            // Convert signature to DER format
            let mut der_signature = [0u8; spdmlib::protocol::ECDSA_ECC_NIST_P384_SIG_SIZE + 8];
            let der_sign_size = ecc_signature_bin_to_der(signature.as_ref(), &mut der_signature)?;

            // Select the appropriate algorithm (ASN.1 versions, not FIXED)
            let sign_algorithm = match (base_hash_algo, base_asym_algo) {
                (
                    SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                    SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                ) => &signature::ECDSA_P256_SHA256_ASN1,
                (
                    SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                    SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                ) => &signature::ECDSA_P256_SHA384_ASN1,
                (
                    SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                    SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                ) => &signature::ECDSA_P384_SHA256_ASN1,
                (
                    SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                    SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                ) => &signature::ECDSA_P384_SHA384_ASN1,
                _ => {
                    error!(
                        "Unsupported ECDSA combination: hash={:?}, asym={:?}",
                        base_hash_algo, base_asym_algo
                    );
                    return Err(SPDM_STATUS_VERIF_FAIL);
                }
            };

            let pk = UnparsedPublicKey::new(sign_algorithm, pub_key_bytes);
            match pk.verify(data, &der_signature[..der_sign_size]) {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!("ECDSA signature verification failed: {:?}", e);
                    Err(SPDM_STATUS_VERIF_FAIL)
                }
            }
        }
        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048
        | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072
        | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096 => {
            // For RSA, use ring signature verification
            let sign_algorithm = match (base_hash_algo, base_asym_algo) {
                (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
                    &signature::RSA_PKCS1_2048_8192_SHA256
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
                    &signature::RSA_PSS_2048_8192_SHA256
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
                    &signature::RSA_PKCS1_2048_8192_SHA384
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
                    &signature::RSA_PSS_2048_8192_SHA384
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
                    &signature::RSA_PKCS1_2048_8192_SHA512
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
                    &signature::RSA_PSS_2048_8192_SHA512
                }
                _ => {
                    error!(
                        "Unsupported RSA combination: hash={:?}, asym={:?}",
                        base_hash_algo, base_asym_algo
                    );
                    return Err(SPDM_STATUS_VERIF_FAIL);
                }
            };

            let pk = UnparsedPublicKey::new(sign_algorithm, pub_key_bytes);
            match pk.verify(data, &signature.data[..signature.data_size as usize]) {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!("RSA signature verification failed: {:?}", e);
                    Err(SPDM_STATUS_VERIF_FAIL)
                }
            }
        }
        _ => {
            error!("Unsupported algorithm: {:?}", base_asym_algo);
            Err(SPDM_STATUS_VERIF_FAIL)
        }
    }
}

// add ASN.1 for the ECDSA binary signature
fn ecc_signature_bin_to_der(signature: &[u8], der_signature: &mut [u8]) -> SpdmResult<usize> {
    let sign_size = signature.len();
    assert!(
        // prevent API misuse
        sign_size == spdmlib::protocol::ECDSA_ECC_NIST_P256_SIG_SIZE
            || sign_size == spdmlib::protocol::ECDSA_ECC_NIST_P384_SIG_SIZE
    );
    let half_size = sign_size / 2;

    let mut r_index = half_size;
    for (i, item) in signature.iter().enumerate().take(half_size) {
        if *item != 0 {
            r_index = i;
            break;
        }
    }
    let r_size = half_size - r_index;
    let r = &signature[r_index..half_size];

    let mut s_index = half_size;
    for i in 0..half_size {
        if signature[i + half_size] != 0 {
            s_index = i;
            break;
        }
    }
    let s_size = half_size - s_index;
    let s = &signature[half_size + s_index..sign_size];
    if r_size == 0 || s_size == 0 {
        return Ok(0);
    }

    let der_r_size = if r[0] < 0x80 { r_size } else { r_size + 1 };
    let der_s_size = if s[0] < 0x80 { s_size } else { s_size + 1 };
    // der_sign_size includes: 0x30 _ 0x02 _ [der_r_size] 0x02 _ [der_s_size]
    let der_sign_size = der_r_size + der_s_size + 6;

    if der_signature.len() < der_sign_size {
        error!("der_signature too small");
        return Err(SPDM_STATUS_VERIF_FAIL);
    }

    if der_r_size > u8::MAX as usize
        || der_s_size > u8::MAX as usize
        || der_sign_size > u8::MAX as usize
    {
        error!("size check fails!");
        return Err(SPDM_STATUS_VERIF_FAIL);
    }

    der_signature[0] = 0x30u8;
    der_signature[1] = (der_sign_size - 2) as u8;
    der_signature[2] = 0x02u8;
    der_signature[3] = der_r_size as u8;
    if r[0] < 0x80 {
        der_signature[4..(4 + r_size)].copy_from_slice(r);
    } else {
        der_signature[4] = 0u8;
        der_signature[5..(5 + r_size)].copy_from_slice(r);
    }
    der_signature[4 + der_r_size] = 0x02u8;
    der_signature[5 + der_r_size] = der_s_size as u8;

    if s[0] < 0x80 {
        der_signature[(6 + der_r_size)..(6 + der_r_size + s_size)].copy_from_slice(s);
    } else {
        der_signature[6 + der_r_size] = 0u8;
        der_signature[(7 + der_r_size)..(7 + der_r_size + s_size)].copy_from_slice(s);
    }

    Ok(der_sign_size)
}
// NOTE: The ring backend's unit tests for this module rely on a `public_cert.der`
// test asset local to that crate. The aws-lc classical asym_verify path is
// exercised end-to-end by the emulator interaction test (standalone aws-lc) and
// by the cert-chain tests in `cert_operation_impl`.

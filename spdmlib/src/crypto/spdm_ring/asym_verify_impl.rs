// Copyright (c) 2021, 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto::SpdmAsymVerify;
use crate::error::{SpdmResult, SPDM_STATUS_INVALID_CERT, SPDM_STATUS_VERIF_FAIL};
use crate::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmDer, SpdmSignatureStruct};
use ring::signature::{self, UnparsedPublicKey};

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
            let mut der_signature = [0u8; crate::protocol::ECDSA_ECC_NIST_P384_SIG_SIZE + 8];
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
        sign_size == crate::protocol::ECDSA_ECC_NIST_P256_SIG_SIZE
            || sign_size == crate::protocol::ECDSA_ECC_NIST_P384_SIG_SIZE
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case0_ecc_signature_bin_to_der() {
        let signature = &mut [0x00u8; 64];
        for i in 10..signature.len() {
            signature[i] = 0x10;
        }

        let der_signature = &mut [0u8; 64];

        let der_sign_size = ecc_signature_bin_to_der(signature, der_signature).unwrap();
        assert_eq!(der_sign_size, 60);
    }
    #[test]
    fn test_case1_ecc_signature_bin_to_der() {
        let signature = &mut [0x00u8; 64];
        for i in 10..signature.len() {
            signature[i] = 0xff;
        }

        let der_signature = &mut [0u8; 64];

        let der_sign_size = ecc_signature_bin_to_der(signature, der_signature).unwrap();
        assert_eq!(der_sign_size, 62);
    }
    #[test]
    fn test_case2_ecc_signature_bin_to_der() {
        let signature = &mut [0x0u8; 64];
        let der_signature = &mut [0u8; 64];
        signature[63] = 0xff;
        ecc_signature_bin_to_der(signature, der_signature).unwrap();
    }
    #[test]
    #[should_panic]
    fn test_case3_ecc_signature_bin_to_der() {
        let signature = &mut [0xffu8; 64];
        let der_signature = &mut [0u8; 64];
        ecc_signature_bin_to_der(signature, der_signature).unwrap();
    }
    #[test]
    fn test_case0_asym_verify() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let base_asym_algo = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
        let mut signature = SpdmSignatureStruct {
            data_size: 512,
            data: [0x00u8; crate::protocol::SPDM_MAX_ASYM_SIG_SIZE],
        };
        signature.data[250] = 0x10;
        signature.data[510] = 0x10;

        let public_cert_der = &include_bytes!("public_cert.der")[..];
        let data = &mut [0x10u8; 4096];

        let asym_verify = asym_verify(
            base_hash_algo,
            base_asym_algo,
            SpdmDer::SpdmDerCertChain(public_cert_der),
            data,
            &signature,
        );
        assert!(asym_verify.is_err());
    }
    #[test]
    fn test_case1_asym_verify() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let base_asym_algo = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        let mut signature = SpdmSignatureStruct {
            data_size: 512,
            data: [0x00u8; crate::protocol::SPDM_MAX_ASYM_SIG_SIZE],
        };
        signature.data[250] = 0x10;
        signature.data[510] = 0x10;

        let public_cert_der = &include_bytes!("public_cert.der")[..];
        let data = &mut [0x10u8; 4096];

        let asym_verify = asym_verify(
            base_hash_algo,
            base_asym_algo,
            SpdmDer::SpdmDerCertChain(public_cert_der),
            data,
            &signature,
        );
        assert!(asym_verify.is_err());
    }
    #[test]
    fn test_case2_asym_verify() {
        let base_hash_algo = [
            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmBaseHashAlgo::TPM_ALG_SHA_512,
        ];
        let base_asym_algo = [
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096,
        ];
        let mut signature = SpdmSignatureStruct {
            data_size: 512,
            data: [0x00u8; crate::protocol::SPDM_MAX_ASYM_SIG_SIZE],
        };
        signature.data[250] = 0x10;
        signature.data[510] = 0x10;

        let public_cert_der = &include_bytes!("public_cert.der")[..];
        let data = &mut [0x10u8; 4096];

        for base_hash_algo in base_hash_algo.iter() {
            for base_asym_algo in base_asym_algo.iter() {
                let asym_verify = asym_verify(
                    *base_hash_algo,
                    *base_asym_algo,
                    SpdmDer::SpdmDerCertChain(public_cert_der),
                    data,
                    &signature,
                );
                assert!(asym_verify.is_err());
            }
        }
    }
    #[test]
    fn test_case3_asym_verify() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let base_asym_algo = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        let mut signature = SpdmSignatureStruct {
            data_size: 512,
            data: [0x00u8; crate::protocol::SPDM_MAX_ASYM_SIG_SIZE],
        };
        signature.data[250] = 0x10;
        signature.data[510] = 0x10;

        let public_cert_der = &include_bytes!("public_cert.der")[..];
        let data = &mut [0x10u8; 4096];

        let asym_verify = asym_verify(
            base_hash_algo,
            base_asym_algo,
            SpdmDer::SpdmDerCertChain(public_cert_der),
            data,
            &signature,
        );
        assert!(asym_verify.is_err());
    }

    #[test]
    fn test_extract_spki_pubkey_rfc7250() {
        // The SPKI bytes (mixed hex/decimal from user input). We'll construct the byte array
        // as provided in the earlier conversation.
        let spki = [
            0x30, 0x4C, 0x30, 0x0A, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
            0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x39, 0xAC, 0xA8, 0x8D,
            0xE8, 0xBF, 0xA6, 0xAC, 0x22, 0x97, 0x49, 0x5D, 0x31, 0x40, 0xF6, 0xEE, 0xA0, 0xC5,
            0x70, 0x27, 0xF5, 0x1F, 0xB7, 0x60, 0xE5, 0x4A, 0xF9, 0x01, 0xFB, 0xC4, 0xD1, 0x5F,
            0x75, 0x00, 0x59, 0x77, 0x9D, 0xF9, 0x24, 0xC4, 0xAE, 0xFC, 0xAC, 0xCE, 0x74, 0xBE,
            0x5E, 0x90, 0xD4, 0xB9, 0x21, 0xC5, 0x18, 0x0A, 0x25, 0x91, 0xD3, 0x4D, 0x44, 0x75,
            0x65, 0x39, 0xCF, 0x02, 0x11, 0xBB, 0x36, 0x3D, 0x46, 0xE6, 0x50, 0x5E, 0x39, 0x93,
            0xD2, 0xBE, 0x43, 0xFB, 0xEB, 0x26, 0x1F, 0x40, 0xE4, 0xBF, 0x52, 0xD3, 0xF7, 0x79,
            0x09, 0xF7, 0xD4, 0x5A, 0x70, 0x19, 0x81, 0x94,
        ];

        let extracted = extract_spki_pubkey(&spki).expect("should extract pubkey");
        // Expect uncompressed point starting with 0x04 and 96 bytes following (X||Y): total 97
        assert_eq!(extracted.len(), 97);
        assert_eq!(extracted[0], 0x04);
        // Check a few known bytes from X and Y
        assert_eq!(extracted[1], 0x39);
        assert_eq!(extracted[2], 0xAC);
        assert_eq!(extracted[96], 0x94);
    }
}

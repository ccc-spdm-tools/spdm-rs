// Copyright (c) 2021, 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::crypto::{x509v3, SpdmAsymVerify};
use crate::error::{SpdmResult, SPDM_STATUS_INVALID_CERT, SPDM_STATUS_VERIF_FAIL};
use crate::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmDer, SpdmSignatureStruct};
use core::convert::TryFrom;
use ring::signature::{self, UnparsedPublicKey};
use rustls_pki_types::CertificateDer;

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

// Extract the public key bytes from a SubjectPublicKeyInfo DER structure.
// Parses: SEQUENCE { SEQUENCE { AlgorithmIdentifier }, BIT STRING { public key } }
// Returns the BIT STRING payload (skipping the unused-bits byte), which for uncompressed
// EC points will start with 0x04 followed by X||Y.
pub(crate) fn extract_spki_pubkey(spki: &[u8]) -> Option<&[u8]> {
    let mut pos = 0usize;

    // 1. Outer SEQUENCE
    if pos >= spki.len() || spki[pos] != 0x30 {
        return None;
    }
    pos += 1;
    let (len_bytes, _outer_len) = parse_der_length(&spki[pos..])?;
    pos += len_bytes;

    // 2. Skip AlgorithmIdentifier SEQUENCE (tag + length + content)
    if pos >= spki.len() || spki[pos] != 0x30 {
        return None;
    }
    pos += 1;
    let (len_bytes, algo_len) = parse_der_length(&spki[pos..])?;
    pos += len_bytes + algo_len;

    // 3. Parse BIT STRING
    if pos >= spki.len() || spki[pos] != 0x03 {
        return None;
    }
    pos += 1;
    let (len_bytes, bit_string_len) = parse_der_length(&spki[pos..])?;
    pos += len_bytes;
    if bit_string_len < 1 || pos + bit_string_len > spki.len() {
        return None;
    }
    let unused = spki[pos];
    if unused > 7 {
        return None;
    }
    pos += 1;
    let key_len = bit_string_len - 1;
    if pos + key_len > spki.len() {
        return None;
    }
    Some(&spki[pos..pos + key_len])
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
                    return Err(SPDM_STATUS_VERIF_FAIL);
                }
            };
            let pk = UnparsedPublicKey::new(sign_algorithm, pub_key);
            pk.verify(data, &signature.data[..signature.data_size as usize])
                .map_err(|_| SPDM_STATUS_VERIF_FAIL)
        }
        SpdmDer::SpdmDerCertChain(public_cert_der) => {
            let algorithm = match (base_hash_algo, base_asym_algo) {
                (
                    SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                    SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                ) => webpki::ring::ECDSA_P256_SHA256,
                (
                    SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                    SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                ) => webpki::ring::ECDSA_P384_SHA256,
                (
                    SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                    SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                ) => webpki::ring::ECDSA_P256_SHA384,
                (
                    SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                    SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                ) => webpki::ring::ECDSA_P384_SHA384,
                (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
                    webpki::ring::RSA_PKCS1_2048_8192_SHA256
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
                    webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
                    webpki::ring::RSA_PKCS1_2048_8192_SHA384
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
                    webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
                    webpki::ring::RSA_PKCS1_2048_8192_SHA512
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
                    webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY
                }
                _ => {
                    panic!();
                }
            };

            x509v3::check_cert_chain_format(public_cert_der, base_asym_algo)?;

            let (leaf_begin, leaf_end) = (super::cert_operation_impl::DEFAULT
                .get_cert_from_cert_chain_cb)(
                public_cert_der, -1
            )?;
            let leaf_cert_der = &public_cert_der[leaf_begin..leaf_end];

            let certificate_der = CertificateDer::from(leaf_cert_der);
            let res = webpki::EndEntityCert::try_from(&certificate_der);
            match res {
                Ok(cert) => {
                    //
                    // Need translate from ECDSA_P384_SHA384_FIXED_SIGNING to ECDSA_P384_SHA384_ASN1
                    // webpki only support ASN1 format ECDSA signature
                    //
                    match base_asym_algo {
                        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256
                        | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384 => {
                            // DER has this format: 0x30 size 0x02 r_size 0x00 [r_size] 0x02 s_size 0x00 [s_size]
                            let mut der_signature =
                                [0u8; crate::protocol::ECDSA_ECC_NIST_P384_SIG_SIZE + 8];
                            let der_sign_size =
                                ecc_signature_bin_to_der(signature.as_ref(), &mut der_signature)?;

                            match cert.verify_signature(
                                algorithm,
                                data,
                                &der_signature[..(der_sign_size)],
                            ) {
                                Ok(()) => Ok(()),
                                Err(_) => Err(SPDM_STATUS_VERIF_FAIL),
                            }
                        }
                        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048
                        | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072
                        | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096
                        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048
                        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
                        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096 => {
                            // RSASSA or RSAPSS
                            match cert.verify_signature(algorithm, data, signature.as_ref()) {
                                Ok(()) => Ok(()),
                                Err(_) => Err(SPDM_STATUS_VERIF_FAIL),
                            }
                        }
                        _ => Err(SPDM_STATUS_VERIF_FAIL),
                    }
                }
                Err(_e) => Err(SPDM_STATUS_INVALID_CERT),
            }
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
    fn test_extract_spki_pubkey_rfc7250_p384() {
        // SubjectPublicKeyInfo for ECDSA P-384:
        //   SEQUENCE {
        //     SEQUENCE { OID ecPublicKey(1.2.840.10045.2.1), OID secp384r1(1.3.132.0.34) }
        //     BIT STRING (97 bytes: 04 || X || Y)
        //   }
        let spki = [
            0x30, 0x76, // SEQUENCE (118 bytes)
            0x30, 0x10, // SEQUENCE (16 bytes) - AlgorithmIdentifier
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID ecPublicKey
            0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, // OID secp384r1
            0x03, 0x62, // BIT STRING (98 bytes)
            0x00, // unused bits = 0
            0x04, // uncompressed point
            // X coordinate (48 bytes)
            0x39, 0xAC, 0xA8, 0x8D, 0xE8, 0xBF, 0xA6, 0xAC, 0x22, 0x97, 0x49, 0x5D, 0x31, 0x40,
            0xF6, 0xEE, 0xA0, 0xC5, 0x70, 0x27, 0xF5, 0x1F, 0xB7, 0x60, 0xE5, 0x4A, 0xF9, 0x01,
            0xFB, 0xC4, 0xD1, 0x5F, 0x75, 0x00, 0x59, 0x77, 0x9D, 0xF9, 0x24, 0xC4, 0xAE, 0xFC,
            0xAC, 0xCE, 0x74, 0xBE, 0x5E, 0x90, // Y coordinate (48 bytes)
            0xD4, 0xB9, 0x21, 0xC5, 0x18, 0x0A, 0x25, 0x91, 0xD3, 0x4D, 0x44, 0x75, 0x65, 0x39,
            0xCF, 0x02, 0x11, 0xBB, 0x36, 0x3D, 0x46, 0xE6, 0x50, 0x5E, 0x39, 0x93, 0xD2, 0xBE,
            0x43, 0xFB, 0xEB, 0x26, 0x1F, 0x40, 0xE4, 0xBF, 0x52, 0xD3, 0xF7, 0x79, 0x09, 0xF7,
            0xD4, 0x5A, 0x70, 0x19, 0x81, 0x94,
        ];

        let extracted = extract_spki_pubkey(&spki).expect("should extract pubkey");
        // Expect uncompressed point: 0x04 + 48 bytes X + 48 bytes Y = 97 bytes
        assert_eq!(extracted.len(), 97);
        assert_eq!(extracted[0], 0x04);
        // Check a few known bytes from X and Y
        assert_eq!(extracted[1], 0x39);
        assert_eq!(extracted[2], 0xAC);
        assert_eq!(extracted[96], 0x94);
    }

    #[test]
    fn test_extract_spki_pubkey_rfc7250_p256() {
        // SubjectPublicKeyInfo for ECDSA P-256:
        //   SEQUENCE {
        //     SEQUENCE { OID ecPublicKey(1.2.840.10045.2.1), OID prime256v1(1.2.840.10045.3.1.7) }
        //     BIT STRING (65 bytes: 04 || X || Y)
        //   }
        let spki = [
            0x30, 0x59, // SEQUENCE (89 bytes)
            0x30, 0x13, // SEQUENCE (19 bytes) - AlgorithmIdentifier
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID ecPublicKey
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID prime256v1
            0x03, 0x42, // BIT STRING (66 bytes)
            0x00, // unused bits = 0
            0x04, // uncompressed point
            // X coordinate (32 bytes)
            0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4,
            0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45,
            0xD8, 0x98, 0xC2, 0x96, // Y coordinate (32 bytes)
            0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F,
            0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68,
            0x37, 0xBF, 0x51, 0xF5,
        ];

        let extracted = extract_spki_pubkey(&spki).expect("should extract P-256 pubkey");
        // Expect uncompressed point: 0x04 + 32 bytes X + 32 bytes Y = 65 bytes
        assert_eq!(extracted.len(), 65);
        assert_eq!(extracted[0], 0x04);
        // Check known bytes from X and Y
        assert_eq!(extracted[1], 0x6B);
        assert_eq!(extracted[2], 0x17);
        assert_eq!(extracted[64], 0xF5);
    }
}

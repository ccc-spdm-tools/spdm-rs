// Copyright (c) 2025, 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use alloc::vec::Vec;
use core::ffi::{c_int, c_uchar};
use log::error;
use spdmlib::crypto::SpdmPqcAsymVerify;
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_CERT, SPDM_STATUS_VERIF_FAIL};
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmPqcAsymAlgo, SpdmSignatureStruct};

use crate::asym_verify_impl::parse_der_length;

// Raw public key sizes for ML-DSA variants (without SPKI DER header)
const MLDSA_44_KEY_SIZE: usize = 1312;
const MLDSA_65_KEY_SIZE: usize = 1952;
const MLDSA_87_KEY_SIZE: usize = 2592;

// DER universal tags used when recognising a SubjectPublicKeyInfo.
const DER_TAG_SEQUENCE: u8 = 0x30;
const DER_TAG_BIT_STRING: u8 = 0x03;

// SPDM signing prefix is 64 bytes, followed by 36 bytes of (zeropad + context_string).
const SPDM_SIGNING_PREFIX_LEN: usize = 64;
const SPDM_SIGNING_CONTEXT_FIELD_LEN: usize = 36;

// These context-verification functions are not exposed by the safe aws-lc-rs
// API. Their prefixed names are tied to the aws-lc-sys revision pinned in
// external/patches/aws-lc-rs/README.md and must be updated with that pin.
extern "C" {
    #[link_name = "aws_lc_0_43_0_ml_dsa_44_verify"]
    fn ml_dsa_44_verify(
        public_key: *const c_uchar,
        sig: *const c_uchar,
        sig_len: usize,
        message: *const c_uchar,
        message_len: usize,
        ctx_string: *const c_uchar,
        ctx_string_len: usize,
    ) -> c_int;

    #[link_name = "aws_lc_0_43_0_ml_dsa_65_verify"]
    fn ml_dsa_65_verify(
        public_key: *const c_uchar,
        sig: *const c_uchar,
        sig_len: usize,
        message: *const c_uchar,
        message_len: usize,
        ctx_string: *const c_uchar,
        ctx_string_len: usize,
    ) -> c_int;

    #[link_name = "aws_lc_0_43_0_ml_dsa_87_verify"]
    fn ml_dsa_87_verify(
        public_key: *const c_uchar,
        sig: *const c_uchar,
        sig_len: usize,
        message: *const c_uchar,
        message_len: usize,
        ctx_string: *const c_uchar,
        ctx_string_len: usize,
    ) -> c_int;
}

pub static DEFAULT: SpdmPqcAsymVerify = SpdmPqcAsymVerify {
    verify_cb: pqc_asym_verify,
    #[cfg(feature = "fips")]
    fips_self_test_cb: Some(crate::fips_cavp_impl::ml_dsa_87_cavp),
    #[cfg(not(feature = "fips"))]
    fips_self_test_cb: None,
};

/// How the peer's ML-DSA public key was supplied to the verifier.
///
/// `spdmlib::crypto::spdm_asym_verify` hands both `SpdmDer` variants to the
/// PQC callback as an untyped byte slice, so the backend must recognise the
/// encoding itself. Classification is deterministic and never attempts an
/// X.509 parse on a bare key, which keeps the RFC 7250 path free of spurious
/// certificate errors.
#[derive(Debug, PartialEq, Eq)]
enum PublicKeyEncoding<'a> {
    /// Bare FIPS 204 public key bytes.
    Raw(&'a [u8]),
    /// RFC 7250 raw public key: a bare DER `SubjectPublicKeyInfo`. Carries
    /// the raw key extracted from the `BIT STRING`.
    Spki(&'a [u8]),
    /// SPDM certificate chain; the key is taken from the leaf certificate.
    CertChain(&'a [u8]),
}

/// Read one DER TLV header at the start of `input`. Returns the tag, the
/// offset of the content, and the content length, provided the element fits
/// within `input`.
fn der_header(input: &[u8]) -> Option<(u8, usize, usize)> {
    let tag = *input.first()?;
    let (len_of_len, content_len) = parse_der_length(input.get(1..)?)?;
    let content_start = 1 + len_of_len;
    content_start
        .checked_add(content_len)
        .filter(|end| *end <= input.len())?;
    Some((tag, content_start, content_len))
}

/// Recognise a bare DER `SubjectPublicKeyInfo` carrying a raw ML-DSA key of
/// `expected_raw_size` bytes and return that key.
///
/// ```text
/// SEQUENCE {
///     SEQUENCE { OID, ... }       -- AlgorithmIdentifier
///     BIT STRING { 0x00, key }    -- subjectPublicKey, no unused bits
/// }
/// ```
///
/// Every length must be consistent with the input; anything else is not an
/// SPKI and is left for the certificate-chain path.
fn spki_public_key(input: &[u8], expected_raw_size: usize) -> Option<&[u8]> {
    let (tag, body_start, body_len) = der_header(input)?;
    if tag != DER_TAG_SEQUENCE || body_start + body_len != input.len() {
        return None;
    }
    let body = &input[body_start..];

    let (tag, alg_start, alg_len) = der_header(body)?;
    if tag != DER_TAG_SEQUENCE {
        return None;
    }
    let rest = &body[alg_start + alg_len..];

    let (tag, key_start, key_len) = der_header(rest)?;
    if tag != DER_TAG_BIT_STRING || key_start + key_len != rest.len() {
        return None;
    }
    let bit_string = &rest[key_start..];
    // First BIT STRING byte is the unused-bit count; a key is whole bytes.
    if bit_string.first() != Some(&0) || bit_string.len() != 1 + expected_raw_size {
        return None;
    }
    Some(&bit_string[1..])
}

fn classify_public_key(input: &[u8], expected_raw_size: usize) -> PublicKeyEncoding<'_> {
    if input.len() == expected_raw_size {
        return PublicKeyEncoding::Raw(input);
    }
    if let Some(key) = spki_public_key(input, expected_raw_size) {
        return PublicKeyEncoding::Spki(key);
    }
    PublicKeyEncoding::CertChain(input)
}

/// Extract the raw ML-DSA public key from a DER-encoded certificate chain.
///
/// Parses the cert chain to find the leaf certificate, then extracts
/// the SubjectPublicKeyInfo's raw public key bytes. If the raw key bytes
/// contain an SPKI header (i.e. are longer than expected), strip the header.
fn extract_public_key_from_cert_chain(
    public_cert_der: &[u8],
    expected_raw_size: usize,
) -> Result<Vec<u8>, spdmlib::error::SpdmStatus> {
    // Use spdm_x509 to get the leaf certificate (index -1 = last cert)
    let (leaf_begin, leaf_end) =
        spdm_x509::x509::chain::get_cert_from_cert_chain(public_cert_der, -1).map_err(|e| {
            error!("Failed to get leaf cert from chain: {:?}", e);
            SPDM_STATUS_INVALID_CERT
        })?;

    let leaf_cert_der = &public_cert_der[leaf_begin..leaf_end];

    // Parse the certificate to extract SubjectPublicKeyInfo
    let cert = spdm_x509::Certificate::from_der(leaf_cert_der).map_err(|e| {
        error!("Failed to parse leaf certificate: {:?}", e);
        SPDM_STATUS_INVALID_CERT
    })?;

    let pub_key_bytes = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    // If the key bytes are exactly the expected raw size, use as-is.
    // Otherwise strip any SPKI/BIT STRING overhead.
    if pub_key_bytes.len() == expected_raw_size {
        Ok(pub_key_bytes.to_vec())
    } else if pub_key_bytes.len() > expected_raw_size {
        Ok(pub_key_bytes[pub_key_bytes.len() - expected_raw_size..].to_vec())
    } else {
        error!(
            "Public key too small: got {} bytes, expected {}",
            pub_key_bytes.len(),
            expected_raw_size
        );
        Err(SPDM_STATUS_INVALID_CERT)
    }
}

/// Extract the SPDM signing context string from the data buffer.
///
/// The SPDM 1.2+ signing message has the following structure:
///   [0..64)   : signing prefix ("dmtf-spdm-v1.x.*" repeated 4 times)
///   [64..100) : zero-padding + signing context string (36 bytes total)
///   [100..)   : hash
///
/// The signing context string is at the end of the 36-byte field (after
/// zero-padding). Per SPDM spec, this context string is also used as the
/// ML-DSA context parameter (ctx) in FIPS 204 sign/verify operations.
fn extract_signing_context(data: &[u8]) -> &[u8] {
    if data.len() < SPDM_SIGNING_PREFIX_LEN + SPDM_SIGNING_CONTEXT_FIELD_LEN {
        return &[];
    }
    let field =
        &data[SPDM_SIGNING_PREFIX_LEN..SPDM_SIGNING_PREFIX_LEN + SPDM_SIGNING_CONTEXT_FIELD_LEN];
    // The context string follows zero-padding. Find the first non-zero byte.
    for i in 0..field.len() {
        if field[i] != 0 {
            return &field[i..];
        }
    }
    &[]
}

fn pqc_asym_verify(
    _base_hash_algo: SpdmBaseHashAlgo,
    pqc_asym_algo: SpdmPqcAsymAlgo,
    public_key_der: &[u8],
    data: &[u8],
    signature: &SpdmSignatureStruct,
) -> SpdmResult {
    let sig_bytes = &signature.data[..signature.data_size as usize];
    let ctx_string = extract_signing_context(data);

    let expected_key_size = match pqc_asym_algo {
        SpdmPqcAsymAlgo::ALG_MLDSA_44 => MLDSA_44_KEY_SIZE,
        SpdmPqcAsymAlgo::ALG_MLDSA_65 => MLDSA_65_KEY_SIZE,
        SpdmPqcAsymAlgo::ALG_MLDSA_87 => MLDSA_87_KEY_SIZE,
        _ => return Err(SPDM_STATUS_VERIF_FAIL),
    };

    // The caller passes either an RFC 7250 raw public key or a certificate
    // chain without saying which; recognise the encoding before parsing so
    // that a bare key never reaches the X.509 parser.
    let raw_key_buf;
    let raw_key: &[u8] = match classify_public_key(public_key_der, expected_key_size) {
        PublicKeyEncoding::Raw(key) | PublicKeyEncoding::Spki(key) => key,
        PublicKeyEncoding::CertChain(chain) => {
            raw_key_buf = extract_public_key_from_cert_chain(chain, expected_key_size)?;
            &raw_key_buf
        }
    };

    let verify_fn: unsafe extern "C" fn(_, _, _, _, _, _, _) -> _ = match pqc_asym_algo {
        SpdmPqcAsymAlgo::ALG_MLDSA_44 => ml_dsa_44_verify,
        SpdmPqcAsymAlgo::ALG_MLDSA_65 => ml_dsa_65_verify,
        SpdmPqcAsymAlgo::ALG_MLDSA_87 => ml_dsa_87_verify,
        _ => return Err(SPDM_STATUS_VERIF_FAIL),
    };

    let ctx_ptr = if ctx_string.is_empty() {
        core::ptr::null()
    } else {
        ctx_string.as_ptr()
    };

    let result = unsafe {
        verify_fn(
            raw_key.as_ptr(),
            sig_bytes.as_ptr(),
            sig_bytes.len(),
            data.as_ptr(),
            data.len(),
            ctx_ptr,
            ctx_string.len(),
        )
    };

    if result == 1 {
        Ok(())
    } else {
        Err(SPDM_STATUS_VERIF_FAIL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair;
    use aws_lc_rs::unstable::signature::{
        PqdsaKeyPair, PqdsaSigningAlgorithm, ML_DSA_44_SIGNING, ML_DSA_65_SIGNING,
        ML_DSA_87_SIGNING,
    };
    use std::vec;

    // id-ml-dsa-44/65/87: 2.16.840.1.101.3.4.3.{17,18,19}
    const OID_ML_DSA_PREFIX: [u8; 8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];

    fn der_len(len: usize) -> Vec<u8> {
        match len {
            0..=0x7f => vec![len as u8],
            0x80..=0xff => vec![0x81, len as u8],
            _ => vec![0x82, (len >> 8) as u8, len as u8],
        }
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(der_len(content.len()));
        out.extend_from_slice(content);
        out
    }

    /// Build the RFC 7250 SubjectPublicKeyInfo that MigTD and other raw-key
    /// SPDM endpoints exchange in place of a certificate chain.
    fn spki(oid_last: u8, raw_key: &[u8]) -> Vec<u8> {
        let mut oid = OID_ML_DSA_PREFIX.to_vec();
        oid.push(oid_last);
        let mut bits = vec![0u8];
        bits.extend_from_slice(raw_key);
        let mut body = der(DER_TAG_SEQUENCE, &der(0x06, &oid));
        body.extend(der(DER_TAG_BIT_STRING, &bits));
        der(DER_TAG_SEQUENCE, &body)
    }

    fn sign(
        key_pair: &PqdsaKeyPair,
        algo: &'static PqdsaSigningAlgorithm,
        message: &[u8],
    ) -> SpdmSignatureStruct {
        let mut sig = vec![0u8; algo.signature_len()];
        let written = key_pair.sign(message, &mut sig).expect("sign");
        let mut out = SpdmSignatureStruct {
            data_size: written as u16,
            ..SpdmSignatureStruct::default()
        };
        out.data[..written].copy_from_slice(&sig[..written]);
        out
    }

    fn load_chain(dir: &str) -> Vec<u8> {
        std::fs::read(std::format!(
            "{}/../test_key/{}/bundle_responder.certchain.der",
            env!("CARGO_MANIFEST_DIR"),
            dir
        ))
        .expect("read test chain")
    }

    #[test]
    fn exact_size_input_is_a_raw_key() {
        let key = [0x5a; MLDSA_87_KEY_SIZE];
        assert_eq!(
            classify_public_key(&key, MLDSA_87_KEY_SIZE),
            PublicKeyEncoding::Raw(&key)
        );
    }

    #[test]
    fn bare_spki_is_recognised_without_touching_x509() {
        for (oid_last, size) in [
            (0x11, MLDSA_44_KEY_SIZE),
            (0x12, MLDSA_65_KEY_SIZE),
            (0x13, MLDSA_87_KEY_SIZE),
        ] {
            let key = vec![0xa5; size];
            let encoded = spki(oid_last, &key);
            assert_eq!(
                classify_public_key(&encoded, size),
                PublicKeyEncoding::Spki(&key)
            );
        }
    }

    #[test]
    fn malformed_spki_falls_through_to_the_cert_chain_path() {
        let key = vec![0xa5; MLDSA_87_KEY_SIZE];
        let good = spki(0x13, &key);

        // Key length does not match the negotiated algorithm.
        assert!(matches!(
            classify_public_key(&good, MLDSA_65_KEY_SIZE),
            PublicKeyEncoding::CertChain(_)
        ));

        // Trailing bytes beyond the outer SEQUENCE.
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(matches!(
            classify_public_key(&trailing, MLDSA_87_KEY_SIZE),
            PublicKeyEncoding::CertChain(_)
        ));

        // Truncated input.
        assert!(matches!(
            classify_public_key(&good[..good.len() - 1], MLDSA_87_KEY_SIZE),
            PublicKeyEncoding::CertChain(_)
        ));

        // Non-zero unused-bit count in the BIT STRING.
        let mut unused_bits = good.clone();
        let bit_string_start = good.len() - MLDSA_87_KEY_SIZE - 1;
        unused_bits[bit_string_start] = 1;
        assert!(matches!(
            classify_public_key(&unused_bits, MLDSA_87_KEY_SIZE),
            PublicKeyEncoding::CertChain(_)
        ));
    }

    #[test]
    fn certificate_chain_is_recognised_and_yields_the_leaf_key() {
        for (dir, size) in [
            ("mldsa44", MLDSA_44_KEY_SIZE),
            ("mldsa65", MLDSA_65_KEY_SIZE),
            ("mldsa87", MLDSA_87_KEY_SIZE),
        ] {
            let chain = load_chain(dir);
            assert!(matches!(
                classify_public_key(&chain, size),
                PublicKeyEncoding::CertChain(_)
            ));
            let key = extract_public_key_from_cert_chain(&chain, size).expect("leaf key");
            assert_eq!(key.len(), size, "{dir}");
        }
    }

    #[test]
    fn garbage_that_is_not_a_chain_is_rejected_as_invalid_cert() {
        // Longer than a raw key, not an SPKI, not a certificate: the old
        // code silently used the trailing bytes as the key.
        let garbage = vec![0x30; MLDSA_87_KEY_SIZE + 64];
        let signature = SpdmSignatureStruct::default();
        let result = pqc_asym_verify(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmPqcAsymAlgo::ALG_MLDSA_87,
            &garbage,
            b"message",
            &signature,
        );
        assert_eq!(result, Err(SPDM_STATUS_INVALID_CERT));
    }

    #[test]
    fn raw_and_spki_encodings_verify_the_same_signature() {
        for (algo, pqc_algo, oid_last) in [
            (&ML_DSA_44_SIGNING, SpdmPqcAsymAlgo::ALG_MLDSA_44, 0x11),
            (&ML_DSA_65_SIGNING, SpdmPqcAsymAlgo::ALG_MLDSA_65, 0x12),
            (&ML_DSA_87_SIGNING, SpdmPqcAsymAlgo::ALG_MLDSA_87, 0x13),
        ] {
            let key_pair = PqdsaKeyPair::generate(algo).expect("keygen");
            let raw = key_pair.public_key().as_ref().to_vec();
            let encoded = spki(oid_last, &raw);
            let message = b"SPDM PQC raw public key verification";
            let signature = sign(&key_pair, algo, message);

            for public_key in [&raw, &encoded] {
                let ok = pqc_asym_verify(
                    SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                    pqc_algo,
                    public_key,
                    message,
                    &signature,
                );
                assert_eq!(ok, Ok(()), "{pqc_algo:?}");

                let bad = pqc_asym_verify(
                    SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                    pqc_algo,
                    public_key,
                    b"tampered",
                    &signature,
                );
                assert_eq!(bad, Err(SPDM_STATUS_VERIF_FAIL), "{pqc_algo:?}");
            }
        }
    }
}

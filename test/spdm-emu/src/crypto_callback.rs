// Copyright (c) 2021-2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

// PathBuf is only used by the classical backend signing paths (which read a key
// file); a no-backend build (cargo test --features spdmlib/spdm-ring) uses none.
#[cfg(any(
    feature = "spdm-ring",
    feature = "spdm-mbedtls",
    feature = "spdm-aws-lc"
))]
use std::path::PathBuf;

use spdmlib::common::SpdmContext;
use spdmlib::secret::{SpdmSecretAsymSign, SpdmSecretPqcAsymSign};

use spdmlib::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmPqcAsymAlgo, SpdmSignatureStruct};
// Only the classical backend paths (ring / aws-lc) use the RSA signature sizes
// and the max signature buffer; gate them so a no-backend build (used by
// `cargo test --features spdmlib/spdm-ring`) is warning-free.
#[cfg(any(
    feature = "spdm-ring",
    feature = "spdm-mbedtls",
    feature = "spdm-aws-lc"
))]
use spdmlib::protocol::{
    RSAPSS_2048_SIG_SIZE, RSAPSS_3072_SIG_SIZE, RSAPSS_4096_SIG_SIZE, RSASSA_2048_SIG_SIZE,
    RSASSA_3072_SIG_SIZE, RSASSA_4096_SIG_SIZE, SPDM_MAX_ASYM_SIG_SIZE,
};

pub static SECRET_ASYM_IMPL_INSTANCE: SpdmSecretAsymSign =
    SpdmSecretAsymSign { sign_cb: asym_sign };

pub static SECRET_PQC_ASYM_IMPL_INSTANCE: SpdmSecretPqcAsymSign = SpdmSecretPqcAsymSign {
    sign_cb: pqc_asym_sign,
};

// Classical secret-signing for the emulator. Three implementations are provided:
// a ring-based one (spdm-ring build), an mbedtls-based one (spdm-mbedtls build
// with no ring), and an aws-lc-based one (standalone spdm-aws-lc build that links
// no ring, i.e. spdm-aws-lc without spdm-ring or spdm-mbedtls). The cfg gates are
// mutually exclusive — ring wins when spdm-ring is enabled — so exactly one
// `asym_sign` is compiled and SECRET_ASYM_IMPL_INSTANCE resolves correctly.
#[cfg(feature = "spdm-ring")]
fn asym_sign(
    _spdm_context: &SpdmContext,
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    match (base_hash_algo, base_asym_algo) {
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256) => {
            sign_ecdsa_asym_algo(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, data)
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384) => {
            sign_ecdsa_asym_algo(&ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING, data)
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
            sign_rsa_asym_algo(
                &ring::signature::RSA_PKCS1_SHA256,
                base_asym_algo.get_sig_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
            sign_rsa_asym_algo(
                &ring::signature::RSA_PSS_SHA256,
                base_asym_algo.get_sig_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
            sign_rsa_asym_algo(
                &ring::signature::RSA_PKCS1_SHA384,
                base_asym_algo.get_sig_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
            sign_rsa_asym_algo(
                &ring::signature::RSA_PSS_SHA384,
                base_asym_algo.get_sig_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
            sign_rsa_asym_algo(
                &ring::signature::RSA_PKCS1_SHA512,
                base_asym_algo.get_sig_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
            sign_rsa_asym_algo(
                &ring::signature::RSA_PSS_SHA512,
                base_asym_algo.get_sig_size() as usize,
                data,
            )
        }
        _ => {
            panic!();
        }
    }
}

#[cfg(feature = "spdm-ring")]
fn sign_ecdsa_asym_algo(
    algorithm: &'static ring::signature::EcdsaSigningAlgorithm,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    // openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -outform DER > private.der
    // or  openssl.exe ecparam -name prime256v1 -genkey -out private.der -outform der
    // openssl.exe pkcs8 -in private.der -inform DER -topk8 -nocrypt -outform DER > private.p8

    // Check for environment variable first
    let key_file_path = if let Ok(env_key_path) = std::env::var("SPDMRS_RSP_EMU_PRIVATE_KEY_PATH") {
        println!("Loading private key from env: {}", env_key_path);
        PathBuf::from(env_key_path)
    } else {
        let crate_dir = get_test_key_directory();
        println!("crate dir: {:?}", crate_dir.as_os_str().to_str());
        if algorithm == &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING {
            crate_dir.join("test_key/ecp256/end_responder.key.p8")
        } else if algorithm == &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING {
            crate_dir.join("test_key/ecp384/end_responder.key.p8")
        } else {
            panic!("not support")
        }
    };
    let der_file = std::fs::read(&key_file_path)
        .unwrap_or_else(|e| panic!("unable to read key from {:?}: {}", key_file_path, e));
    let key_bytes = der_file.as_slice();
    let rng = ring::rand::SystemRandom::new();
    let key_pair: ring::signature::EcdsaKeyPair =
        ring::signature::EcdsaKeyPair::from_pkcs8(algorithm, key_bytes, &rng).ok()?;

    let rng = ring::rand::SystemRandom::new();

    let signature = key_pair.sign(&rng, data).ok()?;
    let signature = signature.as_ref();

    let mut full_signature: [u8; SPDM_MAX_ASYM_SIG_SIZE] = [0u8; SPDM_MAX_ASYM_SIG_SIZE];
    full_signature[..signature.len()].copy_from_slice(signature);

    Some(SpdmSignatureStruct {
        data_size: signature.len() as u16,
        data: full_signature,
    })
}

#[cfg(feature = "spdm-ring")]
fn sign_rsa_asym_algo(
    padding_alg: &'static dyn ring::signature::RsaEncoding,
    key_len: usize,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    // openssl.exe genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -outform DER > private.der

    // Check for environment variable first
    let key_file_path = if let Ok(env_key_path) = std::env::var("SPDMRS_RSP_EMU_PRIVATE_KEY_PATH") {
        println!("Loading private key from env: {}", env_key_path);
        PathBuf::from(env_key_path)
    } else {
        let crate_dir = get_test_key_directory();

        #[allow(unreachable_patterns)]
        match key_len {
            RSASSA_2048_SIG_SIZE | RSAPSS_2048_SIG_SIZE => {
                crate_dir.join("test_key/rsa2048/end_responder.key.der")
            }
            RSASSA_3072_SIG_SIZE | RSAPSS_3072_SIG_SIZE => {
                crate_dir.join("test_key/rsa3072/end_responder.key.der")
            }
            RSASSA_4096_SIG_SIZE | RSAPSS_4096_SIG_SIZE => {
                crate_dir.join("test_key/rsa3072/end_responder.key.der")
            }
            _ => {
                panic!("RSA key len not supported")
            }
        }
    };
    let der_file = std::fs::read(&key_file_path)
        .unwrap_or_else(|e| panic!("unable to read key from {:?}: {}", key_file_path, e));
    let key_bytes = der_file.as_slice();

    let key_pair: ring::signature::RsaKeyPair =
        ring::signature::RsaKeyPair::from_der(key_bytes).ok()?;

    if key_len != key_pair.public().modulus_len() {
        panic!();
    }

    let rng = ring::rand::SystemRandom::new();

    let mut full_sign = [0u8; SPDM_MAX_ASYM_SIG_SIZE];
    key_pair
        .sign(padding_alg, &rng, data, &mut full_sign[0..key_len])
        .ok()?;

    Some(SpdmSignatureStruct {
        data_size: key_len as u16,
        data: full_sign,
    })
}

// mbedtls classical secret-signing, for a spdm-mbedtls build that links no ring.
// mbedtls signs a pre-computed digest (not the message) and, for ECDSA, emits a
// DER-encoded signature, so this pre-hashes the data and converts the ECDSA DER
// output back to the fixed r||s form SPDM expects. RSA-PSS padding is selected
// via Pk::set_options; PKCS#1 v1.5 is mbedtls's default for an RSA key.
#[cfg(all(feature = "spdm-mbedtls", not(feature = "spdm-ring")))]
fn asym_sign(
    _spdm_context: &SpdmContext,
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    match (base_hash_algo, base_asym_algo) {
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384) => {
            sign_ecdsa_asym_algo_mbedtls(base_hash_algo, base_asym_algo, data)
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
            sign_rsa_asym_algo_mbedtls(
                base_hash_algo,
                false,
                base_asym_algo.get_sig_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
            sign_rsa_asym_algo_mbedtls(
                base_hash_algo,
                true,
                base_asym_algo.get_sig_size() as usize,
                data,
            )
        }
        _ => panic!(),
    }
}

// Map an SPDM base hash algorithm to the mbedtls message-digest type used to
// pre-hash the data before signing.
#[cfg(all(feature = "spdm-mbedtls", not(feature = "spdm-ring")))]
fn mbedtls_md_type(base_hash_algo: SpdmBaseHashAlgo) -> mbedtls::hash::Type {
    match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => mbedtls::hash::Type::Sha256,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => mbedtls::hash::Type::Sha384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => mbedtls::hash::Type::Sha512,
        _ => panic!("unsupported hash algo for mbedtls signing"),
    }
}

#[cfg(all(feature = "spdm-mbedtls", not(feature = "spdm-ring")))]
fn mbedtls_digest(base_hash_algo: SpdmBaseHashAlgo, data: &[u8]) -> ([u8; 64], usize) {
    let md = mbedtls_md_type(base_hash_algo);
    let mut out = [0u8; 64];
    let len = mbedtls::hash::Md::hash(md, data, &mut out).expect("mbedtls digest failed");
    (out, len)
}

#[cfg(all(feature = "spdm-mbedtls", not(feature = "spdm-ring")))]
fn sign_ecdsa_asym_algo_mbedtls(
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    let key_file_path = if let Ok(env_key_path) = std::env::var("SPDMRS_RSP_EMU_PRIVATE_KEY_PATH") {
        PathBuf::from(env_key_path)
    } else {
        let crate_dir = get_test_key_directory();
        match base_asym_algo {
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256 => {
                crate_dir.join("test_key/ecp256/end_responder.key.p8")
            }
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384 => {
                crate_dir.join("test_key/ecp384/end_responder.key.p8")
            }
            _ => panic!("not support"),
        }
    };
    let der_file = std::fs::read(&key_file_path)
        .unwrap_or_else(|e| panic!("unable to read key from {:?}: {}", key_file_path, e));

    let mut pk = mbedtls::pk::Pk::from_private_key(der_file.as_slice(), None).ok()?;

    let md = mbedtls_md_type(base_hash_algo);
    let (digest, digest_len) = mbedtls_digest(base_hash_algo, data);

    // mbedtls emits a DER-encoded ECDSA signature; sign into a scratch buffer
    // (>= ECDSA_MAX_LEN) then convert to the fixed r||s form SPDM expects.
    let mut der_sig = [0u8; mbedtls::pk::ECDSA_MAX_LEN];
    let mut rng = mbedtls::rng::Rdrand;
    let der_len = pk
        .sign(md, &digest[..digest_len], &mut der_sig, &mut rng)
        .ok()?;

    let fixed_size = base_asym_algo.get_sig_size() as usize;
    let mut full_signature: [u8; SPDM_MAX_ASYM_SIG_SIZE] = [0u8; SPDM_MAX_ASYM_SIG_SIZE];
    ecc_signature_der_to_bin(&der_sig[..der_len], &mut full_signature[..fixed_size])?;

    Some(SpdmSignatureStruct {
        data_size: fixed_size as u16,
        data: full_signature,
    })
}

#[cfg(all(feature = "spdm-mbedtls", not(feature = "spdm-ring")))]
fn sign_rsa_asym_algo_mbedtls(
    base_hash_algo: SpdmBaseHashAlgo,
    is_pss: bool,
    key_len: usize,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    let key_file_path = if let Ok(env_key_path) = std::env::var("SPDMRS_RSP_EMU_PRIVATE_KEY_PATH") {
        PathBuf::from(env_key_path)
    } else {
        let crate_dir = get_test_key_directory();
        #[allow(unreachable_patterns)]
        match key_len {
            RSASSA_2048_SIG_SIZE | RSAPSS_2048_SIG_SIZE => {
                crate_dir.join("test_key/rsa2048/end_responder.key.der")
            }
            RSASSA_3072_SIG_SIZE | RSAPSS_3072_SIG_SIZE => {
                crate_dir.join("test_key/rsa3072/end_responder.key.der")
            }
            RSASSA_4096_SIG_SIZE | RSAPSS_4096_SIG_SIZE => {
                crate_dir.join("test_key/rsa3072/end_responder.key.der")
            }
            _ => panic!("RSA key len not supported"),
        }
    };
    let der_file = std::fs::read(&key_file_path)
        .unwrap_or_else(|e| panic!("unable to read key from {:?}: {}", key_file_path, e));

    let mut pk = mbedtls::pk::Pk::from_private_key(der_file.as_slice(), None).ok()?;

    let md = mbedtls_md_type(base_hash_algo);
    if is_pss {
        // RSA-PSS with MGF1 using the same hash as the message digest.
        pk.set_options(mbedtls::pk::Options::Rsa {
            padding: mbedtls::pk::RsaPadding::Pkcs1V21 { mgf: md },
        });
    }

    let (digest, digest_len) = mbedtls_digest(base_hash_algo, data);

    let mut full_sign = [0u8; SPDM_MAX_ASYM_SIG_SIZE];
    let sig_len = pk
        .sign(
            md,
            &digest[..digest_len],
            &mut full_sign[..key_len],
            &mut mbedtls::rng::Rdrand,
        )
        .ok()?;
    if sig_len != key_len {
        panic!(
            "unexpected RSA signature length {} (want {})",
            sig_len, key_len
        );
    }

    Some(SpdmSignatureStruct {
        data_size: key_len as u16,
        data: full_sign,
    })
}

// Convert a DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }) into
// the fixed-width r||s form SPDM uses. `fixed` must be sized to the algorithm's
// signature length (2 * coordinate size); r and s are left-zero-padded into
// their halves. This is the inverse of the bin->DER conversion in the mbedtls
// asym_verify backend.
#[cfg(all(feature = "spdm-mbedtls", not(feature = "spdm-ring")))]
fn ecc_signature_der_to_bin(der: &[u8], fixed: &mut [u8]) -> Option<()> {
    let half = fixed.len() / 2;
    // SEQUENCE
    if der.len() < 2 || der[0] != 0x30 {
        return None;
    }
    // Sequence length (assume short form; ECDSA P-256/P-384 sigs fit under 128).
    let seq_len = der[1] as usize;
    let mut idx = 2usize;
    if idx + seq_len != der.len() {
        return None;
    }

    // Parse an INTEGER, returning its content bytes with any leading 0x00
    // sign-padding removed.
    fn read_int<'a>(buf: &'a [u8], idx: &mut usize) -> Option<&'a [u8]> {
        if *idx + 2 > buf.len() || buf[*idx] != 0x02 {
            return None;
        }
        let len = buf[*idx + 1] as usize;
        *idx += 2;
        if *idx + len > buf.len() {
            return None;
        }
        let mut val = &buf[*idx..*idx + len];
        *idx += len;
        while val.len() > 1 && val[0] == 0x00 {
            val = &val[1..];
        }
        Some(val)
    }

    let r = read_int(der, &mut idx)?;
    let s = read_int(der, &mut idx)?;
    if r.len() > half || s.len() > half {
        return None;
    }

    for b in fixed.iter_mut() {
        *b = 0;
    }
    fixed[half - r.len()..half].copy_from_slice(r);
    fixed[2 * half - s.len()..2 * half].copy_from_slice(s);
    Some(())
}

// aws-lc-rs classical secret-signing, for a standalone aws-lc build with no ring.
// Mirrors the ring implementation above; aws-lc-rs exposes a ring-compatible
// signing API (EcdsaKeyPair::from_pkcs8, RsaKeyPair::from_der, .sign()).
#[cfg(all(
    feature = "spdm-aws-lc",
    not(feature = "spdm-ring"),
    not(feature = "spdm-mbedtls")
))]
fn asym_sign(
    _spdm_context: &SpdmContext,
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    use aws_lc_rs::signature;
    match (base_hash_algo, base_asym_algo) {
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256) => {
            sign_ecdsa_asym_algo_aws_lc(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, data)
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384) => {
            sign_ecdsa_asym_algo_aws_lc(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, data)
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
            sign_rsa_asym_algo_aws_lc(
                &signature::RSA_PKCS1_SHA256,
                base_asym_algo.get_sig_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
            sign_rsa_asym_algo_aws_lc(
                &signature::RSA_PSS_SHA256,
                base_asym_algo.get_sig_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
            sign_rsa_asym_algo_aws_lc(
                &signature::RSA_PKCS1_SHA384,
                base_asym_algo.get_sig_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
            sign_rsa_asym_algo_aws_lc(
                &signature::RSA_PSS_SHA384,
                base_asym_algo.get_sig_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
            sign_rsa_asym_algo_aws_lc(
                &signature::RSA_PKCS1_SHA512,
                base_asym_algo.get_sig_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
            sign_rsa_asym_algo_aws_lc(
                &signature::RSA_PSS_SHA512,
                base_asym_algo.get_sig_size() as usize,
                data,
            )
        }
        _ => panic!(),
    }
}

#[cfg(all(
    feature = "spdm-aws-lc",
    not(feature = "spdm-ring"),
    not(feature = "spdm-mbedtls")
))]
fn sign_ecdsa_asym_algo_aws_lc(
    algorithm: &'static aws_lc_rs::signature::EcdsaSigningAlgorithm,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    use aws_lc_rs::signature;
    let key_file_path = if let Ok(env_key_path) = std::env::var("SPDMRS_RSP_EMU_PRIVATE_KEY_PATH") {
        PathBuf::from(env_key_path)
    } else {
        let crate_dir = get_test_key_directory();
        if algorithm == &signature::ECDSA_P256_SHA256_FIXED_SIGNING {
            crate_dir.join("test_key/ecp256/end_responder.key.p8")
        } else if algorithm == &signature::ECDSA_P384_SHA384_FIXED_SIGNING {
            crate_dir.join("test_key/ecp384/end_responder.key.p8")
        } else {
            panic!("not support")
        }
    };
    let der_file = std::fs::read(&key_file_path)
        .unwrap_or_else(|e| panic!("unable to read key from {:?}: {}", key_file_path, e));
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(algorithm, der_file.as_slice()).ok()?;
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let signature = key_pair.sign(&rng, data).ok()?;
    let signature = signature.as_ref();

    let mut full_signature: [u8; SPDM_MAX_ASYM_SIG_SIZE] = [0u8; SPDM_MAX_ASYM_SIG_SIZE];
    full_signature[..signature.len()].copy_from_slice(signature);
    Some(SpdmSignatureStruct {
        data_size: signature.len() as u16,
        data: full_signature,
    })
}

#[cfg(all(
    feature = "spdm-aws-lc",
    not(feature = "spdm-ring"),
    not(feature = "spdm-mbedtls")
))]
fn sign_rsa_asym_algo_aws_lc(
    padding_alg: &'static dyn aws_lc_rs::signature::RsaEncoding,
    key_len: usize,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    use aws_lc_rs::signature;
    let key_file_path = if let Ok(env_key_path) = std::env::var("SPDMRS_RSP_EMU_PRIVATE_KEY_PATH") {
        PathBuf::from(env_key_path)
    } else {
        let crate_dir = get_test_key_directory();
        #[allow(unreachable_patterns)]
        match key_len {
            RSASSA_2048_SIG_SIZE | RSAPSS_2048_SIG_SIZE => {
                crate_dir.join("test_key/rsa2048/end_responder.key.der")
            }
            RSASSA_3072_SIG_SIZE | RSAPSS_3072_SIG_SIZE => {
                crate_dir.join("test_key/rsa3072/end_responder.key.der")
            }
            RSASSA_4096_SIG_SIZE | RSAPSS_4096_SIG_SIZE => {
                crate_dir.join("test_key/rsa3072/end_responder.key.der")
            }
            _ => panic!("RSA key len not supported"),
        }
    };
    let der_file = std::fs::read(&key_file_path)
        .unwrap_or_else(|e| panic!("unable to read key from {:?}: {}", key_file_path, e));
    let key_pair = signature::RsaKeyPair::from_der(der_file.as_slice()).ok()?;
    if key_len != key_pair.public_modulus_len() {
        panic!();
    }
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let mut full_sign = [0u8; SPDM_MAX_ASYM_SIG_SIZE];
    key_pair
        .sign(padding_alg, &rng, data, &mut full_sign[0..key_len])
        .ok()?;
    Some(SpdmSignatureStruct {
        data_size: key_len as u16,
        data: full_sign,
    })
}

// Fallback used only when the emulator library is compiled with no crypto
// backend feature at all (e.g. `cargo test --features spdmlib/spdm-ring`, which
// enables spdmlib's backend but not spdm-emu's own spdm-ring/spdm-mbedtls/
// spdm-aws-lc). SECRET_ASYM_IMPL_INSTANCE is unconditional, so `asym_sign` must
// always resolve; the emu binaries always select a real backend feature.
#[cfg(not(any(
    feature = "spdm-ring",
    feature = "spdm-mbedtls",
    feature = "spdm-aws-lc"
)))]
fn asym_sign(
    _spdm_context: &SpdmContext,
    _base_hash_algo: SpdmBaseHashAlgo,
    _base_asym_algo: SpdmBaseAsymAlgo,
    _data: &[u8],
) -> Option<SpdmSignatureStruct> {
    unimplemented!("classical signing requires spdm-ring, spdm-mbedtls, or spdm-aws-lc")
}

fn pqc_asym_sign(
    _spdm_context: &SpdmContext,
    _base_hash_algo: SpdmBaseHashAlgo,
    pqc_asym_algo: SpdmPqcAsymAlgo,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    #[cfg(feature = "spdm-aws-lc")]
    {
        use aws_lc_rs::encoding::AsRawBytes;
        use aws_lc_rs::unstable::signature::{
            PqdsaKeyPair, ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING,
        };

        let signing_algo = match pqc_asym_algo {
            SpdmPqcAsymAlgo::ALG_MLDSA_44 => &ML_DSA_44_SIGNING,
            SpdmPqcAsymAlgo::ALG_MLDSA_65 => &ML_DSA_65_SIGNING,
            SpdmPqcAsymAlgo::ALG_MLDSA_87 => &ML_DSA_87_SIGNING,
            _ => {
                panic!("unsupported PQC asym algo: {:?}", pqc_asym_algo);
            }
        };

        let key_dir_name = match pqc_asym_algo {
            SpdmPqcAsymAlgo::ALG_MLDSA_44 => "mldsa44",
            SpdmPqcAsymAlgo::ALG_MLDSA_65 => "mldsa65",
            SpdmPqcAsymAlgo::ALG_MLDSA_87 => "mldsa87",
            _ => unreachable!(),
        };

        let key_file_path = get_test_key_directory()
            .join("test_key")
            .join(key_dir_name)
            .join("end_responder.key.der");

        let der_file = std::fs::read(&key_file_path)
            .unwrap_or_else(|e| panic!("unable to read PQC key from {:?}: {}", key_file_path, e));

        let key_pair = PqdsaKeyPair::from_pkcs8(signing_algo, &der_file)
            .unwrap_or_else(|e| panic!("unable to parse PQC key pair: {:?}", e));

        // Extract raw private key for signing with ML-DSA context string
        let raw_priv_key = key_pair
            .private_key()
            .as_raw_bytes()
            .expect("failed to get raw private key");

        spdmlib_crypto_aws_lc::pqc_asym_sign_impl::pqc_sign_with_context(
            pqc_asym_algo,
            raw_priv_key.as_ref(),
            data,
        )
    }
    #[cfg(not(feature = "spdm-aws-lc"))]
    {
        let _ = (pqc_asym_algo, data);
        unimplemented!("PQC signing requires spdm-aws-lc feature")
    }
}

#[cfg(any(
    feature = "spdm-ring",
    feature = "spdm-mbedtls",
    feature = "spdm-aws-lc"
))]
fn get_test_key_directory() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = crate_dir
        .parent()
        .expect("can't find parent dir")
        .parent()
        .expect("can't find parent_dir");
    crate_dir.to_path_buf()
}

/// Register PQC crypto callbacks (KEM and ML-DSA verification) using aws-lc-rs.
/// Must be called before any PQC operations.
///
/// This is the PQC **overlay** registration: it adds ML-KEM, ML-DSA message
/// verification, and the ML-DSA certificate-chain hook on top of a classical
/// backend (ring or mbedtls) that has already been registered for the
/// traditional primitives.
#[cfg(feature = "spdm-aws-lc")]
pub fn register_pqc_crypto_callbacks() {
    spdmlib::crypto::pqc_asym_verify::register(
        spdmlib_crypto_aws_lc::pqc_asym_verify_impl::DEFAULT.clone(),
    );
    spdmlib::crypto::kem_decap::register(spdmlib_crypto_aws_lc::kem_impl::DEFAULT_DECAP.clone());
    spdmlib::crypto::kem_encap::register(spdmlib_crypto_aws_lc::kem_impl::DEFAULT_ENCAP.clone());
    // Enable ML-DSA (FIPS 204) certificate-chain verification in spdm_x509 so
    // PQC certificate chain mode (DSP0274 1.4) can be used, not just raw
    // public key mode.
    spdmlib_crypto_aws_lc::pqc_cert_verify_impl::register();
}

/// Register aws-lc-rs as the **standalone** crypto backend for BOTH traditional
/// and post-quantum algorithms — no ring, no mbedtls.
///
/// This installs the full aws-lc primitive set (hash, HMAC, AEAD, ECDHE,
/// RSA/ECDSA verify, HKDF, rand, certificate-chain verification) plus ML-KEM
/// and ML-DSA. Because the aws-lc certificate backend (`AwsLcBackend`) verifies
/// ML-DSA itself, the runtime PQC verifier hook is intentionally NOT registered
/// here — ML-DSA certificate signatures go through the normal cert_operation
/// path. aws-lc-rs is std-only, so this cannot be used for no_std targets.
#[cfg(feature = "spdm-aws-lc")]
pub fn register_aws_lc_crypto_callbacks() {
    // Traditional primitives.
    spdmlib::crypto::hash::register(spdmlib_crypto_aws_lc::hash_impl::DEFAULT.clone());
    spdmlib::crypto::hmac::register(spdmlib_crypto_aws_lc::hmac_impl::DEFAULT.clone());
    spdmlib::crypto::aead::register(spdmlib_crypto_aws_lc::aead_impl::DEFAULT.clone());
    spdmlib::crypto::asym_verify::register(
        spdmlib_crypto_aws_lc::asym_verify_impl::DEFAULT.clone(),
    );
    spdmlib::crypto::dhe::register(spdmlib_crypto_aws_lc::dhe_impl::DEFAULT.clone());
    spdmlib::crypto::hkdf::register(spdmlib_crypto_aws_lc::hkdf_impl::DEFAULT.clone());
    spdmlib::crypto::rand::register(spdmlib_crypto_aws_lc::rand_impl::DEFAULT.clone());
    spdmlib::crypto::cert_operation::register(
        spdmlib_crypto_aws_lc::cert_operation_impl::DEFAULT.clone(),
    );
    // Post-quantum primitives (message signatures + KEM). No PQC cert-chain
    // verifier hook is registered: AwsLcBackend (cert_operation, above) verifies
    // ML-DSA certificate signatures directly, and is_root_certificate() no longer
    // performs a separate backend-hardcoded self-signature check. The standalone
    // aws-lc path is therefore fully hook-free for ML-DSA certificate chains.
    spdmlib::crypto::pqc_asym_verify::register(
        spdmlib_crypto_aws_lc::pqc_asym_verify_impl::DEFAULT.clone(),
    );
    spdmlib::crypto::kem_decap::register(spdmlib_crypto_aws_lc::kem_impl::DEFAULT_DECAP.clone());
    spdmlib::crypto::kem_encap::register(spdmlib_crypto_aws_lc::kem_impl::DEFAULT_ENCAP.clone());
}

// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use std::path::PathBuf;

use spdmlib::secret::SpdmSecretAsymSign;

use spdmlib::protocol::{
    SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmSignatureStruct, RSAPSS_2048_KEY_SIZE,
    RSAPSS_3072_KEY_SIZE, RSAPSS_4096_KEY_SIZE, RSASSA_2048_KEY_SIZE, RSASSA_3072_KEY_SIZE,
    RSASSA_4096_KEY_SIZE, SPDM_MAX_ASYM_KEY_SIZE,
};

pub static SECRET_ASYM_IMPL_INSTANCE: SpdmSecretAsymSign =
    SpdmSecretAsymSign { sign_cb: asym_sign };

fn asym_sign(
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
                base_asym_algo.get_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
            sign_rsa_asym_algo(
                &ring::signature::RSA_PSS_SHA256,
                base_asym_algo.get_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
            sign_rsa_asym_algo(
                &ring::signature::RSA_PKCS1_SHA384,
                base_asym_algo.get_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
            sign_rsa_asym_algo(
                &ring::signature::RSA_PSS_SHA384,
                base_asym_algo.get_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
            sign_rsa_asym_algo(
                &ring::signature::RSA_PKCS1_SHA512,
                base_asym_algo.get_size() as usize,
                data,
            )
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
            sign_rsa_asym_algo(
                &ring::signature::RSA_PSS_SHA512,
                base_asym_algo.get_size() as usize,
                data,
            )
        }
        _ => {
            panic!();
        }
    }
}

fn sign_ecdsa_asym_algo(
    algorithm: &'static ring::signature::EcdsaSigningAlgorithm,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    // openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -outform DER > private.der
    // or  openssl.exe ecparam -name prime256v1 -genkey -out private.der -outform der
    // openssl.exe pkcs8 -in private.der -inform DER -topk8 -nocrypt -outform DER > private.p8

    let crate_dir = get_test_key_directory();
    println!("crate dir: {:?}", crate_dir.as_os_str().to_str());
    let key_file_path = if algorithm == &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING {
        crate_dir.join("test_key/ecp256/end_responder.key.p8")
    } else if algorithm == &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING {
        crate_dir.join("test_key/ecp384/end_responder.key.p8")
    } else {
        panic!("not support")
    };
    let der_file = std::fs::read(key_file_path).expect("unable to read key der!");
    let key_bytes = der_file.as_slice();
    let rng = ring::rand::SystemRandom::new();
    let key_pair: ring::signature::EcdsaKeyPair =
        ring::signature::EcdsaKeyPair::from_pkcs8(algorithm, key_bytes, &rng).ok()?;

    let rng = ring::rand::SystemRandom::new();

    let signature = key_pair.sign(&rng, data).ok()?;
    let signature = signature.as_ref();

    let mut full_signature: [u8; SPDM_MAX_ASYM_KEY_SIZE] = [0u8; SPDM_MAX_ASYM_KEY_SIZE];
    full_signature[..signature.len()].copy_from_slice(signature);

    Some(SpdmSignatureStruct {
        data_size: signature.len() as u16,
        data: full_signature,
    })
}

fn sign_rsa_asym_algo(
    padding_alg: &'static dyn ring::signature::RsaEncoding,
    key_len: usize,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    // openssl.exe genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -outform DER > private.der
    let crate_dir = get_test_key_directory();

    #[allow(unreachable_patterns)]
    let key_file_path = match key_len {
        RSASSA_2048_KEY_SIZE | RSAPSS_2048_KEY_SIZE => {
            crate_dir.join("test_key/rsa2048/end_responder.key.der")
        }
        RSASSA_3072_KEY_SIZE | RSAPSS_3072_KEY_SIZE => {
            crate_dir.join("test_key/rsa3072/end_responder.key.der")
        }
        RSASSA_4096_KEY_SIZE | RSAPSS_4096_KEY_SIZE => {
            crate_dir.join("test_key/rsa3072/end_responder.key.der")
        }
        _ => {
            panic!("RSA key len not supported")
        }
    };
    let der_file = std::fs::read(key_file_path).expect("unable to read key der!");
    let key_bytes = der_file.as_slice();

    let key_pair: ring::signature::RsaKeyPair =
        ring::signature::RsaKeyPair::from_der(key_bytes).ok()?;

    if key_len != key_pair.public().modulus_len() {
        panic!();
    }

    let rng = ring::rand::SystemRandom::new();

    let mut full_sign = [0u8; SPDM_MAX_ASYM_KEY_SIZE];
    key_pair
        .sign(padding_alg, &rng, data, &mut full_sign[0..key_len])
        .ok()?;

    Some(SpdmSignatureStruct {
        data_size: key_len as u16,
        data: full_sign,
    })
}

fn get_test_key_directory() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = crate_dir
        .parent()
        .expect("can't find parent dir")
        .parent()
        .expect("can't find parent_dir");
    crate_dir.to_path_buf()
}

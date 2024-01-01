// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use spdmlib::crypto::SpdmCertOperation;
use spdmlib::crypto::SpdmCryptoRandom;
use spdmlib::crypto::{SpdmAead, SpdmAsymVerify, SpdmHkdf, SpdmHmac};
use spdmlib::error::{SpdmResult, SPDM_STATUS_VERIF_FAIL};
use spdmlib::protocol::*;

pub static FAKE_HMAC: SpdmHmac = SpdmHmac {
    hmac_cb: fake_hmac,
    hmac_verify_cb: fake_hmac_verify,
};

pub static FAKE_AEAD: SpdmAead = SpdmAead {
    encrypt_cb: fake_encrypt,
    decrypt_cb: fake_decrypt,
};

pub static FAKE_RAND: SpdmCryptoRandom = SpdmCryptoRandom {
    get_random_cb: get_random,
};

pub static FAKE_ASYM_VERIFY: SpdmAsymVerify = SpdmAsymVerify {
    verify_cb: fake_asym_verify,
};

pub static FAKE_HKDF: SpdmHkdf = SpdmHkdf {
    hkdf_extract_cb: fake_hkdf_extract,
    hkdf_expand_cb: fake_hkdf_expand,
};

pub static FAKE_CERT_OPERATION: SpdmCertOperation = SpdmCertOperation {
    get_cert_from_cert_chain_cb: fake_get_cert_from_cert_chain,
    verify_cert_chain_cb: fake_verify_cert_chain,
};

fn fake_hmac(
    _base_hash_algo: SpdmBaseHashAlgo,
    _key: &[u8],
    _data: &[u8],
) -> Option<SpdmDigestStruct> {
    let tag = SpdmDigestStruct {
        data_size: 48,
        data: Box::new([10u8; SPDM_MAX_HASH_SIZE]),
    };
    Some(tag)
}

fn fake_hmac_verify(
    _base_hash_algo: SpdmBaseHashAlgo,
    _key: &[u8],
    _data: &[u8],
    hmac: &SpdmDigestStruct,
) -> SpdmResult {
    let SpdmDigestStruct { data_size, .. } = hmac;
    match data_size {
        48 => Ok(()),
        _ => Err(SPDM_STATUS_VERIF_FAIL),
    }
}

fn fake_encrypt(
    _aead_algo: SpdmAeadAlgo,
    _key: &SpdmAeadKeyStruct,
    _iv: &SpdmAeadIvStruct,
    _aad: &[u8],
    plain_text: &[u8],
    tag: &mut [u8],
    cipher_text: &mut [u8],
) -> SpdmResult<(usize, usize)> {
    let plain_text_size = plain_text.len();
    let cipher_text_size = cipher_text.len();
    if cipher_text_size != plain_text_size {
        panic!("cipher_text len invalid");
    }
    cipher_text.copy_from_slice(plain_text);
    Ok((plain_text_size, tag.len()))
}

fn fake_decrypt(
    _aead_algo: SpdmAeadAlgo,
    _key: &SpdmAeadKeyStruct,
    _iv: &SpdmAeadIvStruct,
    _aad: &[u8],
    cipher_text: &[u8],
    _tag: &[u8],
    plain_text: &mut [u8],
) -> SpdmResult<usize> {
    let plain_text_size = plain_text.len();
    let cipher_text_size = cipher_text.len();
    if cipher_text_size != plain_text_size {
        panic!("plain_text len invalid");
    }
    plain_text.copy_from_slice(cipher_text);
    Ok(cipher_text_size)
}

fn get_random(data: &mut [u8]) -> SpdmResult<usize> {
    #[allow(clippy::needless_range_loop)]
    for i in 0..data.len() {
        data[i] = 0xff;
    }

    Ok(data.len())
}

fn fake_asym_verify(
    _base_hash_algo: SpdmBaseHashAlgo,
    _base_asym_algo: SpdmBaseAsymAlgo,
    _public_cert_der: &[u8],
    _data: &[u8],
    _signature: &SpdmSignatureStruct,
) -> SpdmResult {
    Ok(())
}

fn fake_hkdf_extract(
    hash_algo: SpdmBaseHashAlgo,
    _salt: &[u8],
    _ikm: &SpdmHkdfInputKeyingMaterial,
) -> Option<SpdmHkdfPseudoRandomKey> {
    match hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Some(SpdmHkdfPseudoRandomKey {
            data_size: SHA256_DIGEST_SIZE as u16,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        }),
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Some(SpdmHkdfPseudoRandomKey {
            data_size: SHA384_DIGEST_SIZE as u16,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        }),
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => Some(SpdmHkdfPseudoRandomKey {
            data_size: SHA512_DIGEST_SIZE as u16,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        }),
        _ => None,
    }
}

fn fake_hkdf_expand(
    hash_algo: SpdmBaseHashAlgo,
    _pk: &SpdmHkdfPseudoRandomKey,
    _info: &[u8],
    out_size: u16,
) -> Option<SpdmHkdfOutputKeyingMaterial> {
    if out_size as usize > SPDM_MAX_HKDF_OKM_SIZE {
        return None;
    }
    match hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Some(SpdmHkdfOutputKeyingMaterial {
            data_size: out_size,
            data: Box::new([100u8; SPDM_MAX_HKDF_OKM_SIZE]),
        }),
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Some(SpdmHkdfOutputKeyingMaterial {
            data_size: out_size,
            data: Box::new([100u8; SPDM_MAX_HKDF_OKM_SIZE]),
        }),
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => Some(SpdmHkdfOutputKeyingMaterial {
            data_size: out_size,
            data: Box::new([100u8; SPDM_MAX_HKDF_OKM_SIZE]),
        }),
        _ => None,
    }
}

fn fake_get_cert_from_cert_chain(cert_chain: &[u8], _index: isize) -> SpdmResult<(usize, usize)> {
    return Ok((0, cert_chain.len()));
}

fn fake_verify_cert_chain(_cert_chain: &[u8]) -> SpdmResult {
    Ok(())
}

#[test]
// Make sure this is the first test case running by `cargo test`
fn test_0_crypto_init() {
    use super::secret_callback::{
        FAKE_SECRET_ASYM_IMPL_INSTANCE, SECRET_MEASUREMENT_IMPL_INSTANCE,
    };
    spdmlib::crypto::aead::register(FAKE_AEAD.clone());
    spdmlib::crypto::asym_verify::register(FAKE_ASYM_VERIFY.clone());
    spdmlib::crypto::aead::register(FAKE_AEAD.clone());
    spdmlib::crypto::rand::register(FAKE_RAND.clone());
    spdmlib::secret::asym_sign::register(FAKE_SECRET_ASYM_IMPL_INSTANCE.clone());
    spdmlib::secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
}

// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use mbedtls::hash;
use spdmlib::crypto::SpdmHkdf;
use spdmlib::protocol::{
    SpdmBaseHashAlgo, SpdmHkdfInputKeyingMaterial, SpdmHkdfOutputKeyingMaterial,
    SpdmHkdfPseudoRandomKey,
};

pub static DEFAULT: SpdmHkdf = SpdmHkdf {
    hkdf_extract_cb: hkdf_extract,
    hkdf_expand_cb: hkdf_expand,
};

fn hkdf_extract(
    hash_algo: SpdmBaseHashAlgo,
    salt: &[u8],
    ikm: &SpdmHkdfInputKeyingMaterial,
) -> Option<SpdmHkdfPseudoRandomKey> {
    use mbedtls_sys::hkdf_extract;
    let md = match hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Some(hash::Type::Sha256),
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Some(hash::Type::Sha384),
        _ => None,
    }?;
    let md: hash::MdInfo = match md.into() {
        Some(md) => md,
        None => return None,
    };

    let mut prk = SpdmHkdfPseudoRandomKey::default();
    unsafe {
        let ret = hkdf_extract(
            md.into(),
            salt.as_ptr(),
            salt.len(),
            ikm.as_ref().as_ptr(),
            ikm.as_ref().len(),
            prk.data.as_mut_ptr(),
        );
        if ret != 0 {
            return None;
        }
        prk.data_size = md.size() as u16;
    }
    Some(prk)
}

fn hkdf_expand(
    hash_algo: SpdmBaseHashAlgo,
    prk: &SpdmHkdfPseudoRandomKey,
    info: &[u8],
    out_size: u16,
) -> Option<SpdmHkdfOutputKeyingMaterial> {
    use mbedtls_sys::hkdf_expand;
    let md = match hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Some(hash::Type::Sha256),
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Some(hash::Type::Sha384),
        _ => None,
    }?;
    let md: hash::MdInfo = match md.into() {
        Some(md) => md,
        None => return None,
    };
    let mut okm = SpdmHkdfOutputKeyingMaterial::default();
    unsafe {
        let res = hkdf_expand(
            md.into(),
            prk.as_ref().as_ptr(),
            prk.as_ref().len(),
            info.as_ptr(),
            info.len(),
            okm.data.as_mut_ptr(),
            out_size as usize,
        );
        if res != 0 {
            return None;
        }
    }
    okm.data_size = out_size;
    Some(okm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use spdmlib::protocol::{SpdmBaseHashAlgo, SPDM_MAX_HASH_SIZE};
    #[test]
    fn test_case0_hkdf_expand() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let prk = SpdmHkdfPseudoRandomKey {
            data_size: 32,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        };
        let info = &mut [100u8; 64];
        let out_size = 64;
        let hkdf_expand = hkdf_expand(base_hash_algo, &prk, info, out_size);

        match hkdf_expand {
            Some(_) => {
                assert!(true)
            }
            None => {
                assert!(false)
            }
        }
    }
    #[test]
    fn test_case1_hkdf_expand() {
        // remove should panic
        // hkdf_expand is a library call. It's better to return failure/success instead of panic.
        let base_hash_algo = SpdmBaseHashAlgo::empty();
        let prk = SpdmHkdfPseudoRandomKey {
            data_size: 64,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        };
        let info = &mut [100u8; 64];
        let out_size = 64;
        let hkdf_expand = hkdf_expand(base_hash_algo, &prk, info, out_size);

        match hkdf_expand {
            Some(_) => {
                // when bash_hash_algo is empty
                // hkdf_expand will failed and return None.
                assert!(false)
            }
            None => {
                assert!(true)
            }
        }
    }
}

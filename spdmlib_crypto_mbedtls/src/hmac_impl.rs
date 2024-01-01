// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use mbedtls::hash;
use spdmlib::crypto::SpdmHmac;
use spdmlib::error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR};
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

pub static DEFAULT: SpdmHmac = SpdmHmac {
    hmac_cb: hmac,
    hmac_verify_cb: hmac_verify,
};

fn hmac(base_hash_algo: SpdmBaseHashAlgo, key: &[u8], data: &[u8]) -> Option<SpdmDigestStruct> {
    let hash_algo = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Some(hash::Type::Sha256),
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Some(hash::Type::Sha384),
        _ => None,
    }?;
    let mut ctx = hash::Hmac::new(hash_algo, key).ok()?;
    ctx.update(data).ok()?;
    let mut digest = SpdmDigestStruct::default();
    let len = ctx.finish(digest.data.as_mut()).ok()?;
    digest.data_size = len as u16;
    Some(digest)
}

fn hmac_verify(
    base_hash_algo: SpdmBaseHashAlgo,
    key: &[u8],
    data: &[u8],
    message_digest: &SpdmDigestStruct,
) -> SpdmResult {
    let digest = hmac(base_hash_algo, key, data).ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
    if digest.as_ref() == message_digest.as_ref() {
        Ok(())
    } else {
        Err(SPDM_STATUS_CRYPTO_ERROR)
    }
}

#[cfg(test)]
mod tests {
    use spdmlib::protocol::{SpdmFinishedKeyStruct, SPDM_MAX_HASH_SIZE};

    use super::*;
    #[test]
    fn test_case_rfc4231_2() {
        let key = &mut SpdmFinishedKeyStruct {
            data_size: 4,
            data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
        };
        key.data[0..4].copy_from_slice(&[0x4a, 0x65, 0x66, 0x65]);
        let data: &[u8] = &[
            0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e,
            0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f,
        ][..];
        let hmac_256: &[u8] = &[
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ][..];

        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let spdm_digest = hmac(base_hash_algo, key.as_ref(), data).unwrap();
        assert_eq!(spdm_digest.as_ref(), hmac_256);

        let digest = SpdmDigestStruct::from(hmac_256);
        hmac_verify(base_hash_algo, key.as_ref(), data, &digest).unwrap();
    }
}

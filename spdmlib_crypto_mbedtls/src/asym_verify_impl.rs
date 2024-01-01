// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use mbedtls::{hash, x509::Certificate};
use spdmlib::crypto::SpdmAsymVerify;
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_PARAMETER, SPDM_STATUS_VERIF_FAIL};
use spdmlib::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmSignatureStruct};

pub static DEFAULT: SpdmAsymVerify = SpdmAsymVerify {
    verify_cb: asym_verify,
};

fn asym_verify(
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    public_cert_der: &[u8],
    data: &[u8],
    signature: &SpdmSignatureStruct,
) -> SpdmResult {
    if signature.data_size != base_asym_algo.get_size() {
        return Err(SPDM_STATUS_INVALID_PARAMETER);
    }

    let hash_algo = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Ok(hash::Type::Sha256),
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Ok(hash::Type::Sha384),
        _ => Err(SPDM_STATUS_INVALID_PARAMETER),
    }?;

    match base_asym_algo {
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256
        | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096 => {}
        _ => return Err(SPDM_STATUS_INVALID_PARAMETER),
    };

    // DER has this format: 0x30 size 0x02 r_size 0x00 [r_size] 0x02 s_size 0x00 [s_size]
    let mut der_signature = [0u8; spdmlib::protocol::ECDSA_ECC_NIST_P384_KEY_SIZE + 8];

    let signature = match base_asym_algo {
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256
        | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384 => {
            let der_sign_size = ecc_signature_bin_to_der(signature.as_ref(), &mut der_signature)?;
            &der_signature[0..der_sign_size]
        }
        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048
        | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072
        | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096 => signature.as_ref(),
        _ => {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }
    };

    let (leaf_begin, leaf_end) =
        (super::cert_operation_impl::DEFAULT.get_cert_from_cert_chain_cb)(public_cert_der, -1)?;
    let leaf_cert_der = &public_cert_der[leaf_begin..leaf_end];

    let data_hash = (super::hash_impl::DEFAULT.hash_all_cb)(base_hash_algo, data).unwrap();

    let mut certificate =
        Certificate::from_der(leaf_cert_der).map_err(|_| SPDM_STATUS_INVALID_PARAMETER)?;
    certificate
        .public_key_mut()
        .verify(hash_algo, data_hash.as_ref(), signature)
        .map_err(|_| SPDM_STATUS_VERIF_FAIL)
}

// add ASN.1 for the ECDSA binary signature
fn ecc_signature_bin_to_der(signature: &[u8], der_signature: &mut [u8]) -> SpdmResult<usize> {
    let sign_size = signature.len();
    assert!(
        // prevent API misuse
        sign_size == spdmlib::protocol::ECDSA_ECC_NIST_P256_KEY_SIZE
            || sign_size == spdmlib::protocol::ECDSA_ECC_NIST_P384_KEY_SIZE
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
        return Err(SPDM_STATUS_VERIF_FAIL);
    }

    if der_r_size > u8::MAX as usize
        || der_s_size > u8::MAX as usize
        || der_sign_size > u8::MAX as usize
    {
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

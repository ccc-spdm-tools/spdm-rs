// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;

use crate::crypto::SpdmCertOperation;
use crate::error::{SpdmResult, SPDM_STATUS_INVALID_CERT, SPDM_STATUS_INVALID_STATE_LOCAL};
use ring::io::der;

pub static DEFAULT: SpdmCertOperation = SpdmCertOperation {
    get_cert_from_cert_chain_cb: get_cert_from_cert_chain,
    verify_cert_chain_cb: verify_cert_chain,
};

fn get_cert_from_cert_chain(cert_chain: &[u8], index: isize) -> SpdmResult<(usize, usize)> {
    let mut offset = 0usize;
    let mut this_index = 0isize;
    let cert_chain_size = cert_chain.len();
    loop {
        if cert_chain[offset..].len() < 4 || offset > cert_chain.len() {
            return Err(SPDM_STATUS_INVALID_CERT);
        }
        if cert_chain[offset] != 0x30 || cert_chain[offset + 1] != 0x82 {
            return Err(SPDM_STATUS_INVALID_CERT);
        }
        let this_cert_len =
            ((cert_chain[offset + 2] as usize) << 8) + (cert_chain[offset + 3] as usize) + 4;
        if this_cert_len > cert_chain_size - offset {
            return Err(SPDM_STATUS_INVALID_CERT);
        }
        if this_index == index {
            // return the this one
            return Ok((offset, offset + this_cert_len));
        }
        this_index += 1;
        if (offset + this_cert_len == cert_chain_size) && (index == -1) {
            // return the last one
            return Ok((offset, offset + this_cert_len));
        }
        offset += this_cert_len;
    }
}

fn verify_cert_chain(cert_chain: &[u8]) -> SpdmResult {
    static EKU_SPDM_RESPONDER_AUTH: &[u8] = &[40 + 3, 6, 1, 5, 5, 7, 3, 1];

    static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
        &webpki::RSA_PKCS1_2048_8192_SHA256,
        &webpki::RSA_PKCS1_2048_8192_SHA384,
        &webpki::RSA_PKCS1_2048_8192_SHA512,
        &webpki::ECDSA_P256_SHA256,
        &webpki::ECDSA_P256_SHA384,
        &webpki::ECDSA_P384_SHA256,
        &webpki::ECDSA_P384_SHA384,
    ];

    let mut certs = Vec::new();
    let mut certs_walker = 0;
    let cert_chain_len = cert_chain.len();
    loop {
        let start = if certs_walker < cert_chain_len {
            certs_walker
        } else {
            break;
        };

        let tag = cert_chain[certs_walker];
        if usize::from(der::Tag::Sequence) != tag as usize {
            break;
        }

        certs_walker += 1;
        if certs_walker >= cert_chain_len {
            break;
        }

        // If the high order bit of the first byte is set to zero then the length
        // is encoded in the seven remaining bits of that byte. Otherwise, those
        // seven bits represent the number of bytes used to encode the length.
        let length_byte0 = cert_chain[certs_walker];

        let length = match length_byte0 {
            n if (n & 0x80) == 0 => n as usize,
            0x81 => {
                certs_walker += 1;
                if certs_walker >= cert_chain_len {
                    break;
                }

                let second_byte = cert_chain[certs_walker];
                if second_byte < 128 {
                    break; // Not the canonical encoding.
                }

                certs_walker += 1;
                if certs_walker >= cert_chain_len {
                    break;
                }

                second_byte as usize
            }
            0x82 => {
                certs_walker += 1;
                if certs_walker >= cert_chain_len {
                    break;
                }

                let second_byte = cert_chain[certs_walker] as usize;

                certs_walker += 1;
                if certs_walker >= cert_chain_len {
                    break;
                }

                let third_byte = cert_chain[certs_walker] as usize;

                certs_walker += 1;
                if certs_walker >= cert_chain_len {
                    break;
                }

                let combined = (second_byte << 8) | third_byte;
                if combined < 256 {
                    break; // Not the canonical encoding.
                }
                combined
            }
            _ => {
                break; // We don't support longer lengths.
            }
        };

        certs_walker += length;
        if certs_walker > cert_chain_len {
            break;
        }

        certs.push(&cert_chain[start..certs_walker]);
    }
    let certs_len = certs.len();

    let (ca, inters, ee): (&[u8], &[&[u8]], &[u8]) = match certs_len {
        0 => return Err(SPDM_STATUS_INVALID_CERT),
        1 => (certs[0], &[], certs[0]),
        2 => (certs[0], &[], certs[1]),
        n => (certs[0], &certs[1..(n - 1)], certs[n - 1]),
    };

    let anchors = if let Ok(ta) = webpki::TrustAnchor::try_from_cert_der(ca) {
        vec![ta]
    } else {
        return Err(SPDM_STATUS_INVALID_CERT);
    };

    #[cfg(any(target_os = "uefi", target_os = "none"))]
    let timestamp = {
        if let Some(ts) = sys_time::get_sys_time() {
            ts as u64
        } else {
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }
    };
    #[cfg(not(any(target_os = "uefi", target_os = "none")))]
    let timestamp = {
        extern crate std;
        if let Ok(ds) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            ds.as_secs()
        } else {
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }
    };
    let time = webpki::Time::from_seconds_since_unix_epoch(timestamp);

    let cert = if let Ok(eec) = webpki::EndEntityCert::try_from(ee) {
        eec
    } else {
        return Err(SPDM_STATUS_INVALID_CERT);
    };

    // we cannot call verify_is_valid_tls_server_cert because it will check verify_cert::EKU_SERVER_AUTH.
    if cert
        .verify_cert_chain_with_eku(EKU_SPDM_RESPONDER_AUTH, ALL_SIGALGS, &anchors, inters, time)
        .is_ok()
    {
        info!("Cert verification Pass\n");
        Ok(())
    } else {
        error!("Cert verification Fail\n");
        Err(SPDM_STATUS_INVALID_CERT)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case0_cert_from_cert_chain() {
        let cert_chain = &include_bytes!("public_cert.der")[..];
        let status = get_cert_from_cert_chain(cert_chain, -1).is_ok();
        assert!(status);
    }

    #[test]
    fn test_case1_cert_from_cert_chain() {
        let cert_chain = &include_bytes!("public_cert.der")[..];
        let status = get_cert_from_cert_chain(cert_chain, 0).is_ok();
        assert!(status);
    }
    #[test]
    fn test_case2_cert_from_cert_chain() {
        let cert_chain = &include_bytes!("public_cert.der")[..];
        let status = get_cert_from_cert_chain(cert_chain, 1).is_ok();
        assert!(status);
    }
    #[test]
    fn test_case3_cert_from_cert_chain() {
        let cert_chain = &mut [0x1u8; 4096];
        cert_chain[0] = 0x00;
        cert_chain[1] = 0x00;
        let status = get_cert_from_cert_chain(cert_chain, 0).is_err();
        assert!(status);
    }
    #[test]
    fn test_case4_cert_from_cert_chain() {
        let cert_chain = &mut [0x11u8; 3];
        let status = get_cert_from_cert_chain(cert_chain, 0).is_err();
        assert!(status);
    }
    #[test]
    fn test_case5_cert_from_cert_chain() {
        let cert_chain = &include_bytes!("public_cert.der")[..];
        let status = get_cert_from_cert_chain(cert_chain, -1).is_ok();
        assert!(status);

        let status = verify_cert_chain(cert_chain).is_ok();
        assert!(status);
    }

    /// verfiy cert chain
    #[test]
    fn test_verify_cert_chain_case1() {
        let bundle_certs_der =
            &include_bytes!("../../../../test_key/crypto_chains/ca_selfsigned.crt.der")[..];
        assert!(verify_cert_chain(bundle_certs_der).is_ok());

        let bundle_certs_der =
            &include_bytes!("../../../../test_key/crypto_chains/bundle_two_level_cert.der")[..];
        assert!(verify_cert_chain(bundle_certs_der).is_ok());

        let bundle_certs_der =
            &include_bytes!("../../../../test_key/ecp384/bundle_requester.certchain.der")[..];
        assert!(verify_cert_chain(bundle_certs_der).is_ok());

        let bundle_certs_der =
            &include_bytes!("../../../../test_key/crypto_chains/bundle_cert.der")[..];
        assert!(verify_cert_chain(bundle_certs_der).is_ok());

        // Flipping bits to test signature hash is invalid.
        let mut cert_chain = bundle_certs_der.to_vec();
        // offset 3140 is in signature range.
        cert_chain[3140] ^= 0xFE;
        assert!(verify_cert_chain(&cert_chain).is_err());

        // Invalid Intermediate cert
        let mut cert_chain = bundle_certs_der.to_vec();
        // Change intermediate cert data
        cert_chain[1380] = 0xFF;
        assert!(verify_cert_chain(&cert_chain).is_err());
    }
}

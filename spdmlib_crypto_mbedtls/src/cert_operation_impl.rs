// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use mbedtls::x509::Certificate;
use spdmlib::crypto::SpdmCertOperation;
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_CERT};

use der::{Reader, SliceReader};

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
    let mut reader = SliceReader::new(cert_chain).map_err(|_| SPDM_STATUS_INVALID_CERT)?;
    let mut chain = mbedtls::alloc::List::new();
    let mut ca = mbedtls::alloc::List::new();

    loop {
        let res = reader.tlv_bytes();
        if res.is_err() {
            break;
        }
        let cert = Certificate::from_der(res.unwrap()).map_err(|_| SPDM_STATUS_INVALID_CERT)?;
        if ca.is_empty() {
            ca.push(cert);
        } else {
            chain.push(cert);
        }
    }
    if chain.is_empty() && ca.is_empty() {
        return Err(SPDM_STATUS_INVALID_CERT);
    }
    if chain.is_empty() {
        chain.append(ca.clone())
    }
    Certificate::verify(&chain, &ca, None, None).map_err(|_| SPDM_STATUS_INVALID_CERT)
}

#[test]
fn test_certificate() {
    let cert_chain =
        include_bytes!("../../test_key/rsa3072_Expiration/bundle_requester.certchain.der");

    let mut reader = SliceReader::new(cert_chain).unwrap();
    let mut chain = mbedtls::alloc::List::new();
    let mut ca = mbedtls::alloc::List::new();
    loop {
        let res = reader.tlv_bytes();
        if res.is_err() {
            break;
        }
        let res = res.unwrap();
        let cert = Certificate::from_der(res).unwrap();
        if ca.is_empty() {
            ca.push(cert);
        } else {
            chain.push(cert);
        }
    }
    if chain.is_empty() && ca.is_empty() {
        panic!("SPDM_STATUS_INVALID_CERT")
    }
    if chain.is_empty() {
        chain.append(ca.clone())
    }

    Certificate::verify(&chain, &ca, None, None).unwrap();
}

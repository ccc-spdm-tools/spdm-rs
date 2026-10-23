// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![no_main]

use libfuzzer_sys::fuzz_target;
use spdm_x509::certificate::name::GeneralName;
use spdm_x509::crypto_backend::{CryptoBackend, SignatureAlgorithm};
use spdm_x509::x509::validator::Validator;

struct FuzzBackend;

impl CryptoBackend for FuzzBackend {
    fn verify_signature(
        &self,
        _algorithm: SignatureAlgorithm,
        _tbs_data: &[u8],
        _signature: &[u8],
        _public_key: &[u8],
    ) -> spdm_x509::Result<()> {
        Ok(())
    }
}

fn split_strings(data: &[u8]) -> Option<(String, String)> {
    let separator = data.iter().position(|byte| *byte == 0)?;
    let name = core::str::from_utf8(&data[..separator]).ok()?;
    let constraint = core::str::from_utf8(&data[separator + 1..]).ok()?;
    Some((String::from(name), String::from(constraint)))
}

fuzz_target!(|data: &[u8]| {
    let Some((&name_form, payload)) = data.split_first() else {
        return;
    };

    let pair = match name_form % 4 {
        0 => split_strings(payload).map(|(name, constraint)| {
            (GeneralName::DnsName(name), GeneralName::DnsName(constraint))
        }),
        1 => split_strings(payload).map(|(name, constraint)| {
            (
                GeneralName::Rfc822Name(name),
                GeneralName::Rfc822Name(constraint),
            )
        }),
        2 => split_strings(payload)
            .map(|(name, constraint)| (GeneralName::Uri(name), GeneralName::Uri(constraint))),
        _ if matches!(payload.len(), 12 | 48) => {
            let name_length = payload.len() / 3;
            Some((
                GeneralName::IpAddress(payload[..name_length].to_vec()),
                GeneralName::IpAddress(payload[name_length..].to_vec()),
            ))
        }
        _ => None,
    };

    if let Some((name, constraint)) = pair {
        let _ = Validator::<FuzzBackend>::fuzz_name_within_constraint(&name, &constraint);
    }
});

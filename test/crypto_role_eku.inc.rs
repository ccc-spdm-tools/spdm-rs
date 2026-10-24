// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[test]
fn test_callback_endpoint_algorithm_matrix() {
    let mixed_chain = [
        &include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test_key/rsa2048/ca.cert.der"
        ))[..],
        &include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test_key/rsa2048/inter.cert.der"
        ))[..],
        &include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test_key/ecp256/end_responder_rsa_issuer.cert.der"
        ))[..],
    ]
    .concat();
    let cases: [(&[u8], u32); 6] = [
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../test_key/ecp256/bundle_responder.certchain.der"
            )),
            1 << 4,
        ),
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../test_key/ecp384/bundle_responder.certchain.der"
            )),
            1 << 7,
        ),
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../test_key/rsa2048/bundle_responder.certchain.der"
            )),
            1,
        ),
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../test_key/rsa3072/bundle_responder.certchain.der"
            )),
            1 << 2,
        ),
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../test_key/rsa4096/bundle_responder.certchain.der"
            )),
            1 << 5,
        ),
        (&mixed_chain, 1 << 4),
    ];
    let verify = DEFAULT.verify_cert_chain_with_role_cb.unwrap();
    for (chain, selected) in cases {
        for role in [
            SpdmCertificateRole::Requester,
            SpdmCertificateRole::Responder,
        ] {
            for hash in [None, Some(1), Some(2), Some(4)] {
                assert!(verify(chain, Some(selected), hash, role).is_ok());
                assert!((DEFAULT.verify_cert_chain_cb)(chain, Some(selected), hash).is_ok());
            }
            let mismatch = if selected == 1 << 4 { 1 << 7 } else { 1 << 4 };
            assert_eq!(
                verify(chain, Some(mismatch), None, role),
                Err(SPDM_STATUS_INVALID_CERT),
            );
            let mut corrupt = chain.to_vec();
            *corrupt.last_mut().unwrap() ^= 1;
            assert_eq!(
                verify(&corrupt, Some(selected), Some(1), role),
                Err(SPDM_STATUS_INVALID_CERT),
            );
        }
    }
}

#[test]
fn test_role_aware_callback_signed_eku_matrix() {
    let root = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test_key/ecp256/ca.cert.der"
    ));
    let intermediate = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test_key/ecp256/inter.cert.der"
    ));
    let cases: [(&[u8], bool, bool); 4] = [
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../test_key/ecp256/end_requester_with_spdm_req_eku.cert.der"
            )),
            true,
            false,
        ),
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../test_key/ecp256/end_responder_with_spdm_rsp_eku.cert.der"
            )),
            false,
            true,
        ),
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../test_key/ecp256/end_requester_with_spdm_req_rsp_eku.cert.der"
            )),
            true,
            true,
        ),
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../test_key/ecp256/end_responder.cert.der"
            )),
            true,
            true,
        ),
    ];
    let verify = DEFAULT
        .verify_cert_chain_with_role_cb
        .expect("role-aware backend callback");
    for (leaf, requester, responder) in cases {
        let chain = [&root[..], &intermediate[..], leaf].concat();
        assert_eq!(
            (DEFAULT.verify_cert_chain_cb)(&chain, None, None).is_ok(),
            responder
        );
        for (role, accepted) in [
            (SpdmCertificateRole::Requester, requester),
            (SpdmCertificateRole::Responder, responder),
        ] {
            assert_eq!(
                verify(&chain, None, None, role).is_ok(),
                accepted,
                "{:?}",
                role
            );
            if accepted {
                let mut corrupt = chain.clone();
                *corrupt.last_mut().unwrap() ^= 1;
                assert!(verify(&corrupt, None, None, role).is_err());
            }
        }
    }
}

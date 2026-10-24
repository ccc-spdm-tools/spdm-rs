// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

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

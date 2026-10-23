// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use spdmlib::crypto::{cert_operation, SpdmCertOperation, SpdmCertificateRole};
use spdmlib::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use spdmlib::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo};

#[test]
fn role_aware_validation_never_falls_back_to_legacy_callback() {
    assert!(cert_operation::register(SpdmCertOperation {
        get_cert_from_cert_chain_cb: |chain, _| Ok((0, chain.len())),
        verify_cert_chain_cb: |_, _, _| Ok(()),
        verify_cert_chain_with_role_cb: None,
    }));
    let asym = SpdmBaseAsymAlgo::empty();
    let hash = SpdmBaseHashAlgo::empty();
    assert_eq!(cert_operation::verify_cert_chain(&[], asym, hash), Ok(()));
    for role in [
        SpdmCertificateRole::Requester,
        SpdmCertificateRole::Responder,
    ] {
        assert_eq!(
            cert_operation::verify_cert_chain_with_role(&[], asym, hash, role),
            Err(SPDM_STATUS_INVALID_STATE_LOCAL),
        );
    }
}

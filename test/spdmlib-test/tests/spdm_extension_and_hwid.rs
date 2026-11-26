// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(all(feature = "mut-auth", feature = "hashed-transcript-data"))]

use spdmlib::crypto;
use spdmlib::error::SPDM_STATUS_INVALID_CERT;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::responder::ResponderContext;
use spdmlib_test::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use spdmlib_test::common::transport::PciDoeTransportEncap;
use spdmlib_test::common::util::create_info;
use spin::Mutex;
use std::sync::{Arc, Once};

const P256_ROOT: &[u8] = include_bytes!("../../../test_key/ecp256/ca.cert.der");
const P256_INTER: &[u8] = include_bytes!("../../../test_key/ecp256/inter.cert.der");
const P256_DEVICE_LEAF: &[u8] = include_bytes!("../../../test_key/ecp256/end_responder.cert.der");
const P256_DEVICE_CA: &[u8] =
    include_bytes!("../../../test_key/ecp256/end_responder_alias_cert_partial_set.cert.der");
const P256_ALIAS_LEAF: &[u8] =
    include_bytes!("../../../test_key/ecp256/end_responder_alias.cert.der");
const P256_NO_SPDM_EXT_LEAF: &[u8] =
    include_bytes!("../../../test_key/ecp256/end_responder_with_spdm_rsp_eku.cert.der");

fn contexts() -> (RequesterContext, ResponderContext) {
    static CRYPTO_INIT: Once = Once::new();
    CRYPTO_INIT.call_once(|| {
        assert!(crypto::hash::hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_256, P256_ROOT).is_some());
        assert!(crypto::cert_operation::verify_cert_chain(
            P256_ROOT,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
            SpdmPqcAsymAlgo::empty(),
            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
        )
        .is_ok());
    });
    let (req_config, mut req_provision) = create_info();
    let (rsp_config, mut rsp_provision) = create_info();
    req_provision.peer_root_cert_data.fill(None);
    rsp_provision.peer_root_cert_data.fill(None);
    let io = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        SharedBuffer::new(),
    ))));
    let transport = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let mut requester =
        RequesterContext::new(io.clone(), transport.clone(), req_config, req_provision);
    let mut responder = ResponderContext::new(io, transport, rsp_config, rsp_provision);
    for common in [&mut requester.common, &mut responder.common] {
        common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;
        common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
        common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
    }
    (requester, responder)
}

fn chain_buffer(certs: &[&[u8]]) -> SpdmCertChainBuffer {
    let root_hash = crypto::hash::hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_256, certs[0]).unwrap();
    let hash_len = root_hash.data_size as usize;
    let body: Vec<u8> = certs.iter().copied().flatten().copied().collect();
    let total_len = 4 + hash_len + body.len();
    let mut buf = SpdmCertChainBuffer {
        data_size: total_len as u32,
        ..Default::default()
    };
    buf.data[..4].copy_from_slice(&(total_len as u32).to_le_bytes());
    buf.data[4..4 + hash_len].copy_from_slice(root_hash.as_ref());
    buf.data[4 + hash_len..total_len].copy_from_slice(&body);
    buf
}

#[test]
fn alias_model_accepts_device_ca_with_hwid_and_rejects_alias_leaf_with_hwid() {
    let (mut requester, mut responder) = contexts();
    requester.common.negotiate_info.rsp_capabilities_sel |=
        SpdmResponseCapabilityFlags::ALIAS_CERT_CAP;
    responder.common.negotiate_info.multi_key_conn_req = true;
    responder.common.peer_info.peer_cert_info[0] =
        Some(SpdmCertificateModelType::SpdmCertModelTypeAliasCert);

    // Valid alias chain: DeviceCert CA has HW_ID, AliasCert leaf omits it.
    let valid_alias = chain_buffer(&[P256_ROOT, P256_INTER, P256_DEVICE_CA, P256_ALIAS_LEAF]);
    requester.common.peer_info.peer_cert_chain_temp = Some(valid_alias.clone());
    responder.common.peer_info.peer_cert_chain_temp = Some(valid_alias);
    assert_eq!(requester.verify_spdm_certificate_chain(), Ok(()));
    assert_eq!(responder.verify_spdm_certificate_chain(), Ok(()));

    // DeviceCert leaf (carries HW_ID) presented under AliasCert model must be rejected.
    let invalid_alias = chain_buffer(&[P256_ROOT, P256_INTER, P256_DEVICE_LEAF]);
    requester.common.peer_info.peer_cert_chain_temp = Some(invalid_alias.clone());
    responder.common.peer_info.peer_cert_chain_temp = Some(invalid_alias);
    assert_eq!(
        requester.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );
    assert_eq!(
        responder.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );
}

#[test]
fn device_cert_accepts_present_or_absent_spdm_extension() {
    let (mut requester, _) = contexts();
    let with_spdm_ext = chain_buffer(&[P256_ROOT, P256_INTER, P256_DEVICE_LEAF]);
    requester.common.peer_info.peer_cert_chain_temp = Some(with_spdm_ext);
    assert_eq!(requester.verify_spdm_certificate_chain(), Ok(()));

    let without_spdm_ext = chain_buffer(&[P256_ROOT, P256_INTER, P256_NO_SPDM_EXT_LEAF]);
    requester.common.peer_info.peer_cert_chain_temp = Some(without_spdm_ext);
    assert_eq!(requester.verify_spdm_certificate_chain(), Ok(()));
}

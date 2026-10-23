// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(all(feature = "mut-auth", feature = "hashed-transcript-data"))]

use codec::Writer;
use spdmlib::common::SpdmCodec;
use spdmlib::crypto;
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_CERT};
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::responder::ResponderContext;
use spdmlib_test::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use spdmlib_test::common::transport::PciDoeTransportEncap;
use spdmlib_test::common::util::create_info;
use spin::Mutex;
use std::sync::{Arc, Once};

const ROOT: &[u8] = include_bytes!("../../../test_key/ecp256/ca.cert.der");
const INTERMEDIATE: &[u8] = include_bytes!("../../../test_key/ecp256/inter.cert.der");
const LEAF: &[u8] = include_bytes!("../../../test_key/ecp256/end_responder.cert.der");
const ALIAS_LEAF: &[u8] = include_bytes!("../../../test_key/ecp256/end_responder_alias.cert.der");
const DEVICE_CA: &[u8] =
    include_bytes!("../../../test_key/ecp256/end_responder_alias_cert_partial_set.cert.der");
const MISSING_BC_LEAF: &[u8] =
    include_bytes!("../../../test_key/ecp256/end_requester_without_basic_constraint.cert.der");

fn contexts() -> (RequesterContext, ResponderContext) {
    // Avoid contention during lazy initialization of the global crypto callbacks.
    static CRYPTO_INIT: Once = Once::new();
    CRYPTO_INIT.call_once(|| {
        assert!(crypto::hash::hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_256, ROOT).is_some());
        assert!(crypto::cert_operation::verify_cert_chain(
            ROOT,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
        )
        .is_ok());
    });
    let (req_config, mut req_provision) = create_info();
    let (rsp_config, mut rsp_provision) = create_info();
    // These cases test certificate fields in the existing unprovisioned mode.
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
        common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
        common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion14;
    }
    (requester, responder)
}

fn chain_buffer(leaf: &[u8]) -> SpdmCertChainBuffer {
    let chain = if leaf == ALIAS_LEAF {
        [ROOT, INTERMEDIATE, DEVICE_CA, leaf].concat()
    } else {
        [ROOT, INTERMEDIATE, leaf].concat()
    };
    assert!(
        [
            crypto::SpdmCertificateRole::Requester,
            crypto::SpdmCertificateRole::Responder
        ]
        .iter()
        .any(|role| crypto::cert_operation::verify_cert_chain_with_role(
            &chain,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            *role,
        )
        .is_ok()),
        "integration vectors must have valid signatures and linkage"
    );
    let root_hash = crypto::hash::hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_256, ROOT).unwrap();
    let mut buffer = SpdmCertChainBuffer {
        data_size: (4 + root_hash.data_size as usize + chain.len()) as u32,
        ..Default::default()
    };
    buffer.data[..4].copy_from_slice(&buffer.data_size.to_le_bytes());
    buffer.data[4..36].copy_from_slice(root_hash.as_ref());
    buffer.data[36..buffer.data_size as usize].copy_from_slice(&chain);
    buffer
}

fn expected(accepted: bool) -> SpdmResult {
    if accepted {
        Ok(())
    } else {
        Err(SPDM_STATUS_INVALID_CERT)
    }
}

#[test]
fn spdm12_plus_certificate_eku_roles_in_both_acceptance_paths() {
    for (leaf, requester_eku, responder_eku) in [
        (
            &include_bytes!("../../../test_key/ecp256/end_requester_with_spdm_req_eku.cert.der")[..],
            true,
            false,
        ),
        (
            &include_bytes!("../../../test_key/ecp256/end_responder_with_spdm_rsp_eku.cert.der")[..],
            false,
            true,
        ),
        (
            &include_bytes!(
                "../../../test_key/ecp256/end_requester_with_spdm_req_rsp_eku.cert.der"
            )[..],
            true,
            true,
        ),
        (LEAF, true, true),
    ] {
        for version in [
            SpdmVersion::SpdmVersion10,
            SpdmVersion::SpdmVersion11,
            SpdmVersion::SpdmVersion12,
            SpdmVersion::SpdmVersion13,
            SpdmVersion::SpdmVersion14,
        ] {
            let (mut requester, mut responder) = contexts();
            let chain = chain_buffer(leaf);
            for common in [&mut requester.common, &mut responder.common] {
                common.negotiate_info.spdm_version_sel = version;
                common.peer_info.peer_cert_chain_temp = Some(chain);
            }
            assert_eq!(
                requester.verify_spdm_certificate_chain(),
                expected(responder_eku),
                "Responder certificate {:?}: req={}, rsp={}",
                version,
                requester_eku,
                responder_eku
            );
            assert_eq!(
                responder.verify_spdm_certificate_chain(),
                expected(if version >= SpdmVersion::SpdmVersion12 {
                    requester_eku
                } else {
                    responder_eku
                }),
                "Requester certificate {:?}: req={}, rsp={}",
                version,
                requester_eku,
                responder_eku
            );
            if version >= SpdmVersion::SpdmVersion12 {
                let mut corrupt = chain;
                corrupt.data[corrupt.data_size as usize - 1] ^= 1;
                requester.common.peer_info.peer_cert_chain_temp = Some(corrupt);
                responder.common.peer_info.peer_cert_chain_temp = Some(corrupt);
                assert_eq!(
                    requester.verify_spdm_certificate_chain(),
                    Err(SPDM_STATUS_INVALID_CERT)
                );
                assert_eq!(
                    responder.verify_spdm_certificate_chain(),
                    Err(SPDM_STATUS_INVALID_CERT)
                );
            }
        }
    }
}

#[test]
fn spdm14_certificate_fields_both_acceptance_paths() {
    for version in [
        SpdmVersion::SpdmVersion10,
        SpdmVersion::SpdmVersion11,
        SpdmVersion::SpdmVersion12,
        SpdmVersion::SpdmVersion13,
        SpdmVersion::SpdmVersion14,
    ] {
        for (leaf, has_bc) in [(LEAF, true), (MISSING_BC_LEAF, false)] {
            let (mut requester, mut responder) = contexts();
            let chain = chain_buffer(leaf);
            requester.common.negotiate_info.spdm_version_sel = version;
            responder.common.negotiate_info.spdm_version_sel = version;
            requester.common.peer_info.peer_cert_chain_temp = Some(chain);
            responder.common.peer_info.peer_cert_chain_temp = Some(chain);
            let result = expected(version != SpdmVersion::SpdmVersion14 || has_bc);
            assert_eq!(
                requester.verify_spdm_certificate_chain(),
                result,
                "responder certificate {:?}/{}",
                version,
                has_bc
            );
            assert_eq!(
                responder.verify_spdm_certificate_chain(),
                result,
                "requester certificate {:?}/{}",
                version,
                has_bc
            );
        }
    }
}

#[test]
fn spdm14_certificate_model_and_slot_selection() {
    for slot in [0, 3] {
        for model in [
            None,
            Some(SpdmCertificateModelType::SpdmCertModelTypeNone),
            Some(SpdmCertificateModelType::SpdmCertModelTypeDeviceCert),
            Some(SpdmCertificateModelType::SpdmCertModelTypeAliasCert),
            Some(SpdmCertificateModelType::SpdmCertModelTypeGenericCert),
        ] {
            let (mut requester, mut responder) = contexts();
            let chain = chain_buffer(
                if model == Some(SpdmCertificateModelType::SpdmCertModelTypeAliasCert) {
                    ALIAS_LEAF
                } else {
                    LEAF
                },
            );
            for common in [&mut requester.common, &mut responder.common] {
                common.negotiate_info.multi_key_conn_req = true;
                common.negotiate_info.multi_key_conn_rsp = true;
                common.negotiate_info.rsp_capabilities_sel |=
                    SpdmResponseCapabilityFlags::ALIAS_CERT_CAP;
                common.peer_info.peer_cert_info[slot as usize] = model;
                common.peer_info.peer_cert_chain_temp = Some(chain);
            }
            responder.common.encap_context.req_slot_id = slot;
            let accepted = matches!(
                model,
                Some(SpdmCertificateModelType::SpdmCertModelTypeDeviceCert)
                    | Some(SpdmCertificateModelType::SpdmCertModelTypeAliasCert)
            ) || (slot != 0
                && model == Some(SpdmCertificateModelType::SpdmCertModelTypeGenericCert));
            assert_eq!(
                requester.verify_spdm_certificate_chain_for_slot(slot),
                expected(accepted),
                "responder model {:?}/slot {}",
                model,
                slot
            );
            assert_eq!(
                responder.verify_spdm_certificate_chain(),
                expected(accepted),
                "requester model {:?}/slot {}",
                model,
                slot
            );
        }
    }
}

#[test]
fn spdm14_alias_model_rejects_leaf_hardware_identity_in_both_directions() {
    let (mut requester, mut responder) = contexts();
    let chain = chain_buffer(LEAF);
    for common in [&mut requester.common, &mut responder.common] {
        common.negotiate_info.multi_key_conn_req = true;
        common.negotiate_info.multi_key_conn_rsp = true;
        common.peer_info.peer_cert_info[0] =
            Some(SpdmCertificateModelType::SpdmCertModelTypeAliasCert);
        common.peer_info.peer_cert_chain_temp = Some(chain);
    }
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
fn spdm14_certificate_model_uses_peer_direction() {
    for (req_multi, rsp_multi) in [(true, false), (false, true)] {
        let (mut requester, mut responder) = contexts();
        let chain = chain_buffer(LEAF);
        for common in [&mut requester.common, &mut responder.common] {
            common.negotiate_info.multi_key_conn_req = req_multi;
            common.negotiate_info.multi_key_conn_rsp = rsp_multi;
            common.peer_info.peer_cert_info.fill(None);
            common.peer_info.peer_cert_chain_temp = Some(chain);
        }
        assert_eq!(
            requester.verify_spdm_certificate_chain(),
            expected(!rsp_multi)
        );
        assert_eq!(
            responder.verify_spdm_certificate_chain(),
            expected(!req_multi)
        );
    }
}

#[test]
fn spdm14_certificate_fields_do_not_replace_signature_validation() {
    let (mut requester, mut responder) = contexts();
    let mut chain = chain_buffer(LEAF);
    chain.data[chain.data_size as usize - 1] ^= 1;
    requester.common.peer_info.peer_cert_chain_temp = Some(chain);
    responder.common.peer_info.peer_cert_chain_temp = Some(chain);
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
fn spdm14_encapsulated_digest_model_roundtrip() {
    for (req_multi, rsp_multi) in [(true, false), (false, true)] {
        let (mut requester, mut responder) = contexts();
        for common in [&mut requester.common, &mut responder.common] {
            common.negotiate_info.multi_key_conn_req = req_multi;
            common.negotiate_info.multi_key_conn_rsp = rsp_multi;
            common.negotiate_info.req_capabilities_sel |= SpdmRequestCapabilityFlags::CERT_CAP;
        }
        requester.common.provision_info.my_cert_chain.fill(None);
        requester.common.provision_info.local_supported_slot_mask = 0b1001;
        for (slot, leaf, model) in [
            (
                0,
                LEAF,
                SpdmCertificateModelType::SpdmCertModelTypeDeviceCert,
            ),
            (
                3,
                MISSING_BC_LEAF,
                SpdmCertificateModelType::SpdmCertModelTypeGenericCert,
            ),
        ] {
            requester.common.provision_info.my_cert_chain[slot] = Some(chain_buffer(leaf));
            requester.common.provision_info.local_cert_info[slot] = Some(model);
            requester.common.provision_info.local_key_pair_id[slot] = Some(slot as u8 + 10);
            requester.common.provision_info.local_key_usage_bit_mask[slot] =
                Some(SpdmKeyUsageMask::KEY_USAGE_MASK_CHALLENGE_USE);
        }
        responder.common.peer_info.peer_cert_info[4] =
            Some(SpdmCertificateModelType::SpdmCertModelTypeAliasCert);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion14,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetDigests,
            },
            payload: SpdmMessagePayload::SpdmGetDigestsRequest(SpdmGetDigestsRequestPayload {}),
        };
        let mut request_bytes = [0u8; 4];
        let mut request_writer = Writer::init(&mut request_bytes);
        request
            .spdm_encode(&mut responder.common, &mut request_writer)
            .unwrap();
        let mut response_bytes = [0u8; 256];
        let mut response = Writer::init(&mut response_bytes);
        requester.encap_handle_get_digest(request_writer.used_slice(), &mut response);
        assert_eq!(response.used(), 4 + 64 + if req_multi { 8 } else { 0 });
        for (packed, slot) in [0, 3].iter().enumerate() {
            let chain = requester.common.provision_info.my_cert_chain[*slot]
                .as_ref()
                .unwrap();
            let digest =
                crypto::hash::hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_256, chain.as_ref()).unwrap();
            assert_eq!(
                &response.used_slice()[4 + packed * 32..4 + (packed + 1) * 32],
                digest.as_ref()
            );
        }
        responder
            .handle_encap_response_digest(response.used_slice())
            .unwrap();
        if req_multi {
            assert!(
                responder
                    .handle_encap_response_digest(&response.used_slice()[..68])
                    .is_err(),
                "requester multi-key metadata must not be silently omitted"
            );
        }
        assert_eq!(
            responder.common.peer_info.peer_provisioned_slot_mask,
            0b1001
        );
        assert_eq!(responder.common.peer_info.peer_cert_info[4], None);
        for slot in [0, 3] {
            let expected_model = if req_multi {
                requester.common.provision_info.local_cert_info[slot]
            } else {
                None
            };
            assert_eq!(
                responder.common.peer_info.peer_cert_info[slot],
                expected_model
            );
            assert_eq!(
                responder.common.peer_info.peer_key_pair_id[slot],
                if req_multi {
                    Some(slot as u8 + 10)
                } else {
                    None
                }
            );
            assert_eq!(
                responder.common.peer_info.peer_key_usage_bit_mask[slot],
                if req_multi {
                    Some(SpdmKeyUsageMask::KEY_USAGE_MASK_CHALLENGE_USE)
                } else {
                    None
                }
            );
        }
    }
}

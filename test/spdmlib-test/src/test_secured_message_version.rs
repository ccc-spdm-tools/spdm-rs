// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

// The selection of the Secured Message version in KEY_EXCHANGE and PSK_EXCHANGE (DSP0277): the
// Responder selects the latest version that the Requester supports and it supports itself,
// whatever the order of the lists, and the Requester accepts only a version that it offered.

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, get_rsp_cert_chain_buff};
use async_trait::async_trait;
use core::ops::DerefMut;
use spdmlib::common::opaque::*;
use spdmlib::common::{SpdmConnectionState, SpdmContext, SpdmDeviceIo};
use spdmlib::config::MAX_SPDM_PSK_HINT_SIZE;
use spdmlib::config::SPDM_DATA_TRANSFER_SIZE;
use spdmlib::error::{SpdmResult, SpdmStatus, SPDM_STATUS_INVALID_MSG_FIELD};
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

fn version(byte: u8) -> SecuredMessageVersion {
    SecuredMessageVersion::try_from(byte).unwrap()
}

// A list of Secured Message versions, in this order.
fn versions(bytes: &[u8]) -> [Option<SecuredMessageVersion>; MAX_SECURE_SPDM_VERSION_COUNT] {
    assert!(
        bytes.len() <= MAX_SECURE_SPDM_VERSION_COUNT,
        "a list holds at most {} versions",
        MAX_SECURE_SPDM_VERSION_COUNT
    );
    let mut versions = [None; MAX_SECURE_SPDM_VERSION_COUNT];
    for (slot, byte) in versions.iter_mut().zip(bytes) {
        *slot = Some(version(*byte));
    }
    versions
}

fn version_list(bytes: &[u8]) -> SecuredMessageVersionList {
    // The count says how many entries are set, so it cannot be more than the list holds.
    assert!(
        bytes.len() <= MAX_SECURE_SPDM_VERSION_COUNT,
        "a list holds at most {} versions",
        MAX_SECURE_SPDM_VERSION_COUNT
    );
    let mut versions_list = [SecuredMessageVersion::default(); MAX_SECURE_SPDM_VERSION_COUNT];
    for (slot, byte) in versions_list.iter_mut().zip(bytes) {
        *slot = version(*byte);
    }
    SecuredMessageVersionList {
        version_count: bytes.len() as u8,
        versions_list,
    }
}

const V10: u8 = DMTF_SECURE_SPDM_VERSION_10;
const V11: u8 = DMTF_SECURE_SPDM_VERSION_11;
const V12: u8 = DMTF_SECURE_SPDM_VERSION_12;
const V13: u8 = DMTF_SECURE_SPDM_VERSION_13;

// A context that encodes and decodes the Secured Message opaque data of SPDM 1.2, and supports
// these Secured Message versions.
fn new_context(supported: &[u8]) -> SpdmContext {
    let (mut config_info, provision_info) = create_info();
    config_info.secure_spdm_version = versions(supported);
    let mut context = responder::ResponderContext::new(
        Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            SharedBuffer::new(),
        )))),
        Arc::new(Mutex::new(PciDoeTransportEncap {})),
        config_info,
        provision_info,
    )
    .common;
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    context.negotiate_info.other_params_support = SpdmAlgoOtherParams::OPAQUE_DATA_FMT1;
    context
}

#[test]
fn test_the_supported_versions_are_ordered_from_the_earliest_to_the_latest() {
    let mut context = new_context(&[V10, V11, V12, V13]);
    // The Requester can list its versions in any order.
    for sent in [
        &[V10, V11, V12, V13][..],
        &[V13, V12, V11, V10],
        &[V11, V13, V10, V12],
        &[V12, V10],
        &[V13],
        &[V13, V10],
    ] {
        let opaque = SpdmOpaqueStruct::from_sm_supported_ver_list_opaque(
            &mut context,
            &SMSupportedVerListOpaque {
                secured_message_version_list: version_list(sent),
            },
        )
        .unwrap();
        let list = opaque
            .rsp_get_dmtf_supported_secure_spdm_version_list(&mut context)
            .unwrap();

        let mut expected = sent.to_vec();
        expected.sort_unstable();
        assert_eq!(list.version_count as usize, sent.len());
        let received: Vec<u8> = list.versions_list[..sent.len()]
            .iter()
            .map(u8::from)
            .collect();
        assert_eq!(received, expected, "sent {:02x?}", sent);
    }
}

#[test]
fn test_the_requester_gets_a_selection_only_for_a_version_it_supports() {
    let selection = |context: &mut SpdmContext, selected: u8| {
        SpdmOpaqueStruct::from_sm_version_sel_opaque(
            context,
            &SMVersionSelOpaque {
                secured_message_version: version(selected),
            },
        )
        .unwrap()
        .req_get_dmtf_secure_spdm_version_selection(context)
    };

    let mut context = new_context(&[V10, V12]);
    assert_eq!(selection(&mut context, V12), Some(version(V12)));
    assert_eq!(selection(&mut context, V10), Some(version(V10)));
    // Not offered: a version in between, a later one, and one that does not exist.
    assert_eq!(selection(&mut context, V11), None);
    assert_eq!(selection(&mut context, V13), None);
    assert_eq!(selection(&mut context, 0x14), None);

    // A Requester that supports nothing accepts nothing.
    let mut context = new_context(&[]);
    assert_eq!(selection(&mut context, V12), None);

    // No selection at all.
    let mut context = new_context(&[V10, V11, V12, V13]);
    assert_eq!(
        SpdmOpaqueStruct::default().req_get_dmtf_secure_spdm_version_selection(&mut context),
        None
    );
}

#[derive(Clone, Copy)]
enum Flow {
    KeyExchange,
    PskExchange,
}

// The data transfer size that holds a whole PSK_EXCHANGE message with its opaque data.
const MIN_TRANSFER_SIZE_WITHOUT_CHUNKING: usize = 256;

// Both flows, with SPDM 1.2 and, for PSK_EXCHANGE, SPDM 1.1 (the general opaque data header), which
// has no chunking, so it only runs when the data transfer size holds the whole message.
fn cases() -> Vec<(Flow, SpdmVersion)> {
    let mut cases = vec![
        (Flow::KeyExchange, SpdmVersion::SpdmVersion12),
        (Flow::PskExchange, SpdmVersion::SpdmVersion12),
    ];
    if SPDM_DATA_TRANSFER_SIZE >= MIN_TRANSFER_SIZE_WITHOUT_CHUNKING {
        cases.push((Flow::PskExchange, SpdmVersion::SpdmVersion11));
    }
    cases
}

// The device that the Requester talks to: the Responder, with the version in its version
// selection data changed on its way back, if asked.
struct ChangeSelectedVersion {
    inner: FakeSpdmDeviceIo,
    to: Option<u8>,
}

#[async_trait]
impl SpdmDeviceIo for ChangeSelectedVersion {
    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        self.inner.send(buffer).await
    }

    async fn receive(
        &mut self,
        read_buffer: Arc<Mutex<&mut [u8]>>,
        timeout: usize,
    ) -> Result<usize, usize> {
        let len = self.inner.receive(read_buffer.clone(), timeout).await?;
        if let Some(to) = self.to {
            // The version selection element: ID, VendorLen, 4 bytes of data (SMDataVersion,
            // SMDataID, then the version), which is the byte to change, as its last one.
            let element = [
                DMTF_ID,
                DMTF_VENDOR_LEN,
                4,
                0,
                SM_DATA_VERSION,
                VERSION_SELECTION_SM_DATA_ID,
                0,
            ];
            let mut read_buffer = read_buffer.lock();
            let read_buffer = read_buffer.deref_mut();
            if let Some(position) = read_buffer[..len]
                .windows(element.len())
                .position(|window| window == element)
            {
                // The version byte follows the element. Change it only if it was received.
                let version_index = position + element.len();
                if version_index < len {
                    read_buffer[version_index] = to;
                }
            }
        }
        Ok(len)
    }

    async fn flush_all(&mut self) -> SpdmResult {
        self.inner.flush_all().await
    }
}

// Run a key exchange or a PSK exchange between a Requester and a Responder that support these
// Secured Message versions, in this order. The version in the response is changed to `change_to`
// if it is set. Return the version that the session has on the Requester and on the Responder.
async fn exchange(
    flow: Flow,
    spdm_version: SpdmVersion,
    requester_versions: &[u8],
    responder_versions: &[u8],
    change_to: Option<u8>,
) -> Result<(SecuredMessageVersion, SecuredMessageVersion), SpdmStatus> {
    let (mut rsp_config_info, rsp_provision_info) = create_info();
    let (mut req_config_info, req_provision_info) = create_info();
    req_config_info.secure_spdm_version = versions(requester_versions);
    rsp_config_info.secure_spdm_version = versions(responder_versions);

    let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        SharedBuffer::new(),
    ))));
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());
    secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

    let mut responder = responder::ResponderContext::new(
        device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );
    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
    responder.common.negotiate_info.spdm_version_sel = spdm_version;
    if spdm_version >= SpdmVersion::SpdmVersion12 {
        responder.common.negotiate_info.other_params_support =
            SpdmAlgoOtherParams::OPAQUE_DATA_FMT1;
    }
    #[cfg(feature = "chunk-cap")]
    {
        responder.common.negotiate_info.rsp_data_transfer_size_sel = SPDM_DATA_TRANSFER_SIZE as u32;
        responder.common.negotiate_info.req_data_transfer_size_sel = SPDM_DATA_TRANSFER_SIZE as u32;
        responder.common.negotiate_info.rsp_capabilities_sel |=
            SpdmResponseCapabilityFlags::CHUNK_CAP;
        responder.common.negotiate_info.req_capabilities_sel |=
            SpdmRequestCapabilityFlags::CHUNK_CAP;
    }
    match flow {
        Flow::KeyExchange => {
            responder.common.negotiate_info.rsp_capabilities_sel |=
                SpdmResponseCapabilityFlags::KEY_EX_CAP;
            responder.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
            // The algorithm of the certificate chain, which is RSA when SPDMRS_USE_ECDSA is
            // false, and not always ECDSA.
            responder.common.negotiate_info.base_asym_sel =
                responder.common.config_info.base_asym_algo;
            #[cfg(feature = "mut-auth")]
            {
                responder.common.negotiate_info.rsp_capabilities_sel |=
                    SpdmResponseCapabilityFlags::MUT_AUTH_CAP;
                responder.common.negotiate_info.req_capabilities_sel |=
                    SpdmRequestCapabilityFlags::MUT_AUTH_CAP;
            }
            responder.common.reset_runtime_info();
            responder.common.provision_info.my_cert_chain = [
                Some(get_rsp_cert_chain_buff()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ];
        }
        Flow::PskExchange => {
            responder.common.negotiate_info.rsp_capabilities_sel |=
                SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT;
        }
    }
    responder
        .common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

    let responder = Arc::new(Mutex::new(responder));
    let device_io_requester = Arc::new(Mutex::new(ChangeSelectedVersion {
        inner: FakeSpdmDeviceIo::new(Arc::new(SharedBuffer::new()), responder.clone()),
        to: change_to,
    }));
    let mut requester = RequesterContext::new(
        device_io_requester,
        Arc::new(Mutex::new(PciDoeTransportEncap {})),
        req_config_info,
        req_provision_info,
    );
    requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
    requester.common.negotiate_info.spdm_version_sel = spdm_version;
    if spdm_version >= SpdmVersion::SpdmVersion12 {
        requester.common.negotiate_info.other_params_support =
            SpdmAlgoOtherParams::OPAQUE_DATA_FMT1;
    }
    #[cfg(feature = "chunk-cap")]
    {
        requester.common.negotiate_info.rsp_data_transfer_size_sel = SPDM_DATA_TRANSFER_SIZE as u32;
        requester.common.negotiate_info.req_data_transfer_size_sel = SPDM_DATA_TRANSFER_SIZE as u32;
        requester.common.negotiate_info.rsp_capabilities_sel |=
            SpdmResponseCapabilityFlags::CHUNK_CAP;
        requester.common.negotiate_info.req_capabilities_sel |=
            SpdmRequestCapabilityFlags::CHUNK_CAP;
    }

    let measurement_summary_hash_type =
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone;
    let session_id = match flow {
        Flow::KeyExchange => {
            requester.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
            // The algorithm of the certificate chain, which is RSA when SPDMRS_USE_ECDSA is
            // false, and not always ECDSA.
            requester.common.negotiate_info.base_asym_sel =
                requester.common.config_info.base_asym_algo;
            #[cfg(feature = "mut-auth")]
            {
                requester.common.negotiate_info.rsp_capabilities_sel |=
                    SpdmResponseCapabilityFlags::MUT_AUTH_CAP;
                requester.common.negotiate_info.req_capabilities_sel |=
                    SpdmRequestCapabilityFlags::MUT_AUTH_CAP;
            }
            requester.common.reset_runtime_info();
            requester.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());
            requester
                .send_receive_spdm_key_exchange(0, measurement_summary_hash_type)
                .await?
        }
        Flow::PskExchange => {
            let mut psk_hint = SpdmPskHintStruct {
                data_size: b"TestPskHint\0".len() as u16,
                data: [0u8; MAX_SPDM_PSK_HINT_SIZE],
            };
            psk_hint.data[0..(psk_hint.data_size as usize)].copy_from_slice(b"TestPskHint\0");
            requester
                .send_receive_spdm_psk_exchange(measurement_summary_hash_type, Some(&psk_hint))
                .await?
        }
    };

    let requester_version = requester
        .common
        .get_session_via_id(session_id)
        .unwrap()
        .secure_spdm_version_sel;
    let responder_version = responder
        .lock()
        .common
        .get_session_via_id(session_id)
        .unwrap()
        .secure_spdm_version_sel;
    Ok((requester_version, responder_version))
}

#[test]
fn test_the_responder_selects_the_latest_common_version() {
    let task = async {
        for (flow, spdm_version) in cases() {
            // (Requester versions, Responder versions, the selected version.)
            let cases: [(&[u8], &[u8], u8); 7] = [
                (&[V10, V11, V12, V13], &[V10, V11, V12, V13], V13),
                // The Requester lists the latest version first, so it is not the last common one.
                (&[V13, V12, V11, V10], &[V10, V11, V12, V13], V13),
                (&[V10, V11, V12, V13], &[V13, V12, V11, V10], V13),
                (&[V13, V12, V11, V10], &[V13, V12, V11, V10], V13),
                (&[V11, V13, V10, V12], &[V12, V10, V13, V11], V13),
                // Only the common versions count.
                (&[V13, V10], &[V10, V11, V12], V10),
                (&[V13, V12], &[V12], V12),
            ];
            for (requester, responder, selected) in cases {
                let (requester_version, responder_version) =
                    exchange(flow, spdm_version, requester, responder, None)
                        .await
                        .unwrap();
                assert_eq!(requester_version, version(selected));
                assert_eq!(responder_version, version(selected));
            }
        }
    };
    executor::block_on(task);
}

#[test]
fn test_the_requester_rejects_a_version_it_did_not_offer() {
    // The response is searched for the version selection, which chunking can cut in two.
    if SPDM_DATA_TRANSFER_SIZE < MIN_TRANSFER_SIZE_WITHOUT_CHUNKING {
        return;
    }
    let task = async {
        for (flow, spdm_version) in cases() {
            // The Requester offers 1.0 to 1.2. The Responder selects 1.2, and the response is
            // changed to say 1.3, which the Requester did not offer.
            let offered: &[u8] = &[V10, V11, V12];
            let all: &[u8] = &[V10, V11, V12, V13];
            assert_eq!(
                exchange(flow, spdm_version, offered, all, Some(V13)).await,
                Err(SPDM_STATUS_INVALID_MSG_FIELD)
            );
            // A version that does not exist.
            assert_eq!(
                exchange(flow, spdm_version, all, all, Some(0x14)).await,
                Err(SPDM_STATUS_INVALID_MSG_FIELD)
            );
            // Without the change the exchange works, and selects the latest common version.
            let (requester_version, responder_version) =
                exchange(flow, spdm_version, offered, all, None)
                    .await
                    .unwrap();
            assert_eq!(requester_version, version(V12));
            assert_eq!(responder_version, version(V12));
        }
    };
    executor::block_on(task);
}

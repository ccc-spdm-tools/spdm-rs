// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

// A session ends at the smaller one of the AEAD limits that the Requester and the Responder
// ask for in KEY_EXCHANGE or PSK_EXCHANGE (DSP0277 1.3).

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, get_rsp_cert_chain_buff};
use spdmlib::common::opaque::*;
use spdmlib::common::SpdmConnectionState;
use spdmlib::config::MAX_SPDM_PSK_HINT_SIZE;
use spdmlib::config::SPDM_DATA_TRANSFER_SIZE;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[derive(Clone, Copy)]
enum Flow {
    KeyExchange,
    PskExchange,
}

// The Secured Message versions up to this one.
fn secured_message_versions(
    highest: u8,
) -> [Option<SecuredMessageVersion>; MAX_SECURE_SPDM_VERSION_COUNT] {
    let mut versions = [None; MAX_SECURE_SPDM_VERSION_COUNT];
    for (slot, version) in versions.iter_mut().zip([
        DMTF_SECURE_SPDM_VERSION_10,
        DMTF_SECURE_SPDM_VERSION_11,
        DMTF_SECURE_SPDM_VERSION_12,
        DMTF_SECURE_SPDM_VERSION_13,
    ]) {
        if version <= highest {
            *slot = Some(SecuredMessageVersion::try_from(version).unwrap());
        }
    }
    versions
}

// The AEAD limit element in the opaque data: a DMTF element (ID, VendorLen) with 3 bytes of
// data (SMDataVersion, SMDataID, AeadLimitExponent). This is its start, up to the exponent.
const AEAD_LIMIT_ELEMENT: [u8; 6] = [
    DMTF_ID,
    DMTF_VENDOR_LEN,
    3,
    0,
    SM_DATA_VERSION,
    AEAD_LIMIT_SM_DATA_ID,
];

// Run a key exchange or a PSK exchange, where the Requester and the Responder ask for these
// AEAD limit exponents (0 is the default) and support Secured Message versions up to
// `req_highest_secured_version` and `rsp_highest_secured_version`. Return the largest
// sequence number that the session allows on the Requester and on the Responder, and whether
// the AEAD limit element went over the wire, in a request or in a response.
async fn exchange_with_wire(
    flow: Flow,
    spdm_version: SpdmVersion,
    req_exponent: u8,
    req_highest_secured_version: u8,
    rsp_exponent: u8,
    rsp_highest_secured_version: u8,
) -> (u64, u64, bool) {
    let (mut rsp_config_info, rsp_provision_info) = create_info();
    let (mut req_config_info, req_provision_info) = create_info();
    req_config_info.aead_limit_exponent = req_exponent;
    req_config_info.secure_spdm_version = secured_message_versions(req_highest_secured_version);
    rsp_config_info.aead_limit_exponent = rsp_exponent;
    rsp_config_info.secure_spdm_version = secured_message_versions(rsp_highest_secured_version);

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
    // Everything that the Requester sends and receives goes through this buffer.
    let requester_wire = Arc::new(SharedBuffer::new());
    let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
        requester_wire.clone(),
        responder.clone(),
    )));
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
                .await
                .unwrap()
        }
        Flow::PskExchange => {
            let mut psk_hint = SpdmPskHintStruct {
                data_size: b"TestPskHint\0".len() as u16,
                data: [0u8; MAX_SPDM_PSK_HINT_SIZE],
            };
            psk_hint.data[0..(psk_hint.data_size as usize)].copy_from_slice(b"TestPskHint\0");
            requester
                .send_receive_spdm_psk_exchange(measurement_summary_hash_type, Some(&psk_hint))
                .await
                .unwrap()
        }
    };

    let requester_max = requester
        .common
        .get_session_via_id(session_id)
        .unwrap()
        .get_max_sequence_number();
    let responder_max = responder
        .lock()
        .common
        .get_session_via_id(session_id)
        .unwrap()
        .get_max_sequence_number();
    let aead_limit_on_wire = requester_wire
        .contents()
        .windows(AEAD_LIMIT_ELEMENT.len())
        .any(|window| window == AEAD_LIMIT_ELEMENT);
    (requester_max, responder_max, aead_limit_on_wire)
}

// The same, for a Requester that supports all the Secured Message versions.
async fn exchange(
    flow: Flow,
    spdm_version: SpdmVersion,
    req_exponent: u8,
    rsp_exponent: u8,
    rsp_highest_secured_version: u8,
) -> (u64, u64) {
    let (requester_max, responder_max, _) = exchange_with_wire(
        flow,
        spdm_version,
        req_exponent,
        V13,
        rsp_exponent,
        rsp_highest_secured_version,
    )
    .await;
    (requester_max, responder_max)
}

const MAX: u64 = u64::MAX;
const V13: u8 = DMTF_SECURE_SPDM_VERSION_13;
const V12: u8 = DMTF_SECURE_SPDM_VERSION_12;

// The data transfer size that holds a whole PSK_EXCHANGE request with its opaque data.
const MIN_TRANSFER_SIZE_WITHOUT_CHUNKING: usize = 256;

// Both flows, with the opaque data of SPDM 1.2 (OpaqueDataFmt1) and, for PSK_EXCHANGE, of SPDM 1.1
// (the general header). SPDM 1.1 has no chunking, so it only runs when the data transfer size, which
// the chunking test configuration makes small, holds the whole message.
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

#[test]
fn test_the_session_gets_the_smaller_aead_limit() {
    let task = async {
        for (flow, version) in cases() {
            // Both ask for a limit: the smaller one wins, from either side.
            assert_eq!(exchange(flow, version, 8, 12, V13).await, (255, 255));
            assert_eq!(exchange(flow, version, 12, 8, V13).await, (255, 255));
            assert_eq!(
                exchange(flow, version, 20, 20, V13).await,
                ((1 << 20) - 1, (1 << 20) - 1)
            );
            // Only one side asks for a limit: the other has the default.
            assert_eq!(exchange(flow, version, 0, 12, V13).await, (4095, 4095));
            assert_eq!(exchange(flow, version, 8, 0, V13).await, (255, 255));
            // The default limit of 2^64 is not asked for, and is not a limit.
            assert_eq!(exchange(flow, version, 64, 64, V13).await, (MAX, MAX));
            assert_eq!(exchange(flow, version, 0, 0, V13).await, (MAX, MAX));
        }
    };
    executor::block_on(task);
}

#[test]
fn test_the_aead_limit_needs_secured_message_version_1_3() {
    let task = async {
        for (flow, version) in cases() {
            // The Responder does not select 1.3, so the AEAD limit data does not apply, even
            // though the Requester sent it.
            assert_eq!(exchange(flow, version, 8, 12, V12).await, (MAX, MAX));
            assert_eq!(exchange(flow, version, 8, 0, V12).await, (MAX, MAX));
            assert_eq!(exchange(flow, version, 0, 12, V12).await, (MAX, MAX));
        }
    };
    executor::block_on(task);
}

// Who sends the AEAD limit data, and who applies it. An endpoint sends it only when it supports
// Secured Message version 1.3 and asks for a limit below the default. It is applied only when
// 1.3 is selected, which needs the Requester and the Responder both to support it.
#[test]
fn test_the_aead_limit_data_needs_secured_message_version_1_3_on_both_sides() {
    let task = async {
        // Chunking splits the messages into pieces, which can cut the element in two, so the
        // wire is only looked at when the messages are not chunked.
        let check = |got: (u64, u64, bool), want: (u64, u64, bool)| {
            assert_eq!((got.0, got.1), (want.0, want.1));
            if SPDM_DATA_TRANSFER_SIZE >= MIN_TRANSFER_SIZE_WITHOUT_CHUNKING {
                assert_eq!(got.2, want.2);
            }
        };
        for (flow, version) in cases() {
            // (flow, version, Requester exponent, Requester highest, Responder exponent,
            // Responder highest) gives (Requester maximum, Responder maximum, on the wire).

            // Both support 1.3: the data goes over the wire, from either side, and applies.
            check(
                exchange_with_wire(flow, version, 8, V13, 0, V13).await,
                (255, 255, true),
            );
            check(
                exchange_with_wire(flow, version, 0, V13, 12, V13).await,
                (4095, 4095, true),
            );
            // The default limit is not sent.
            check(
                exchange_with_wire(flow, version, 0, V13, 0, V13).await,
                (MAX, MAX, false),
            );

            // The Requester supports only up to 1.2: it does not send its data, 1.3 is not
            // selected, so the Responder neither answers with its data nor applies a limit.
            check(
                exchange_with_wire(flow, version, 8, V12, 12, V13).await,
                (MAX, MAX, false),
            );
            check(
                exchange_with_wire(flow, version, 0, V12, 12, V13).await,
                (MAX, MAX, false),
            );

            // The Responder supports only up to 1.2: 1.3 is not selected, so nothing applies,
            // and the Responder does not answer with its data. The Requester does send its data
            // in the request, because it cannot know that yet.
            check(
                exchange_with_wire(flow, version, 8, V13, 12, V12).await,
                (MAX, MAX, true),
            );
            check(
                exchange_with_wire(flow, version, 0, V13, 12, V12).await,
                (MAX, MAX, false),
            );

            // Neither supports 1.3.
            check(
                exchange_with_wire(flow, version, 8, V12, 12, V12).await,
                (MAX, MAX, false),
            );
        }
    };
    executor::block_on(task);
}

// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[cfg(feature = "hashed-transcript-data")]
extern crate alloc;
#[cfg(feature = "hashed-transcript-data")]
use {
    crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer},
    crate::common::secret_callback::*,
    crate::common::transport::PciDoeTransportEncap,
    crate::common::util::{create_info, get_rsp_cert_chain_buff},
    alloc::sync::Arc,
    spdmlib::common::SpdmConnectionState,
    spdmlib::config::{MAX_SPDM_CERT_CHAIN_DATA_SIZE, MAX_SPDM_MSG_SIZE, SPDM_DATA_TRANSFER_SIZE},
    spdmlib::error::{SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD},
    spdmlib::protocol::*,
    spdmlib::requester::RequesterContext,
    spdmlib::{responder, secret},
    spin::Mutex,
};

#[test]
#[cfg(feature = "hashed-transcript-data")]
fn test_case0_send_receive_spdm_certificate() {
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());

        let mut responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.reset_runtime_info();
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        #[cfg(feature = "chunk-cap")]
        {
            responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
            responder.common.negotiate_info.rsp_data_transfer_size_sel =
                (SPDM_DATA_TRANSFER_SIZE) as u32;
            responder.common.negotiate_info.req_data_transfer_size_sel =
                (SPDM_DATA_TRANSFER_SIZE) as u32;
            responder.common.negotiate_info.req_capabilities_sel |=
                SpdmRequestCapabilityFlags::CHUNK_CAP;
            responder.common.negotiate_info.rsp_capabilities_sel |=
                SpdmResponseCapabilityFlags::CHUNK_CAP;
        }

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

        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
            Arc::new(shared_buffer),
            Arc::new(Mutex::new(responder)),
        )));

        let mut requester = RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        #[cfg(feature = "chunk-cap")]
        {
            requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
            requester.common.negotiate_info.rsp_data_transfer_size_sel =
                (SPDM_DATA_TRANSFER_SIZE) as u32;
            requester.common.negotiate_info.req_data_transfer_size_sel =
                (SPDM_DATA_TRANSFER_SIZE) as u32;
            requester.common.negotiate_info.req_capabilities_sel |=
                SpdmRequestCapabilityFlags::CHUNK_CAP;
            requester.common.negotiate_info.rsp_capabilities_sel |=
                SpdmResponseCapabilityFlags::CHUNK_CAP;
        }

        let status = requester
            .send_receive_spdm_certificate(None, 0)
            .await
            .is_ok();
        assert!(status);
    };
    executor::block_on(future);
}

#[test]
#[cfg(feature = "hashed-transcript-data")]
fn test_handle_spdm_certificate_partial_response() {
    struct Tc<'a> {
        name: &'a str,
        slot_id: u8,
        total_size: u32,
        offset: u32,
        length: u32,
        receive_buffer: &'a [u8],
        expected_result: SpdmResult<(u32, u32)>,
    }
    let tt: [Tc; 8] = [
        Tc {
            name: "invalid certificate partial resp",
            slot_id: 0u8,
            total_size: 0u32,
            offset: 0u32,
            length: 0u32,
            receive_buffer: &[0x12, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            expected_result: Err(SPDM_STATUS_ERROR_PEER),
        },
        Tc {
            name: "zero length portion",
            slot_id: 0u8,
            total_size: 2048u32,
            offset: 0u32,
            length: 2048u32,
            receive_buffer: &[
                0x12, 0x02, 0x00, 0x00, //
                0x00, 0x00, // portion
                0x00, 0x08, // remainder
            ],
            expected_result: Err(SPDM_STATUS_INVALID_MSG_FIELD),
        },
        Tc {
            name: "portion larger than remainder",
            slot_id: 0u8,
            total_size: 10u32,
            offset: 7u32,
            length: 3u32,
            receive_buffer: &[
                0x12, 0x02, 0x00, 0x00, //
                0x05, 0x00, // portion
                0x00, 0x00, // remainder
                0x05, 0x00, 0x00, 0x00, 0x00,
            ],
            expected_result: Err(SPDM_STATUS_INVALID_MSG_FIELD),
        },
        Tc {
            name: "portion larger than max cert chain size",
            slot_id: 0u8,
            total_size: MAX_SPDM_CERT_CHAIN_DATA_SIZE as u32,
            offset: (MAX_SPDM_CERT_CHAIN_DATA_SIZE - 3) as u32,
            length: 3u32,
            receive_buffer: &[
                0x12, 0x02, 0x00, 0x00, //
                0x05, 0x00, // portion
                0x00, 0x00, // remainder
                0x05, 0x00, 0x00, 0x00, 0x00,
            ],
            expected_result: Err(SPDM_STATUS_INVALID_MSG_FIELD),
        },
        Tc {
            name: "zero remainder but certificate is incomplete",
            slot_id: 0u8,
            total_size: 100u32,
            offset: 90u32,
            length: 10u32,
            receive_buffer: &[
                0x12, 0x02, 0x00, 0x00, //
                0x05, 0x00, // portion
                0x00, 0x00, // remainder
                0x05, 0x00, 0x00, 0x00, 0x00,
            ],
            expected_result: Err(SPDM_STATUS_INVALID_MSG_FIELD),
        },
        Tc {
            name: "remainder larger than max cert chain size",
            slot_id: 0u8,
            total_size: MAX_SPDM_CERT_CHAIN_DATA_SIZE as u32,
            offset: (MAX_SPDM_CERT_CHAIN_DATA_SIZE - 10) as u32,
            length: 10u32,
            receive_buffer: &[
                0x12, 0x02, 0x00, 0x00, //
                0x05, 0x00, // portion
                0x06, 0x00, // remainder
                0x05, 0x00, 0x00, 0x00, 0x00,
            ],
            expected_result: Err(SPDM_STATUS_INVALID_MSG_FIELD),
        },
        Tc {
            name: "wrong certificate slot id",
            slot_id: 7u8,
            total_size: 100u32,
            offset: 90u32,
            length: 10u32,
            receive_buffer: &[
                0x12, 0x02, 0x00, 0x00, //
                0x05, 0x00, // portion
                0x05, 0x00, // remainder
                0x05, 0x00, 0x00, 0x00, 0x00,
            ],
            expected_result: Err(SPDM_STATUS_INVALID_MSG_FIELD),
        },
        Tc {
            name: "positive",
            slot_id: 0u8,
            total_size: 100u32,
            offset: 90u32,
            length: 10u32,
            receive_buffer: &[
                0x12, 0x02, 0x00, 0x00, //
                0x05, 0x00, // portion
                0x05, 0x00, // remainder
                0x05, 0x00, 0x00, 0x00, 0x00,
            ],
            expected_result: Ok((5, 5)),
        },
    ];
    for tc in tt {
        executor::add_task(async move {
            let (req_config_info, req_provision_info) = create_info();
            let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
            let device_io = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
                SharedBuffer::new(),
            ))));
            let mut requester = RequesterContext::new(
                device_io,
                pcidoe_transport_encap,
                req_config_info,
                req_provision_info,
            );
            requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
            requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
            requester.common.peer_info.peer_cert_chain_temp = Some(SpdmCertChainBuffer::default());
            let session_id = None;
            let send_buffer = [0u8; MAX_SPDM_MSG_SIZE];
            let result = requester.handle_spdm_certificate_partial_response(
                session_id,
                tc.slot_id,
                tc.total_size,
                tc.offset,
                tc.length,
                &send_buffer,
                0,
                tc.receive_buffer,
            );
            assert!(
                result == tc.expected_result,
                "tc '{}' expect {:?} got {:?}",
                tc.name,
                tc.expected_result,
                result
            );
        })
    }
    executor::poll_tasks();
}

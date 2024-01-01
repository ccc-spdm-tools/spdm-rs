// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use spdmlib::common::SpdmConnectionState;
use spdmlib::config::MAX_SPDM_PSK_HINT_SIZE;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_send_receive_spdm_psk_exchange() {
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

        let mut responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
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
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
        let measurement_summary_hash_type =
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone;
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        let mut psk_key = SpdmPskHintStruct {
            data_size: b"TestPskHint\0".len() as u16,
            data: [0u8; MAX_SPDM_PSK_HINT_SIZE],
        };
        psk_key.data[0..(psk_key.data_size as usize)].copy_from_slice(b"TestPskHint\0");

        let status = requester
            .send_receive_spdm_psk_exchange(measurement_summary_hash_type, Some(&psk_key))
            .await
            .is_ok();
        assert!(status);
    };
    executor::block_on(future);
}

#[test]
fn test_case1_send_receive_spdm_psk_exchange() {
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

        let mut responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_256; // different base hash algo will cause key negotiate fail
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
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
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
        let measurement_summary_hash_type =
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone;
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        let mut psk_key = SpdmPskHintStruct {
            data_size: b"TestPskHint\0".len() as u16,
            data: [0u8; MAX_SPDM_PSK_HINT_SIZE],
        };
        psk_key.data[0..(psk_key.data_size as usize)].copy_from_slice(b"TestPskHint\0");

        let status = requester
            .send_receive_spdm_psk_exchange(measurement_summary_hash_type, Some(&psk_key))
            .await
            .is_ok();
        assert_eq!(status, false);

        for session in requester.common.session.iter() {
            assert_eq!(
                session.get_session_id(),
                spdmlib::common::INVALID_SESSION_ID
            );
        }
    };
    executor::block_on(future);
}

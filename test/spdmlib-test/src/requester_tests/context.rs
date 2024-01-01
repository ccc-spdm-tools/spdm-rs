// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use crate::watchdog_impl_sample::init_watchdog;
use codec::Writer;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::common::SpdmCodec;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{config, protocol, responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_start_session() {
    init_watchdog();
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
        secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

        let responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

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

        let mut transcript_vca = None;
        let status = requester.init_connection(&mut transcript_vca).await.is_ok();
        assert!(status);

        let status = requester.send_receive_spdm_digest(None).await.is_ok();
        assert!(status);

        let status = requester
            .send_receive_spdm_certificate(None, 0)
            .await
            .is_ok();
        assert!(status);

        #[cfg(feature = "mut-auth")]
        {
            requester.common.negotiate_info.req_asym_sel =
                SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        }

        let result = requester
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            )
            .await;
        assert!(result.is_ok());

        let result = requester
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            )
            .await;
        assert!(result.is_ok());

        let result = requester
            .start_session(
                true,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            )
            .await;
        assert!(result.is_ok());
    };
    executor::block_on(future);
}

#[test]
fn test_case0_get_next_half_session() {
    let future = async {
        init_watchdog();
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
        secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

        let responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

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

        let mut transcript_vca = None;
        let status = requester.init_connection(&mut transcript_vca).await.is_ok();
        assert!(status);

        let status = requester.send_receive_spdm_digest(None).await.is_ok();
        assert!(status);

        let status = requester
            .send_receive_spdm_certificate(None, 0)
            .await
            .is_ok();
        assert!(status);

        #[cfg(feature = "mut-auth")]
        {
            requester.common.negotiate_info.req_asym_sel =
                SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        }

        let result = requester
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            )
            .await;
        assert_eq!(result.unwrap(), 0xfffdfffd);

        let result = requester
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            )
            .await;
        assert_eq!(result.unwrap(), 0xfffcfffc);

        let result = requester
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            )
            .await;
        assert_eq!(result.unwrap(), 0xfffbfffb);

        let result = requester
            .start_session(
                true,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            )
            .await;
        assert_eq!(result.unwrap(), 0xfffafffa);

        let result = requester.end_session(0xfffbfffb).await;
        assert!(result.is_ok());

        let result = requester
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            )
            .await;
        assert_eq!(result.unwrap(), 0xfffbfffb);

        let result = requester
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            )
            .await;
        assert!(result.is_err());
    };
    executor::block_on(future);
}

#[test]
fn test_case0_receive_secured_message() {
    let future = async {
        init_watchdog();
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

        let mut responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.base_hash_sel = protocol::SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        responder.common.session = gen_array_clone(SpdmSession::new(), 4);
        responder.common.session[0].setup(session_id).unwrap();
        responder.common.session[0].set_crypto_param(
            protocol::SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            protocol::SpdmDheAlgo::SECP_384_R1,
            protocol::SpdmAeadAlgo::AES_256_GCM,
            protocol::SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        assert!(responder.common.session[0]
            .set_dhe_secret(
                SpdmVersion::SpdmVersion12,
                SpdmDheFinalKeyStruct {
                    data_size: 5,
                    data: Box::new([100u8; SPDM_MAX_DHE_KEY_SIZE])
                }
            )
            .is_ok());
        assert!(responder.common.session[0]
            .generate_handshake_secret(
                SpdmVersion::SpdmVersion12,
                &SpdmDigestStruct {
                    data_size: 5,
                    data: Box::new([100u8; SPDM_MAX_HASH_SIZE])
                }
            )
            .is_ok());
        assert!(responder.common.session[0]
            .generate_data_secret(
                SpdmVersion::SpdmVersion12,
                &SpdmDigestStruct {
                    data_size: 5,
                    data: Box::new([100u8; SPDM_MAX_HASH_SIZE])
                }
            )
            .is_ok());
        responder.common.session[0]
            .set_session_state(spdmlib::common::session::SpdmSessionState::SpdmSessionEstablished);

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

        requester.common.negotiate_info.base_hash_sel = protocol::SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        requester.common.session = gen_array_clone(SpdmSession::new(), 4);
        requester.common.session[0].setup(session_id).unwrap();
        requester.common.session[0].set_crypto_param(
            protocol::SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            protocol::SpdmDheAlgo::SECP_384_R1,
            protocol::SpdmAeadAlgo::AES_256_GCM,
            protocol::SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        assert!(requester.common.session[0]
            .set_dhe_secret(
                SpdmVersion::SpdmVersion12,
                SpdmDheFinalKeyStruct {
                    data_size: 5,
                    data: Box::new([100u8; SPDM_MAX_DHE_KEY_SIZE])
                }
            )
            .is_ok());
        assert!(requester.common.session[0]
            .generate_handshake_secret(
                SpdmVersion::SpdmVersion12,
                &SpdmDigestStruct {
                    data_size: 5,
                    data: Box::new([100u8; SPDM_MAX_HASH_SIZE])
                }
            )
            .is_ok());
        assert!(requester.common.session[0]
            .generate_data_secret(
                SpdmVersion::SpdmVersion12,
                &SpdmDigestStruct {
                    data_size: 5,
                    data: Box::new([100u8; SPDM_MAX_HASH_SIZE])
                }
            )
            .is_ok());
        requester.common.session[0]
            .set_session_state(spdmlib::common::session::SpdmSessionState::SpdmSessionEstablished);
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmRequestResponseCode::SpdmRequestEndSession,
            },
            payload: SpdmMessagePayload::SpdmEndSessionRequest(SpdmEndSessionRequestPayload {
                end_session_request_attributes: SpdmEndSessionRequestAttributes::empty(),
            }),
        };
        assert!(request
            .spdm_encode(&mut requester.common, &mut writer)
            .is_ok());
        let used = writer.used();

        let status = requester
            .send_message(Some(session_id), &send_buffer[..used], false)
            .await
            .is_ok();
        assert!(status);

        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];

        let status = requester
            .receive_message(Some(session_id), &mut receive_buffer, false)
            .await
            .is_ok();
        assert!(status);
    };
    executor::block_on(future);
}

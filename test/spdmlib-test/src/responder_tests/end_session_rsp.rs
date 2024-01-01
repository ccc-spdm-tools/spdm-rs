// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Writer};
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::common::SpdmCodec;
use spdmlib::config::MAX_SPDM_MSG_SIZE;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_handle_spdm_end_session() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        let mut context = responder::ResponderContext::new(
            socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        let session_request = &mut [0u8; 1024];
        let mut writer = Writer::init(session_request);
        let value = SpdmEndSessionRequestPayload {
            end_session_request_attributes:
                SpdmEndSessionRequestAttributes::PRESERVE_NEGOTIATED_STATE,
        };
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        context.common.session = gen_array_clone(SpdmSession::new(), 4);
        context.common.session[0].setup(session_id).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        assert!(context.common.session[0]
            .set_dhe_secret(
                SpdmVersion::SpdmVersion12,
                SpdmDheFinalKeyStruct {
                    data_size: 5,
                    data: Box::new([100u8; SPDM_MAX_DHE_KEY_SIZE])
                }
            )
            .is_ok());
        assert!(context.common.session[0]
            .generate_handshake_secret(
                SpdmVersion::SpdmVersion12,
                &SpdmDigestStruct {
                    data_size: 5,
                    data: Box::new([100u8; SPDM_MAX_HASH_SIZE])
                }
            )
            .is_ok());
        assert!(context.common.session[0]
            .generate_data_secret(
                SpdmVersion::SpdmVersion12,
                &SpdmDigestStruct {
                    data_size: 5,
                    data: Box::new([100u8; SPDM_MAX_HASH_SIZE])
                }
            )
            .is_ok());
        context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&session_request[0..1022]);
        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        let (status, send_buffer) = context.handle_spdm_end_session(session_id, bytes, &mut writer);
        assert!(status.is_ok());
    };
    executor::block_on(future);
}

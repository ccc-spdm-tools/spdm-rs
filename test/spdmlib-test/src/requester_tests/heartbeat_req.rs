// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_send_receive_spdm_heartbeat() {
    let future = async {
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

        let rsp_session_id = 0x11u16;
        let session_id = (0x11u32 << 16) + rsp_session_id as u32;
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.session = gen_array_clone(SpdmSession::new(), 4);
        responder.common.session[0].setup(session_id).unwrap();
        responder.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        assert!(responder.common.session[0]
            .set_shared_secret(
                SpdmVersion::SpdmVersion12,
                SpdmSharedSecretFinalKeyStruct {
                    data_size: 5,
                    data: Box::new([100u8; SPDM_MAX_SHARED_SECRET_SIZE])
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
        responder.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);

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

        let rsp_session_id = 0x11u16;
        let session_id = (0x11u32 << 16) + rsp_session_id as u32;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.session = gen_array_clone(SpdmSession::new(), 4);
        requester.common.session[0].setup(session_id).unwrap();
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        assert!(requester.common.session[0]
            .set_shared_secret(
                SpdmVersion::SpdmVersion12,
                SpdmSharedSecretFinalKeyStruct {
                    data_size: 5,
                    data: Box::new([100u8; SPDM_MAX_SHARED_SECRET_SIZE])
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
        requester.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);

        let status = requester
            .send_receive_spdm_heartbeat(session_id)
            .await
            .is_ok();
        assert!(status);
    };
    executor::block_on(future);
}

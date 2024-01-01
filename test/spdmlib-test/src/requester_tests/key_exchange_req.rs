// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, get_rsp_cert_chain_buff};
use spdmlib::common::SpdmOpaqueSupport;
use spdmlib::common::{session, SpdmConnectionState};
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_send_receive_spdm_key_exchange() {
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

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
        responder.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.opaque_data_support = SpdmOpaqueSupport::OPAQUE_DATA_FMT1;
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
        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
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
        requester.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.opaque_data_support = SpdmOpaqueSupport::OPAQUE_DATA_FMT1;
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        #[cfg(feature = "mut-auth")]
        {
            requester.common.negotiate_info.rsp_capabilities_sel |=
                SpdmResponseCapabilityFlags::MUT_AUTH_CAP;
            requester.common.negotiate_info.req_capabilities_sel |=
                SpdmRequestCapabilityFlags::MUT_AUTH_CAP;
        }

        requester.common.reset_runtime_info();

        requester.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());

        let measurement_summary_hash_type =
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone;
        let status = requester
            .send_receive_spdm_key_exchange(0, measurement_summary_hash_type)
            .await
            .is_ok();
        assert!(status);
    };
    executor::block_on(future);
}

#[test]
fn test_case1_send_receive_spdm_key_exchange() {
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        let mut responder = responder::ResponderContext::new(
            device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

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

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
        responder.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_256_R1; // different dhe algo will cause key negotiate fail
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.opaque_data_support = SpdmOpaqueSupport::OPAQUE_DATA_FMT1;
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
        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
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
        requester.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.opaque_data_support = SpdmOpaqueSupport::OPAQUE_DATA_FMT1;
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        #[cfg(feature = "mut-auth")]
        {
            requester.common.negotiate_info.rsp_capabilities_sel |=
                SpdmResponseCapabilityFlags::MUT_AUTH_CAP;
            requester.common.negotiate_info.req_capabilities_sel |=
                SpdmRequestCapabilityFlags::MUT_AUTH_CAP;
        }

        requester.common.reset_runtime_info();

        requester.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());

        let measurement_summary_hash_type =
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone;
        let status = requester
            .send_receive_spdm_key_exchange(0, measurement_summary_hash_type)
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

// Copyright (c) 2020, 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::Writer;
use spdmlib::common::{SpdmCodec, SpdmConnectionState};
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_case0_send_receive_spdm_capability() {
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
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionAfterVersion);

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

        requester.common.reset_runtime_info();
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion10;

        let status = requester.send_receive_spdm_capability().await.is_ok();
        assert!(status);
    };
    executor::block_on(future);
}

// DSP0274 1.3 SUPPORTED_ALGOS_EXT_CAP end-to-end: with both peers on SPDM 1.3 and CHUNK_CAP,
// the Requester sets the GET_CAPABILITIES Param1 bit, the Responder appends its
// SupportedAlgorithms block to CAPABILITIES, and the Requester consumes it via
// get_peer_supported_algorithms(). The reported algorithms must match the Responder config.
#[test]
fn test_case1_send_receive_spdm_capability_supported_algorithms() {
    let future = async {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (mut req_config_info, req_provision_info) = create_info();
        // Requester opts in to querying the Responder's SupportedAlgorithms.
        req_config_info.supported_algos_ext_cap = true;

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
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionAfterVersion);
        // The Responder emits the block only once a >=1.3 version is selected.
        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;

        let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        // Keep a handle to the Responder so its transcript (message_a) can be compared with
        // the Requester's after the exchange.
        let responder = Arc::new(Mutex::new(responder));
        let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
            Arc::new(shared_buffer),
            responder.clone(),
        )));

        let mut requester = RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.reset_runtime_info();
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;

        // Before the exchange, nothing is available to consume.
        assert!(requester.get_peer_supported_algorithms().is_none());

        // Drive the full VERSION/CAPABILITIES/ALGORITHMS sequence in one shot (no stop or
        // restart): GET_CAPABILITIES requests the block, then NEGOTIATE_ALGORITHMS follows on
        // the same transcript. Both messages are accumulated into message_a (the VCA transcript
        // that later CHALLENGE_AUTH / KEY_EXCHANGE signatures are computed over).
        assert!(requester.send_receive_spdm_capability().await.is_ok());
        assert!(requester.send_receive_spdm_algorithm().await.is_ok());

        // The Responder's SupportedAlgorithms block was consumed and reflects create_info().
        let block = requester
            .get_peer_supported_algorithms()
            .expect("Responder must return SupportedAlgorithms when requested with CHUNK_CAP");
        assert_eq!(
            block.measurement_specification,
            SpdmMeasurementSpecification::DMTF
        );
        assert_eq!(
            block.base_asym_algo,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        );
        assert_eq!(block.base_hash_algo, SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        // create_info() configures DHE, AEAD, ReqAsym and KeySchedule (4 alg struct tables).
        assert_eq!(block.alg_struct_count, 4);
        assert_eq!(block.alg_struct[0].alg_type, SpdmAlgType::SpdmAlgTypeDHE);
        assert_eq!(
            block.alg_struct[0].alg_supported,
            SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_384_R1)
        );
        assert_eq!(block.alg_struct[1].alg_type, SpdmAlgType::SpdmAlgTypeAEAD);
        assert_eq!(
            block.alg_struct[1].alg_supported,
            SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::AES_256_GCM)
        );
        assert_eq!(
            block.alg_struct[2].alg_type,
            SpdmAlgType::SpdmAlgTypeReqAsym
        );
        assert_eq!(
            block.alg_struct[3].alg_type,
            SpdmAlgType::SpdmAlgTypeKeySchedule
        );

        // End-to-end transcript check: the Requester and Responder must have built an identical
        // VCA transcript (message_a). The block-bearing CAPABILITIES response is part of it, so
        // if the SupportedAlgorithms bytes were not accounted for identically on both sides,
        // these buffers would differ and every later transcript-hash-based signature would fail.
        let req_message_a = requester.common.runtime_info.message_a.as_ref().to_vec();
        let rsp_message_a = responder
            .lock()
            .common
            .runtime_info
            .message_a
            .as_ref()
            .to_vec();
        assert_eq!(
            req_message_a, rsp_message_a,
            "requester/responder VCA transcripts diverged"
        );

        // The transcript must actually contain the encoded SupportedAlgorithms block. Re-encode
        // it as the Responder does and confirm the bytes appear in message_a. Clone the block
        // first so the immutable borrow of `requester` is released before spdm_encode.
        let block = block.clone();
        let mut block_buf = [0u8; 128];
        let mut block_writer = Writer::init(&mut block_buf);
        let block_len = block
            .spdm_encode(&mut requester.common, &mut block_writer)
            .expect("failed to re-encode SupportedAlgorithms block");
        let needle = &block_buf[..block_len];
        assert!(
            req_message_a.windows(needle.len()).any(|w| w == needle),
            "SupportedAlgorithms block not found in the VCA transcript"
        );
    };
    executor::block_on(future);
}

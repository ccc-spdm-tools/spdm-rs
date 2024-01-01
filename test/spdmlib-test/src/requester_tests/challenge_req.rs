// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::crypto_callback::FAKE_RAND;
use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, get_rsp_cert_chain_buff};
use spdmlib::common::SpdmConnectionState;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{config, crypto, responder, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
#[cfg(feature = "hashed-transcript-data")]
fn test_case0_send_receive_spdm_challenge() {
    let (rsp_config_info, rsp_provision_info) = create_info();
    let (req_config_info, req_provision_info) = create_info();

    let shared_buffer = SharedBuffer::new();
    let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));

    let pcidoe_transport_encap = PciDoeTransportEncap {};
    let pcidoe_transport_encap = Arc::new(Mutex::new(pcidoe_transport_encap));

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    crypto::rand::register(FAKE_RAND.clone());

    let mut responder = responder::ResponderContext::new(
        device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );

    responder.common.reset_runtime_info();
    responder.common.provision_info.my_cert_chain = [
        Some(SpdmCertChainBuffer {
            data_size: 512u16,
            data: [0u8; 4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        }),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ];
    responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;

    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    responder.common.runtime_info.need_measurement_summary_hash = true;

    responder
        .common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

    let pcidoe_transport_encap2 = PciDoeTransportEncap {};
    let pcidoe_transport_encap2 = Arc::new(Mutex::new(pcidoe_transport_encap2));
    let responder = Arc::new(Mutex::new(responder));
    let shared_buffer = SharedBuffer::new();
    let device_io_requester = Arc::new(Mutex::new(FakeSpdmDeviceIo::new(
        Arc::new(shared_buffer),
        responder,
    )));

    let mut requester = RequesterContext::new(
        device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );
    requester.common.reset_runtime_info();

    requester
        .common
        .negotiate_info
        .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

    requester.common.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
    requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    requester.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    requester.common.runtime_info.need_measurement_summary_hash = true;

    requester.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());
    requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;

    let task = async move {
        let status = requester
            .send_receive_spdm_challenge(
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await;
        log::info!("{:?}", status);
    };
    executor::block_on(task);
}

// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use fuzzlib::{
    spdmlib::common::session::{SpdmSession, SpdmSessionState},
    spdmlib::message::SpdmMeasurementOperation,
    *,
};
use spdmlib::common::SpdmConnectionState;
use spdmlib::message::*;
use spdmlib::protocol::*;

use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::borrow::BorrowMut;
use core::ops::DerefMut;

async fn fuzz_send_receive_spdm_measurement(fuzzdata: Arc<Vec<u8>>) {
    spdmlib::crypto::asym_verify::register(FAKE_ASYM_VERIFY.clone());
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle measurement response'
    // - description: '<p>Request with SIGNATURE_REQUESTED attribute and SpdmMeasurementRequestAll operation.</p>'
    // -
    {
        let (req_config_info, req_provision_info) = req_create_info();
        let shared_buffer = SharedBuffer::new();

        let pcidoe_transport_encap: Arc<Mutex<(dyn SpdmTransportEncap + Send + Sync + 'static)>> =
            Arc::new(Mutex::new(PciDoeTransportEncap {}));

        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(Arc::new(shared_buffer));
        device_io_requester.set_rx(&fuzzdata);
        let device_io_requester: Arc<Mutex<(dyn SpdmDeviceIo + Send + Sync + 'static)>> =
            Arc::new(Mutex::new(device_io_requester));

        let mut requester = requester::RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;
        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());

        requester.common.reset_runtime_info();

        let mut total_number = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let mut content_changed = None;
        let mut transcript_meas = None;

        let _ = requester
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                SpdmMeasurementOperation::SpdmMeasurementRequestAll,
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await;
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle measurement response'
    // - description: '<p>No peer cert chain set, but request with SIGNATURE_REQUESTED.</p><p>When requester receive measurements, it will verify signature and return error.</p>'
    // -
    {
        let (req_config_info, req_provision_info) = req_create_info();
        let shared_buffer = SharedBuffer::new();

        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(Arc::new(shared_buffer));
        device_io_requester.set_rx(&fuzzdata);
        let device_io_requester = Arc::new(Mutex::new(device_io_requester));

        let mut requester = requester::RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;
        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.reset_runtime_info();

        let mut total_number = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let mut content_changed = None;
        let mut transcript_meas = None;

        let _ = requester
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await;
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle measurement response'
    // - description: '<p>Request raw bit stream measurement and signature verification is not required.</p>'
    // -
    {
        let (req_config_info, req_provision_info) = req_create_info();

        let shared_buffer = SharedBuffer::new();

        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(Arc::new(shared_buffer));
        device_io_requester.set_rx(&fuzzdata);
        let device_io_requester = Arc::new(Mutex::new(device_io_requester));

        let mut requester = requester::RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;
        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.reset_runtime_info();

        let mut total_number = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let mut content_changed = None;
        let mut transcript_meas = None;

        let _ = requester
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementAttributes::RAW_BIT_STREAM_REQUESTED,
                SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await;
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle measurement response'
    // - description: '<p>Request with empty attribute and unknown operation value.</p>'
    // -
    {
        let (req_config_info, req_provision_info) = req_create_info();

        let shared_buffer = SharedBuffer::new();

        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(Arc::new(shared_buffer));
        device_io_requester.set_rx(&fuzzdata);
        let device_io_requester = Arc::new(Mutex::new(device_io_requester));

        let mut requester = requester::RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;
        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.reset_runtime_info();

        let mut total_number = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let mut content_changed = None;
        let mut transcript_meas = None;

        let _ = requester
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementAttributes::empty(),
                SpdmMeasurementOperation::Unknown(4),
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await;
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle measurement response'
    // - description: '<p>Request measurement in a session.</p>'
    // -
    spdmlib::crypto::aead::register(FAKE_AEAD.clone());
    {
        let (req_config_info, req_provision_info) = req_create_info();

        let shared_buffer = SharedBuffer::new();

        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(Arc::new(shared_buffer));
        device_io_requester.set_rx(&fuzzdata);
        let device_io_requester = Arc::new(Mutex::new(device_io_requester));

        let mut requester = requester::RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;
        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;

        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        requester.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;

        requester.common.session[0] = SpdmSession::new();
        requester.common.session[0].setup(4294836221).unwrap();
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);

        #[cfg(feature = "hashed-transcript-data")]
        {
            let mut dhe_secret = SpdmDheFinalKeyStruct::default();
            dhe_secret.data_size = SpdmDheAlgo::SECP_384_R1.get_size();
            requester.common.session[0]
                .set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret)
                .unwrap();
            requester.common.session[0].runtime_info.digest_context_th =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }

        requester.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());

        requester.common.reset_runtime_info();
        let mut total_number = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let mut content_changed = None;
        let mut transcript_meas = None;

        let _ = requester
            .send_receive_spdm_measurement(
                Some(4294836221),
                0,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                SpdmMeasurementOperation::SpdmMeasurementRequestAll,
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await;
    }
}

#[cfg(not(feature = "use_libfuzzer"))]
fn main() {
    #[cfg(all(feature = "fuzzlogfile", feature = "fuzz"))]
    flexi_logger::Logger::try_with_str("info")
        .unwrap()
        .log_to_file(
            FileSpec::default()
                .directory("traces")
                .basename("foo")
                .discriminant("Sample4711A")
                .suffix("trc"),
        )
        .print_message()
        .create_symlink("current_run")
        .start()
        .unwrap();

    spdmlib::secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
    spdmlib::secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());
    #[cfg(not(feature = "fuzz"))]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            // Here you can replace the single-step debugging value in the fuzzdata array.
            let fuzzdata = vec![
                01, 00, 01, 00, 0x0c, 00, 00, 00, 11, 0xe0, 01, 04, 0x0a, 0xfc, 04, 0xa0, 63, 0x5c,
                0x2e, 0x6c, 0x4b, 0x62, 0xd6, 0xc0, 0x1c, 0xf5, 0xc5, 0xa1, 0xb0, 0x9f, 0xff, 0x5a,
                0x1a, 68, 0xab, 78, 0xb1, 0xea, 25, 0xa8, 94, 0x6b, 0xac, 0xf4, 00, 00, 00, 00,
            ];
            executor::block_on(fuzz_send_receive_spdm_measurement(Arc::new(fuzzdata)));
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            executor::block_on(fuzz_send_receive_spdm_measurement(Arc::new(data)));
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        executor::block_on(fuzz_send_receive_spdm_measurement(Arc::new(data.to_vec())));
    });
}

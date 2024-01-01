// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![allow(unused)]

use super::device_io::TestSpdmDeviceIo;
use super::USE_ECDSA;
use crate::common::device_io::{MySpdmDeviceIo, TestTransportEncap};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use codec::{Codec, Reader, Writer};
use spdmlib::common::{
    SecuredMessageVersion, SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmDeviceIo, SpdmOpaqueSupport,
    SpdmProvisionInfo, SpdmTransportEncap, DMTF_SECURE_SPDM_VERSION_10,
    DMTF_SECURE_SPDM_VERSION_11, MAX_SECURE_SPDM_VERSION_COUNT, ST1,
};
use spdmlib::config::{MAX_ROOT_CERT_SUPPORT, MAX_SPDM_MSG_SIZE};
use spdmlib::crypto;
use spdmlib::message::SpdmMessage;
use spdmlib::protocol::*;
use spdmlib::{config, responder};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::ops::DerefMut;

pub fn create_info() -> (SpdmConfigInfo, SpdmProvisionInfo) {
    let config_info = SpdmConfigInfo {
        spdm_version: [
            Some(SpdmVersion::SpdmVersion10),
            Some(SpdmVersion::SpdmVersion11),
            Some(SpdmVersion::SpdmVersion12),
        ],
        rsp_capabilities: SpdmResponseCapabilityFlags::CERT_CAP
            | SpdmResponseCapabilityFlags::CHAL_CAP
            | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
            | SpdmResponseCapabilityFlags::MEAS_FRESH_CAP
            | SpdmResponseCapabilityFlags::ENCRYPT_CAP
            | SpdmResponseCapabilityFlags::MAC_CAP
            | SpdmResponseCapabilityFlags::KEY_EX_CAP
            | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT
            | SpdmResponseCapabilityFlags::ENCAP_CAP
            | SpdmResponseCapabilityFlags::HBEAT_CAP
            | SpdmResponseCapabilityFlags::KEY_UPD_CAP
            | SpdmResponseCapabilityFlags::MUT_AUTH_CAP
            | SpdmResponseCapabilityFlags::ENCAP_CAP,
        req_capabilities: SpdmRequestCapabilityFlags::CERT_CAP
            | SpdmRequestCapabilityFlags::ENCRYPT_CAP
            | SpdmRequestCapabilityFlags::MAC_CAP
            | SpdmRequestCapabilityFlags::KEY_EX_CAP
            | SpdmRequestCapabilityFlags::ENCAP_CAP
            | SpdmRequestCapabilityFlags::HBEAT_CAP
            | SpdmRequestCapabilityFlags::KEY_UPD_CAP
            | SpdmRequestCapabilityFlags::MUT_AUTH_CAP
            | SpdmRequestCapabilityFlags::ENCAP_CAP,
        rsp_ct_exponent: 0,
        req_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA_384,
        base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        dhe_algo: SpdmDheAlgo::SECP_384_R1,

        aead_algo: SpdmAeadAlgo::AES_256_GCM,
        req_asym_algo: SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048,
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        opaque_support: SpdmOpaqueSupport::OPAQUE_DATA_FMT1,
        data_transfer_size: 0x1200,
        max_spdm_msg_size: 0x1200,
        secure_spdm_version: [
            Some(SecuredMessageVersion::try_from(0x10u8).unwrap()),
            Some(SecuredMessageVersion::try_from(0x11u8).unwrap()),
        ],
        ..Default::default()
    };

    let mut my_cert_chain_data = SpdmCertChainData {
        ..Default::default()
    };
    let mut peer_root_cert_data = SpdmCertChainData {
        ..Default::default()
    };

    let crate_dir = get_test_key_directory();
    let ca_file_path = crate_dir.join("test_key/ecp384/ca.cert.der");
    let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
    let inter_file_path = crate_dir.join("test_key/ecp384/inter.cert.der");
    let inter_cert = std::fs::read(inter_file_path).expect("unable to read inter cert!");
    let leaf_file_path = crate_dir.join("test_key/ecp384/end_responder.cert.der");
    let leaf_cert = std::fs::read(leaf_file_path).expect("unable to read leaf cert!");

    let ca_len = ca_cert.len();
    let inter_len = inter_cert.len();
    let leaf_len = leaf_cert.len();

    my_cert_chain_data.data_size = (ca_len + inter_len + leaf_len) as u16;
    my_cert_chain_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());
    my_cert_chain_data.data[ca_len..(ca_len + inter_len)].copy_from_slice(inter_cert.as_ref());
    my_cert_chain_data.data[(ca_len + inter_len)..(ca_len + inter_len + leaf_len)]
        .copy_from_slice(leaf_cert.as_ref());

    peer_root_cert_data.data_size = (ca_len) as u16;
    peer_root_cert_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());

    let mut peer_root_cert_data_list = gen_array_clone(None, MAX_ROOT_CERT_SUPPORT);
    peer_root_cert_data_list[0] = Some(peer_root_cert_data);

    let provision_info = SpdmProvisionInfo {
        my_cert_chain_data: [
            Some(my_cert_chain_data.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ],
        my_cert_chain: [None, None, None, None, None, None, None, None],
        peer_root_cert_data: peer_root_cert_data_list,
    };

    (config_info, provision_info)
}

pub fn new_context(
    my_spdm_device_io: Arc<Mutex<dyn SpdmDeviceIo + Send + Sync>>,
    pcidoe_transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
) -> SpdmContext {
    let (config_info, provision_info) = create_info();
    let mut context = SpdmContext::new(
        my_spdm_device_io,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );
    context.negotiate_info.opaque_data_support = SpdmOpaqueSupport::OPAQUE_DATA_FMT1;
    context
}

pub fn new_spdm_message(value: SpdmMessage, mut context: SpdmContext) -> SpdmMessage {
    let u8_slice = &mut [0u8; 1000];
    let mut writer = Writer::init(u8_slice);
    value.spdm_encode(&mut context, &mut writer);
    let mut reader = Reader::init(u8_slice);
    let spdm_message: SpdmMessage = SpdmMessage::spdm_read(&mut context, &mut reader).unwrap();
    spdm_message
}

pub fn req_create_info() -> (SpdmConfigInfo, SpdmProvisionInfo) {
    let req_capabilities = SpdmRequestCapabilityFlags::CERT_CAP
        | SpdmRequestCapabilityFlags::CHAL_CAP
        | SpdmRequestCapabilityFlags::ENCRYPT_CAP
        | SpdmRequestCapabilityFlags::MAC_CAP
        | SpdmRequestCapabilityFlags::KEY_EX_CAP
        | SpdmRequestCapabilityFlags::PSK_CAP
        | SpdmRequestCapabilityFlags::ENCAP_CAP
        | SpdmRequestCapabilityFlags::HBEAT_CAP
        // | SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
        // | SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP
        | SpdmRequestCapabilityFlags::KEY_UPD_CAP;
    let req_capabilities = if cfg!(feature = "mut-auth") {
        req_capabilities | SpdmRequestCapabilityFlags::MUT_AUTH_CAP
    } else {
        req_capabilities
    };
    let config_info = SpdmConfigInfo {
        spdm_version: [
            Some(SpdmVersion::SpdmVersion10),
            Some(SpdmVersion::SpdmVersion11),
            Some(SpdmVersion::SpdmVersion12),
        ],
        req_capabilities: req_capabilities,
        req_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        base_asym_algo: if USE_ECDSA {
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        } else {
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
        },
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        dhe_algo: SpdmDheAlgo::SECP_384_R1,
        aead_algo: SpdmAeadAlgo::AES_256_GCM,
        req_asym_algo: if USE_ECDSA {
            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        } else {
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_3072
        },
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        opaque_support: SpdmOpaqueSupport::OPAQUE_DATA_FMT1,
        data_transfer_size: config::MAX_SPDM_MSG_SIZE as u32,
        max_spdm_msg_size: config::MAX_SPDM_MSG_SIZE as u32,
        secure_spdm_version: [
            Some(SecuredMessageVersion::try_from(0x10u8).unwrap()),
            Some(SecuredMessageVersion::try_from(0x11u8).unwrap()),
        ],
        ..Default::default()
    };

    let mut peer_root_cert_data = SpdmCertChainData {
        ..Default::default()
    };

    let crate_dir = get_test_key_directory();
    let ca_file_path = if USE_ECDSA {
        crate_dir.join("test_key/ecp384/ca.cert.der")
    } else {
        crate_dir.join("test_key/rsa3072/ca.cert.der")
    };
    let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
    let inter_file_path = if USE_ECDSA {
        crate_dir.join("test_key/ecp384/inter.cert.der")
    } else {
        crate_dir.join("test_key/rsa3072/inter.cert.der")
    };
    let inter_cert = std::fs::read(inter_file_path).expect("unable to read inter cert!");
    let leaf_file_path = if USE_ECDSA {
        crate_dir.join("test_key/ecp384/end_responder.cert.der")
    } else {
        crate_dir.join("test_key/rsa3072/end_responder.cert.der")
    };
    let leaf_cert = std::fs::read(leaf_file_path).expect("unable to read leaf cert!");

    let ca_len = ca_cert.len();
    let inter_len = inter_cert.len();
    let leaf_len = leaf_cert.len();
    log::info!(
        "total cert size - {:?} = {:?} + {:?} + {:?}",
        ca_len + inter_len + leaf_len,
        ca_len,
        inter_len,
        leaf_len
    );
    peer_root_cert_data.data_size = (ca_len) as u16;
    peer_root_cert_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());

    let mut peer_root_cert_data_list = gen_array_clone(None, MAX_ROOT_CERT_SUPPORT);
    peer_root_cert_data_list[0] = Some(peer_root_cert_data);

    let provision_info = if cfg!(feature = "mut-auth") {
        spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        let mut my_cert_chain_data = SpdmCertChainData {
            ..Default::default()
        };

        my_cert_chain_data.data_size = (ca_len + inter_len + leaf_len) as u16;
        my_cert_chain_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());
        my_cert_chain_data.data[ca_len..(ca_len + inter_len)].copy_from_slice(inter_cert.as_ref());
        my_cert_chain_data.data[(ca_len + inter_len)..(ca_len + inter_len + leaf_len)]
            .copy_from_slice(leaf_cert.as_ref());

        SpdmProvisionInfo {
            my_cert_chain_data: [
                Some(my_cert_chain_data),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ],
            my_cert_chain: [None, None, None, None, None, None, None, None],
            peer_root_cert_data: peer_root_cert_data_list,
        }
    } else {
        SpdmProvisionInfo {
            my_cert_chain_data: [None, None, None, None, None, None, None, None],
            my_cert_chain: [None, None, None, None, None, None, None, None],
            peer_root_cert_data: peer_root_cert_data_list,
        }
    };

    (config_info, provision_info)
}

pub fn rsp_create_info() -> (SpdmConfigInfo, SpdmProvisionInfo) {
    let rsp_capabilities = SpdmResponseCapabilityFlags::CERT_CAP
        | SpdmResponseCapabilityFlags::CHAL_CAP
        | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
        | SpdmResponseCapabilityFlags::MEAS_FRESH_CAP
        | SpdmResponseCapabilityFlags::ENCRYPT_CAP
        | SpdmResponseCapabilityFlags::MAC_CAP
        | SpdmResponseCapabilityFlags::KEY_EX_CAP
        | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT
        | SpdmResponseCapabilityFlags::ENCAP_CAP
        | SpdmResponseCapabilityFlags::HBEAT_CAP
        // | SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
        // | SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP
        | SpdmResponseCapabilityFlags::KEY_UPD_CAP;
    let rsp_capabilities = if cfg!(feature = "mut-auth") {
        rsp_capabilities | SpdmResponseCapabilityFlags::MUT_AUTH_CAP
    } else {
        rsp_capabilities
    };
    let config_info = SpdmConfigInfo {
        spdm_version: [
            Some(SpdmVersion::SpdmVersion10),
            Some(SpdmVersion::SpdmVersion11),
            Some(SpdmVersion::SpdmVersion12),
        ],
        rsp_capabilities: rsp_capabilities,
        rsp_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA_384,
        base_asym_algo: if USE_ECDSA {
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        } else {
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
        },
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        dhe_algo: SpdmDheAlgo::SECP_384_R1,
        aead_algo: SpdmAeadAlgo::AES_256_GCM,
        req_asym_algo: if USE_ECDSA {
            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        } else {
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_3072
        },
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        opaque_support: SpdmOpaqueSupport::OPAQUE_DATA_FMT1,
        data_transfer_size: config::MAX_SPDM_MSG_SIZE as u32,
        max_spdm_msg_size: config::MAX_SPDM_MSG_SIZE as u32,
        heartbeat_period: config::HEARTBEAT_PERIOD,
        secure_spdm_version: [
            Some(SecuredMessageVersion::try_from(0x10u8).unwrap()),
            Some(SecuredMessageVersion::try_from(0x11u8).unwrap()),
        ],
        ..Default::default()
    };

    let mut my_cert_chain_data = SpdmCertChainData {
        ..Default::default()
    };

    let crate_dir = get_test_key_directory();
    let ca_file_path = if USE_ECDSA {
        crate_dir.join("test_key/ecp384/ca.cert.der")
    } else {
        crate_dir.join("test_key/rsa3072/ca.cert.der")
    };
    log::info!("{}", ca_file_path.display());
    let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
    let inter_file_path = if USE_ECDSA {
        crate_dir.join("test_key/ecp384/inter.cert.der")
    } else {
        crate_dir.join("test_key/rsa3072/inter.cert.der")
    };
    let inter_cert = std::fs::read(inter_file_path).expect("unable to read inter cert!");
    let leaf_file_path = if USE_ECDSA {
        crate_dir.join("test_key/ecp384/end_responder.cert.der")
    } else {
        crate_dir.join("test_key/rsa3072/end_responder.cert.der")
    };
    let leaf_cert = std::fs::read(leaf_file_path).expect("unable to read leaf cert!");

    let ca_len = ca_cert.len();
    let inter_len = inter_cert.len();
    let leaf_len = leaf_cert.len();
    log::info!(
        "total cert size - {:?} = {:?} + {:?} + {:?}",
        ca_len + inter_len + leaf_len,
        ca_len,
        inter_len,
        leaf_len
    );
    my_cert_chain_data.data_size = (ca_len + inter_len + leaf_len) as u16;
    my_cert_chain_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());
    my_cert_chain_data.data[ca_len..(ca_len + inter_len)].copy_from_slice(inter_cert.as_ref());
    my_cert_chain_data.data[(ca_len + inter_len)..(ca_len + inter_len + leaf_len)]
        .copy_from_slice(leaf_cert.as_ref());

    let provision_info = SpdmProvisionInfo {
        my_cert_chain_data: [
            Some(my_cert_chain_data),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ],
        my_cert_chain: [None, None, None, None, None, None, None, None],
        peer_root_cert_data: gen_array_clone(None, MAX_ROOT_CERT_SUPPORT),
    };

    (config_info, provision_info)
}

pub fn get_test_key_directory() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = crate_dir
        .parent()
        .expect("can't find parent dir")
        .parent()
        .expect("can't find parent dir");
    crate_dir.to_path_buf()
}

pub fn get_rsp_cert_chain_buff() -> SpdmCertChainBuffer {
    let hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    let cert_chain = include_bytes!("../../../../test_key/ecp384/bundle_responder.certchain.der");

    let (root_cert_begin, root_cert_end) =
        crypto::cert_operation::get_cert_from_cert_chain(cert_chain, 0)
            .expect("Get provisioned root cert failed");

    let root_cert_hash =
        crypto::hash::hash_all(hash_algo, &cert_chain[root_cert_begin..root_cert_end])
            .expect("Must provide hash algo");
    SpdmCertChainBuffer::new(cert_chain, root_cert_hash.as_ref())
        .expect("Create format certificate chain failed.")
}

#[derive(Debug, PartialEq, Eq)]
pub struct TestSpdmMessage {
    pub message: crate::protocol::Message,
    pub secure: u8, // secure message
}

#[derive(Debug, PartialEq, Eq)]
pub struct TestCase {
    pub input: Vec<TestSpdmMessage>,
    pub expected: Vec<TestSpdmMessage>,
}

impl TestCase {
    pub fn config() -> (SpdmConfigInfo, SpdmProvisionInfo) {
        create_info()
    }

    pub fn input_to_vec(&self, cb: fn(secure: u8, bufer: &[u8]) -> VecDeque<u8>) -> VecDeque<u8> {
        let mut ret = VecDeque::new();
        for data in &self.input {
            let mut buffer = vec![0u8; MAX_SPDM_MSG_SIZE];
            let writer = &mut Writer::init(&mut buffer[..]);
            let len = data
                .message
                .encode(writer)
                .expect("Error to encode input message");
            ret.extend((cb)(data.secure, &buffer[..len]).iter())
        }
        ret
    }
    pub fn expected_to_vec(
        &self,
        cb: fn(secure: u8, bufer: &[u8]) -> VecDeque<u8>,
    ) -> VecDeque<u8> {
        let mut ret = VecDeque::new();
        for data in &self.expected {
            let mut buffer = vec![0u8; MAX_SPDM_MSG_SIZE];
            let writer = &mut Writer::init(&mut buffer[..]);
            let len = data
                .message
                .encode(writer)
                .expect("Error to encode input message");
            ret.extend((cb)(data.secure, &buffer[..len]).iter())
        }
        ret
    }

    pub fn get_certificate_chain_buffer(
        hash_algo: SpdmBaseHashAlgo,
        cert_chain: &[u8],
    ) -> SpdmCertChainBuffer {
        let (root_cert_begin, root_cert_end) =
            crypto::cert_operation::get_cert_from_cert_chain(cert_chain, 0)
                .expect("Get provisioned root cert failed");

        let root_cert_hash =
            crypto::hash::hash_all(hash_algo, &cert_chain[root_cert_begin..root_cert_end])
                .expect("Must provide hash algo");
        SpdmCertChainBuffer::new(cert_chain, root_cert_hash.as_ref())
            .expect("Create format certificate chain failed.")
    }
}

pub struct ResponderRunner;
impl ResponderRunner {
    pub fn run(case: TestCase, cb: fn(secure: u8, bufer: &[u8]) -> VecDeque<u8>) -> bool {
        use super::secret_callback::FAKE_SECRET_ASYM_IMPL_INSTANCE;
        use crate::common::crypto_callback::{FAKE_AEAD, FAKE_ASYM_VERIFY, FAKE_RAND};
        spdmlib::crypto::aead::register(FAKE_AEAD.clone());
        spdmlib::crypto::rand::register(FAKE_RAND.clone());
        spdmlib::crypto::asym_verify::register(FAKE_ASYM_VERIFY.clone());
        spdmlib::secret::asym_sign::register(FAKE_SECRET_ASYM_IMPL_INSTANCE.clone());

        let mut output = Arc::new(Mutex::new(VecDeque::<u8>::new()));
        let mut rx = Arc::new(Mutex::new(case.input_to_vec(cb)));
        let mut output_ref = Arc::clone(&output);
        log::debug!("intput  : {:02x?}", rx.lock().make_contiguous());
        let future = async {
            let mut device_io = TestSpdmDeviceIo::new(rx, output_ref);
            let mut transport_encap = TestTransportEncap;
            let (config_info, provision_info) = TestCase::config();
            let mut context = responder::ResponderContext::new(
                Arc::new(Mutex::new(device_io)),
                Arc::new(Mutex::new(transport_encap)),
                config_info,
                provision_info,
            );
            let raw_packet = &mut [0u8; spdmlib::config::RECEIVER_BUFFER_SIZE];
            loop {
                let result = context.process_message(false, 0, raw_packet).await;
                match result {
                    Err(nread) => {
                        if nread == 0 {
                            break;
                        }
                    }
                    Ok(_) => continue,
                }
            }
        };
        executor::block_on(future);
        // Check Result
        // output and case.expected
        let mut expected = case.expected_to_vec(cb);
        let mut output = output.lock();
        let output = output.make_contiguous();
        let expected = expected.make_contiguous();
        log::debug!("output  : {:02x?}\n", output);
        log::debug!("expected: {:02x?}\n", expected);
        output == expected
    }
}

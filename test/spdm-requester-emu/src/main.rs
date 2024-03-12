// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![forbid(unsafe_code)]

use codec::Codec;
use common::SpdmDeviceIo;
use common::SpdmTransportEncap;
use core::convert::TryFrom;
use idekm::pci_ide_km_requester::IdekmReqContext;
use idekm::pci_idekm::Aes256GcmKeyBuffer;
use idekm::pci_idekm::KpAckStatus;
use idekm::pci_idekm::KEY_DIRECTION_RX;
use idekm::pci_idekm::KEY_DIRECTION_TX;
use idekm::pci_idekm::KEY_SET_0;
use idekm::pci_idekm::KEY_SUB_STREAM_CPL;
use idekm::pci_idekm::KEY_SUB_STREAM_NPR;
use idekm::pci_idekm::KEY_SUB_STREAM_PR;
use idekm::pci_idekm::PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT;
use log::*;
use simple_logger::SimpleLogger;

#[cfg(not(feature = "is_sync"))]
use spdm_emu::async_runtime::block_on;
use spdm_emu::crypto_callback::SECRET_ASYM_IMPL_INSTANCE;
use spdm_emu::secret_impl_sample::SECRET_PSK_IMPL_INSTANCE;
use spdm_emu::EMU_STACK_SIZE;
use spdmlib::common;
use spdmlib::common::SecuredMessageVersion;
use spdmlib::common::SpdmOpaqueSupport;
use spdmlib::common::ST1;
use spdmlib::config;
use spdmlib::config::MAX_ROOT_CERT_SUPPORT;
use spdmlib::crypto::rand::get_random;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::requester;

use mctp_transport::MctpTransportEncap;
use pcidoe_transport::PciDoeTransportEncap;
use spdm_emu::socket_io_transport::SocketIoTransport;
use spdm_emu::spdm_emu::*;
use std::net::TcpStream;
use tdisp::pci_tdisp::FunctionId;
use tdisp::pci_tdisp::InterfaceId;
use tdisp::pci_tdisp::InterfaceInfo;
use tdisp::pci_tdisp::LockInterfaceFlag;
use tdisp::pci_tdisp::TdiState;
use tdisp::pci_tdisp::TdispMmioRange;
use tdisp::pci_tdisp::MAX_DEVICE_REPORT_BUFFER;
use tdisp::pci_tdisp::START_INTERFACE_NONCE_LEN;
use tdisp::pci_tdisp_requester::pci_tdisp_req_get_device_interface_report;
use tdisp::pci_tdisp_requester::pci_tdisp_req_get_device_interface_state;
use tdisp::pci_tdisp_requester::pci_tdisp_req_get_tdisp_capabilities;
use tdisp::pci_tdisp_requester::pci_tdisp_req_get_tdisp_version;
use tdisp::pci_tdisp_requester::pci_tdisp_req_lock_interface_request;
use tdisp::pci_tdisp_requester::pci_tdisp_req_start_interface_request;
use tdisp::pci_tdisp_requester::pci_tdisp_req_stop_interface_request;

use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;
use core::ops::DerefMut;

#[maybe_async::maybe_async]
async fn send_receive_hello(
    stream: Arc<Mutex<TcpStream>>,
    transport_encap: Arc<Mutex<dyn common::SpdmTransportEncap + Send + Sync>>,
    transport_type: u32,
) {
    println!("send test");
    let mut payload = [0u8; 1024];

    let mut transport_encap = transport_encap.lock();
    let transport_encap = transport_encap.deref_mut();
    let used = transport_encap
        .encap(
            Arc::new(b"Client Hello!\0"),
            Arc::new(Mutex::new(&mut payload[..])),
            false,
        )
        .await
        .unwrap();

    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream.clone(),
        transport_type,
        SOCKET_SPDM_COMMAND_TEST,
        &payload[0..used],
    );
    let mut buffer = [0u8; config::RECEIVER_BUFFER_SIZE];
    let (_transport_type, _command, _payload) =
        spdm_emu::spdm_emu::receive_message(stream, &mut buffer[..], ST1)
            .await
            .unwrap();
}

#[maybe_async::maybe_async]
async fn send_receive_stop(
    stream: Arc<Mutex<TcpStream>>,
    transport_encap: Arc<Mutex<dyn common::SpdmTransportEncap + Send + Sync>>,
    transport_type: u32,
) {
    println!("send stop");

    let mut payload = [0u8; 1024];

    let mut transport_encap = transport_encap.lock();
    let transport_encap = transport_encap.deref_mut();

    let used = transport_encap
        .encap(Arc::new(b""), Arc::new(Mutex::new(&mut payload[..])), false)
        .await
        .unwrap();

    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream.clone(),
        transport_type,
        SOCKET_SPDM_COMMAND_STOP,
        &payload[0..used],
    );
    let mut buffer = [0u8; config::RECEIVER_BUFFER_SIZE];
    let (_transport_type, _command, _payload) =
        spdm_emu::spdm_emu::receive_message(stream, &mut buffer[..], ST1)
            .await
            .unwrap();
}

#[maybe_async::maybe_async]
async fn test_spdm(
    socket_io_transport: Arc<Mutex<dyn SpdmDeviceIo + Send + Sync>>,
    transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
) {
    let req_capabilities = SpdmRequestCapabilityFlags::CERT_CAP
        | SpdmRequestCapabilityFlags::CHAL_CAP
        | SpdmRequestCapabilityFlags::ENCRYPT_CAP
        | SpdmRequestCapabilityFlags::MAC_CAP
        | SpdmRequestCapabilityFlags::KEY_EX_CAP
        | SpdmRequestCapabilityFlags::PSK_CAP
        | SpdmRequestCapabilityFlags::ENCAP_CAP
        | SpdmRequestCapabilityFlags::HBEAT_CAP
        | SpdmRequestCapabilityFlags::KEY_UPD_CAP;
    // | SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
    // | SpdmRequestCapabilityFlags::PUB_KEY_ID_CAP
    let req_capabilities = if cfg!(feature = "mut-auth") {
        req_capabilities | SpdmRequestCapabilityFlags::MUT_AUTH_CAP
    } else {
        req_capabilities
    };

    let config_info = common::SpdmConfigInfo {
        spdm_version: [
            Some(SpdmVersion::SpdmVersion10),
            Some(SpdmVersion::SpdmVersion11),
            Some(SpdmVersion::SpdmVersion12),
        ],
        req_capabilities,
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

    let ca_file_path = if USE_ECDSA {
        "test_key/ecp384/ca.cert.der"
    } else {
        "test_key/rsa3072/ca.cert.der"
    };
    let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
    let inter_file_path = if USE_ECDSA {
        "test_key/ecp384/inter.cert.der"
    } else {
        "test_key/rsa3072/inter.cert.der"
    };
    let inter_cert = std::fs::read(inter_file_path).expect("unable to read inter cert!");
    let leaf_file_path = if USE_ECDSA {
        "test_key/ecp384/end_responder.cert.der"
    } else {
        "test_key/rsa3072/end_responder.cert.der"
    };
    let leaf_cert = std::fs::read(leaf_file_path).expect("unable to read leaf cert!");

    let ca_len = ca_cert.len();
    let inter_len = inter_cert.len();
    let leaf_len = leaf_cert.len();
    println!(
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

        common::SpdmProvisionInfo {
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
        common::SpdmProvisionInfo {
            my_cert_chain_data: [None, None, None, None, None, None, None, None],
            my_cert_chain: [None, None, None, None, None, None, None, None],
            peer_root_cert_data: peer_root_cert_data_list,
        }
    };

    let mut context = requester::RequesterContext::new(
        socket_io_transport,
        transport_encap,
        config_info,
        provision_info,
    );

    let mut transcript_vca = None;
    if context.init_connection(&mut transcript_vca).await.is_err() {
        panic!("init_connection failed!");
    }

    if context.send_receive_spdm_digest(None).await.is_err() {
        panic!("send_receive_spdm_digest failed!");
    }

    if context
        .send_receive_spdm_certificate(None, 0)
        .await
        .is_err()
    {
        panic!("send_receive_spdm_certificate failed!");
    }

    if context
        .send_receive_spdm_challenge(
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        )
        .await
        .is_err()
    {
        panic!("send_receive_spdm_challenge failed!");
    }

    let mut total_number: u8 = 0;
    let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
    let mut content_changed = None;
    let mut transcript_meas = None;

    if context
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
        .await
        .is_err()
    {
        panic!("send_receive_spdm_measurement failed!");
    }

    if transcript_meas.is_none() {
        panic!("get message_m from send_receive_spdm_measurement failed!");
    }

    let result = context
        .start_session(
            false,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        )
        .await;
    if let Ok(session_id) = result {
        info!("\nSession established ... session_id {:0x?}\n", session_id);
        info!("Key Information ...\n");

        let session = context.common.get_session_via_id(session_id).unwrap();
        let (request_direction, response_direction) = session.export_keys();
        info!(
            "equest_direction.encryption_key {:0x?}\n",
            request_direction.encryption_key.as_ref()
        );
        info!(
            "equest_direction.salt {:0x?}\n",
            request_direction.salt.as_ref()
        );
        info!(
            "esponse_direction.encryption_key {:0x?}\n",
            response_direction.encryption_key.as_ref()
        );
        info!(
            "esponse_direction.salt {:0x?}\n",
            response_direction.salt.as_ref()
        );

        if context
            .send_receive_spdm_heartbeat(session_id)
            .await
            .is_err()
        {
            panic!("send_receive_spdm_heartbeat failed");
        }

        if context
            .send_receive_spdm_key_update(session_id, SpdmKeyUpdateOperation::SpdmUpdateAllKeys)
            .await
            .is_err()
        {
            panic!("send_receive_spdm_key_update failed");
        }

        let mut content_changed = None;
        let mut transcript_meas = None;

        if context
            .send_receive_spdm_measurement(
                Some(session_id),
                0,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await
            .is_err()
        {
            panic!("send_receive_spdm_measurement failed");
        }

        if transcript_vca.is_none() || transcript_meas.is_none() {
            panic!("get VCA + message_m from send_receive_spdm_measurement failed!");
        }

        if context
            .send_receive_spdm_digest(Some(session_id))
            .await
            .is_err()
        {
            panic!("send_receive_spdm_digest failed");
        }

        if context
            .send_receive_spdm_certificate(Some(session_id), 0)
            .await
            .is_err()
        {
            panic!("send_receive_spdm_certificate failed");
        }

        if context.end_session(session_id).await.is_err() {
            panic!("end_session failed");
        }
    } else {
        panic!("\nSession session_id not got\n");
    }

    let result = context
        .start_session(
            true,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        )
        .await;
    if let Ok(session_id) = result {
        if context.end_session(session_id).await.is_err() {
            panic!("\nSession session_id is err\n");
        }
    } else {
        panic!("\nSession session_id not got\n");
    }

    #[cfg(feature = "test_stack_size")]
    {
        let value = td_benchmark::StackProfiling::stack_usage().unwrap();
        println!("max stack usage(no idekm): {}", value);
    }
}

#[maybe_async::maybe_async]
async fn test_idekm_tdisp(
    socket_io_transport: Arc<Mutex<dyn SpdmDeviceIo + Send + Sync>>,
    transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    key_iv: Arc<Mutex<Aes256GcmKeyBuffer>>,
) {
    let req_capabilities = SpdmRequestCapabilityFlags::CERT_CAP
        | SpdmRequestCapabilityFlags::CHAL_CAP
        | SpdmRequestCapabilityFlags::ENCRYPT_CAP
        | SpdmRequestCapabilityFlags::MAC_CAP
        | SpdmRequestCapabilityFlags::KEY_EX_CAP
        | SpdmRequestCapabilityFlags::PSK_CAP
        | SpdmRequestCapabilityFlags::ENCAP_CAP
        | SpdmRequestCapabilityFlags::HBEAT_CAP
        | SpdmRequestCapabilityFlags::KEY_UPD_CAP;
    // | SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
    // | SpdmRequestCapabilityFlags::PUB_KEY_ID_CAP
    let req_capabilities = if cfg!(feature = "mut-auth") {
        req_capabilities | SpdmRequestCapabilityFlags::MUT_AUTH_CAP
    } else {
        req_capabilities
    };

    let config_info = common::SpdmConfigInfo {
        spdm_version: [
            Some(SpdmVersion::SpdmVersion10),
            Some(SpdmVersion::SpdmVersion11),
            Some(SpdmVersion::SpdmVersion12),
        ],
        req_capabilities,
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

    let ca_file_path = if USE_ECDSA {
        "test_key/ecp384/ca.cert.der"
    } else {
        "test_key/rsa3072/ca.cert.der"
    };
    let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
    let inter_file_path = if USE_ECDSA {
        "test_key/ecp384/inter.cert.der"
    } else {
        "test_key/rsa3072/inter.cert.der"
    };
    let inter_cert = std::fs::read(inter_file_path).expect("unable to read inter cert!");
    let leaf_file_path = if USE_ECDSA {
        "test_key/ecp384/end_responder.cert.der"
    } else {
        "test_key/rsa3072/end_responder.cert.der"
    };
    let leaf_cert = std::fs::read(leaf_file_path).expect("unable to read leaf cert!");

    let ca_len = ca_cert.len();
    let inter_len = inter_cert.len();
    let leaf_len = leaf_cert.len();
    println!(
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

        common::SpdmProvisionInfo {
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
        common::SpdmProvisionInfo {
            my_cert_chain_data: [None, None, None, None, None, None, None, None],
            my_cert_chain: [None, None, None, None, None, None, None, None],
            peer_root_cert_data: peer_root_cert_data_list,
        }
    };

    let mut context = requester::RequesterContext::new(
        socket_io_transport,
        transport_encap,
        config_info,
        provision_info,
    );

    let mut transcript_vca = None;
    if context.init_connection(&mut transcript_vca).await.is_err() {
        panic!("init_connection failed!");
    }

    if context.send_receive_spdm_digest(None).await.is_err() {
        panic!("send_receive_spdm_digest failed!");
    }

    if context
        .send_receive_spdm_certificate(None, 0)
        .await
        .is_err()
    {
        panic!("send_receive_spdm_certificate failed!");
    }

    if context
        .send_receive_spdm_challenge(
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        )
        .await
        .is_err()
    {
        panic!("send_receive_spdm_challenge failed!");
    }

    let mut total_number: u8 = 0;
    let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
    let mut content_changed = None;
    let mut transcript_meas = None;

    if context
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
        .await
        .is_err()
    {
        panic!("send_receive_spdm_measurement failed!");
    }

    let session_id = context
        .start_session(
            false,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        )
        .await
        .unwrap();

    // ide_km test
    let mut idekm_req_context = IdekmReqContext;
    // ide_km query
    let port_index = 0u8;
    let mut dev_func_num = 0u8;
    let mut bus_num = 0u8;
    let mut segment = 0u8;
    let mut max_port_index = 0u8;
    let mut ide_reg_block = [0u32; PCI_IDE_KM_IDE_REG_BLOCK_MAX_COUNT];
    let mut ide_reg_block_cnt = 0usize;
    idekm_req_context
        .pci_ide_km_query(
            &mut context,
            session_id,
            port_index,
            &mut dev_func_num,
            &mut bus_num,
            &mut segment,
            &mut max_port_index,
            &mut ide_reg_block,
            &mut ide_reg_block_cnt,
        )
        .await
        .unwrap();

    // ide_km key_prog key set 0 | RX | PR
    let stream_id = 0u8;
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_RX;
    let key_sub_stream = KEY_SUB_STREAM_PR;

    let mut key_iv = key_iv.lock();

    get_random(&mut key_iv.key[0].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[1].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[2].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[3].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[4].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[5].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[6].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[7].to_le_bytes()).unwrap();
    key_iv.iv[0] = 0;
    key_iv.iv[1] = 1;
    let mut kp_ack_status = KpAckStatus::default();
    idekm_req_context
        .pci_ide_km_key_prog(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
            &key_iv,
            &mut kp_ack_status,
        )
        .await
        .unwrap();
    if kp_ack_status != KpAckStatus::SUCCESS {
        panic!(
            "KEY_PROG at Key Set 0 | RX | PR failed with {:X?}",
            kp_ack_status
        );
    } else {
        println!("Successful KEY_PROG at Key Set 0 | RX | PR!");
    }

    // ide_km key_prog key set 0 | RX | NPR
    let stream_id = 0u8;
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_RX;
    let key_sub_stream = KEY_SUB_STREAM_NPR;

    get_random(&mut key_iv.key[0].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[1].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[2].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[3].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[4].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[5].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[6].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[7].to_le_bytes()).unwrap();
    key_iv.iv[0] = 0;
    key_iv.iv[1] = 1;
    let mut kp_ack_status = KpAckStatus::default();
    idekm_req_context
        .pci_ide_km_key_prog(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
            &key_iv,
            &mut kp_ack_status,
        )
        .await
        .unwrap();
    if kp_ack_status != KpAckStatus::SUCCESS {
        panic!(
            "KEY_PROG at Key Set 0 | RX | NPR failed with {:X?}",
            kp_ack_status
        );
    } else {
        println!("Successful KEY_PROG at Key Set 0 | RX | NPR!");
    }

    // ide_km key_prog key set 0 | RX | CPL
    let stream_id = 0u8;
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_RX;
    let key_sub_stream = KEY_SUB_STREAM_CPL;

    get_random(&mut key_iv.key[0].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[1].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[2].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[3].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[4].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[5].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[6].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[7].to_le_bytes()).unwrap();
    key_iv.iv[0] = 0;
    key_iv.iv[1] = 1;
    let mut kp_ack_status = KpAckStatus::default();
    idekm_req_context
        .pci_ide_km_key_prog(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
            &key_iv,
            &mut kp_ack_status,
        )
        .await
        .unwrap();
    if kp_ack_status != KpAckStatus::SUCCESS {
        panic!(
            "KEY_PROG at Key Set 0 | RX | CPL failed with {:X?}",
            kp_ack_status
        );
    } else {
        println!("Successful KEY_PROG at Key Set 0 | RX | CPL!");
    }

    // ide_km key_prog key set 0 | TX | PR
    let stream_id = 0u8;
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_TX;
    let key_sub_stream = KEY_SUB_STREAM_PR;

    get_random(&mut key_iv.key[0].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[1].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[2].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[3].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[4].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[5].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[6].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[7].to_le_bytes()).unwrap();
    key_iv.iv[0] = 0;
    key_iv.iv[1] = 1;
    let mut kp_ack_status = KpAckStatus::default();
    idekm_req_context
        .pci_ide_km_key_prog(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
            &key_iv,
            &mut kp_ack_status,
        )
        .await
        .unwrap();
    if kp_ack_status != KpAckStatus::SUCCESS {
        panic!(
            "KEY_PROG at Key Set 0 | TX | PR failed with {:X?}",
            kp_ack_status
        );
    } else {
        println!("Successful KEY_PROG at Key Set 0 | TX | PR!");
    }

    // ide_km key_prog key set 0 | TX | NPR
    let stream_id = 0u8;
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_TX;
    let key_sub_stream = KEY_SUB_STREAM_NPR;

    get_random(&mut key_iv.key[0].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[1].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[2].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[3].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[4].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[5].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[6].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[7].to_le_bytes()).unwrap();
    key_iv.iv[0] = 0;
    key_iv.iv[1] = 1;
    let mut kp_ack_status = KpAckStatus::default();
    idekm_req_context
        .pci_ide_km_key_prog(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
            &key_iv,
            &mut kp_ack_status,
        )
        .await
        .unwrap();
    if kp_ack_status != KpAckStatus::SUCCESS {
        panic!(
            "KEY_PROG at Key Set 0 | TX | NPR failed with {:X?}",
            kp_ack_status
        );
    } else {
        println!("Successful KEY_PROG at Key Set 0 | TX | NPR!");
    }

    // ide_km key_prog key set 0 | TX | CPL
    let stream_id = 0u8;
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_TX;
    let key_sub_stream = KEY_SUB_STREAM_CPL;

    get_random(&mut key_iv.key[0].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[1].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[2].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[3].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[4].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[5].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[6].to_le_bytes()).unwrap();
    get_random(&mut key_iv.key[7].to_le_bytes()).unwrap();
    key_iv.iv[0] = 0;
    key_iv.iv[1] = 1;
    let mut kp_ack_status = KpAckStatus::default();
    idekm_req_context
        .pci_ide_km_key_prog(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
            &key_iv,
            &mut kp_ack_status,
        )
        .await
        .unwrap();
    if kp_ack_status != KpAckStatus::SUCCESS {
        panic!(
            "KEY_PROG at Key Set 0 | TX | CPL failed with {:X?}",
            kp_ack_status
        );
    } else {
        println!("Successful KEY_PROG at Key Set 0 | TX | CPL!");
    }

    // ide_km key_set_go key set 0 | RX | PR
    let stream_id = 0u8;
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_RX;
    let key_sub_stream = KEY_SUB_STREAM_PR;
    let port_index = 0u8;
    idekm_req_context
        .pci_ide_km_key_set_go(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        )
        .await
        .unwrap();
    println!("Successful KEY_SET_GO at Key Set 0 | RX | PR!");

    // ide_km key_set_go key set 0 | RX | NPR
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_RX;
    let key_sub_stream = KEY_SUB_STREAM_NPR;
    idekm_req_context
        .pci_ide_km_key_set_go(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        )
        .await
        .unwrap();
    println!("Successful KEY_SET_GO at Key Set 0 | RX | NPR!");

    // ide_km key_set_go key set 0 | RX | CPL
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_RX;
    let key_sub_stream = KEY_SUB_STREAM_CPL;
    idekm_req_context
        .pci_ide_km_key_set_go(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        )
        .await
        .unwrap();
    println!("Successful KEY_SET_GO at Key Set 0 | RX | CPL!");

    // ide_km key_set_go key set 0 | TX | PR
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_TX;
    let key_sub_stream = KEY_SUB_STREAM_PR;
    idekm_req_context
        .pci_ide_km_key_set_go(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        )
        .await
        .unwrap();
    println!("Successful KEY_SET_GO at Key Set 0 | TX | PR!");

    // ide_km key_set_go key set 0 | TX | NPR
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_TX;
    let key_sub_stream = KEY_SUB_STREAM_NPR;
    idekm_req_context
        .pci_ide_km_key_set_go(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        )
        .await
        .unwrap();
    println!("Successful KEY_SET_GO at Key Set 0 | TX | NPR!");

    // ide_km key_set_go key set 0 | TX | CPL
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_TX;
    let key_sub_stream = KEY_SUB_STREAM_CPL;
    idekm_req_context
        .pci_ide_km_key_set_go(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        )
        .await
        .unwrap();
    println!("Successful KEY_SET_GO at Key Set 0 | TX | CPL!");

    // ide_km key_set_stop key set 0 | RX | PR
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_RX;
    let key_sub_stream = KEY_SUB_STREAM_PR;
    idekm_req_context
        .pci_ide_km_key_set_stop(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        )
        .await
        .unwrap();
    println!("Successful KEY_SET_STOP at Key Set 0 | RX | PR!");

    // ide_km key_set_stop key set 0 | RX | NPR
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_RX;
    let key_sub_stream = KEY_SUB_STREAM_NPR;
    idekm_req_context
        .pci_ide_km_key_set_stop(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        )
        .await
        .unwrap();
    println!("Successful KEY_SET_STOP at Key Set 0 | RX | NPR!");

    // ide_km key_set_stop key set 0 | RX | CPL
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_RX;
    let key_sub_stream = KEY_SUB_STREAM_CPL;
    idekm_req_context
        .pci_ide_km_key_set_stop(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        )
        .await
        .unwrap();
    println!("Successful KEY_SET_STOP at Key Set 0 | RX | CPL!");

    // ide_km key_set_stop key set 0 | TX | PR
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_TX;
    let key_sub_stream = KEY_SUB_STREAM_PR;
    idekm_req_context
        .pci_ide_km_key_set_stop(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        )
        .await
        .unwrap();
    println!("Successful KEY_SET_STOP at Key Set 0 | TX | PR!");

    // ide_km key_set_stop key set 0 | TX | NPR
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_TX;
    let key_sub_stream = KEY_SUB_STREAM_NPR;
    idekm_req_context
        .pci_ide_km_key_set_stop(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        )
        .await
        .unwrap();
    println!("Successful KEY_SET_STOP at Key Set 0 | TX | NPR!");

    // ide_km key_set_stop key set 0 | TX | CPL
    let key_set = KEY_SET_0;
    let key_direction = KEY_DIRECTION_TX;
    let key_sub_stream = KEY_SUB_STREAM_CPL;
    idekm_req_context
        .pci_ide_km_key_set_stop(
            &mut context,
            session_id,
            stream_id,
            key_set,
            key_direction,
            key_sub_stream,
            port_index,
        )
        .await
        .unwrap();
    println!("Successful KEY_SET_STOP at Key Set 0 | TX | CPL!");

    // tdisp test
    let interface_id = InterfaceId {
        function_id: FunctionId {
            requester_id: 0x1234,
            requester_segment: 0,
            requester_segment_valid: false,
        },
    };

    pci_tdisp_req_get_tdisp_version(&mut context, session_id, interface_id)
        .await
        .unwrap();
    println!("Successful Get Tdisp Version!");

    let tsm_caps = 0;
    let mut dsm_caps = 0u32;
    let mut lock_interface_flags_supported = LockInterfaceFlag::empty();
    let mut dev_addr_width = 0u8;
    let mut num_req_this = 0u8;
    let mut num_req_all = 0u8;
    let mut req_msgs_supported = [0u8; 16];
    pci_tdisp_req_get_tdisp_capabilities(
        &mut context,
        session_id,
        tsm_caps,
        interface_id,
        &mut dsm_caps,
        &mut lock_interface_flags_supported,
        &mut dev_addr_width,
        &mut num_req_this,
        &mut num_req_all,
        &mut req_msgs_supported,
    )
    .await
    .unwrap();
    println!("Successful Get Tdisp Capabilities!");

    let mut tdi_state = TdiState::ERROR;
    pci_tdisp_req_get_device_interface_state(
        &mut context,
        session_id,
        interface_id,
        &mut tdi_state,
    )
    .await
    .unwrap();
    assert_eq!(tdi_state, TdiState::CONFIG_UNLOCKED);
    println!("Successful Get Tdisp State: {:X?}!", tdi_state);

    let flags = LockInterfaceFlag::NO_FW_UPDATE;
    let default_stream_id = 0;
    let mmio_reporting_offset = 0xFFFFFF00;
    let bind_p2p_address_mask = 0;
    let mut start_interface_nonce = [0u8; START_INTERFACE_NONCE_LEN];
    let mut tdisp_error_code = None;
    pci_tdisp_req_lock_interface_request(
        &mut context,
        session_id,
        interface_id,
        flags,
        default_stream_id,
        mmio_reporting_offset,
        bind_p2p_address_mask,
        &mut start_interface_nonce,
        &mut tdisp_error_code,
    )
    .await
    .unwrap();
    assert!(tdisp_error_code.is_none());
    println!(
        "Successful Lock Interface, start_interface_nonce: {:X?}!",
        start_interface_nonce
    );

    pci_tdisp_req_get_device_interface_state(
        &mut context,
        session_id,
        interface_id,
        &mut tdi_state,
    )
    .await
    .unwrap();
    assert_eq!(tdi_state, TdiState::CONFIG_LOCKED);
    println!("Successful Get Tdisp State: {:X?}!", tdi_state);

    let mut report = [0u8; MAX_DEVICE_REPORT_BUFFER];
    let mut report_size = 0usize;
    pci_tdisp_req_get_device_interface_report(
        &mut context,
        session_id,
        interface_id,
        &mut report,
        &mut report_size,
        &mut tdisp_error_code,
    )
    .await
    .unwrap();
    assert!(tdisp_error_code.is_none());
    let tdi_report = TdiReportStructure::read_bytes(&report).unwrap();
    println!(
        "Successful Get Interface Report, tdi_report: {:X?}!",
        tdi_report
    );

    pci_tdisp_req_start_interface_request(
        &mut context,
        session_id,
        interface_id,
        &start_interface_nonce,
        &mut tdisp_error_code,
    )
    .await
    .unwrap();
    assert!(tdisp_error_code.is_none());
    println!("Successful Start Interface!");

    pci_tdisp_req_get_device_interface_state(
        &mut context,
        session_id,
        interface_id,
        &mut tdi_state,
    )
    .await
    .unwrap();
    assert_eq!(tdi_state, TdiState::RUN);
    println!("Successful Get Tdisp State: {:X?}!", tdi_state);

    pci_tdisp_req_stop_interface_request(&mut context, session_id, interface_id)
        .await
        .unwrap();
    println!("Successful Stop Interface!");

    pci_tdisp_req_get_device_interface_state(
        &mut context,
        session_id,
        interface_id,
        &mut tdi_state,
    )
    .await
    .unwrap();
    assert_eq!(tdi_state, TdiState::CONFIG_UNLOCKED);
    println!("Successful Get Tdisp State: {:X?}!", tdi_state);

    // end spdm session
    context.end_session(session_id).await.unwrap();
}

// A new logger enables the user to choose log level by setting a `SPDM_LOG` environment variable.
// Use the `Trace` level by default.
fn new_logger_from_env() -> SimpleLogger {
    let level = match std::env::var("SPDM_LOG") {
        Ok(x) => match x.to_lowercase().as_str() {
            "trace" => LevelFilter::Trace,
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            _ => LevelFilter::Error,
        },
        _ => LevelFilter::Trace,
    };

    SimpleLogger::new().with_utc_timestamps().with_level(level)
}

#[cfg(feature = "test_stack_size")]
fn emu_main() {
    // emu_main function stack
    // 1. When compiler optimization is turned off
    // The stack size used by emu_main will not exceed 4k
    // 2. However if compiler optimization is turned on.
    // The situation becomes complicated.
    // The size of the stack used in emu_main needs to be estimated by looking at
    // the location of rsp and the memory map in /proc/self/maps.
    // Here is an example code to dump memory map info for determining EMU_MAIN_FUNCTION_STACK
    //
    // use std::fs::File;
    // use std::io::Read;
    // let rsp: usize;
    // unsafe {
    //     core::arch::asm!("mov {}, rsp", out(reg) rsp);
    // }
    // println!("rsp in emu_main_function: {:x}", rsp);
    // let file_path = "/proc/self/maps";
    // let mut file = File::open(file_path).unwrap();
    // let mut content = String::new();
    // file.read_to_string(&mut content).unwrap();
    // println!("Memory:\n{}", content);
    //
    // Results (example):
    // rsp in emu_main_function: 7f98529a6ef0
    // ...
    // 7f9852656000-7f9852a00000 rw-p 00000000 00:00 0
    //
    // we can got emu_main_function_stack size:
    // 7f9852a00000 - 7f98529a6ef0 = 59110
    const EMU_MAIN_FUNCTION_STACK: usize = 0x60000;

    td_benchmark::StackProfiling::init(
        0x5aa5_5aa5_5aa5_5aa5,
        EMU_STACK_SIZE - EMU_MAIN_FUNCTION_STACK,
    );
    emu_main_inner()
}

#[cfg(not(feature = "test_stack_size"))]
fn emu_main() {
    emu_main_inner()
}

fn emu_main_inner() {
    new_logger_from_env().init().unwrap();

    spdmlib::secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

    #[cfg(feature = "spdm-mbedtls")]
    spdm_emu::crypto::crypto_mbedtls_register_handles();

    let since_the_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards");
    println!("current unit time epoch - {:?}", since_the_epoch.as_secs());

    let socket = TcpStream::connect("127.0.0.1:2323").expect("Couldn't connect to the server...");

    let socket: Arc<Mutex<TcpStream>> = Arc::new(Mutex::new(socket));

    let pcidoe_transport_encap: Arc<Mutex<(dyn SpdmTransportEncap + Send + Sync)>> =
        Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let mctp_transport_encap: Arc<Mutex<(dyn SpdmTransportEncap + Send + Sync)>> =
        Arc::new(Mutex::new(MctpTransportEncap {}));

    let transport_encap: Arc<Mutex<(dyn SpdmTransportEncap + Send + Sync)>> = if USE_PCIDOE {
        pcidoe_transport_encap
    } else {
        mctp_transport_encap
    };

    let transport_type = if USE_PCIDOE {
        SOCKET_TRANSPORT_TYPE_PCI_DOE
    } else {
        SOCKET_TRANSPORT_TYPE_MCTP
    };

    #[cfg(not(feature = "is_sync"))]
    block_on(Box::pin(send_receive_hello(
        socket.clone(),
        transport_encap.clone(),
        transport_type,
    )));

    #[cfg(feature = "is_sync")]
    send_receive_hello(socket.clone(), transport_encap.clone(), transport_type);

    let socket_io_transport = SocketIoTransport::new(socket.clone());
    let socket_io_transport: Arc<Mutex<dyn SpdmDeviceIo + Send + Sync>> =
        Arc::new(Mutex::new(socket_io_transport));

    let key_iv = Arc::new(Mutex::new(Aes256GcmKeyBuffer {
        key: Box::new([0u32; 8]),
        iv: Box::new([0u32; 2]),
    }));

    #[cfg(not(feature = "is_sync"))]
    {
        block_on(Box::pin(test_spdm(
            socket_io_transport.clone(),
            transport_encap.clone(),
        )));

        block_on(Box::pin(test_idekm_tdisp(
            socket_io_transport.clone(),
            transport_encap.clone(),
            key_iv,
        )));

        block_on(Box::pin(send_receive_stop(
            socket,
            transport_encap,
            transport_type,
        )));
    }

    #[cfg(feature = "is_sync")]
    {
        test_spdm(socket_io_transport.clone(), transport_encap.clone());

        test_idekm_tdisp(socket_io_transport.clone(), transport_encap.clone(), key_iv);

        send_receive_stop(socket, transport_encap, transport_type);
    }
    #[cfg(feature = "test_stack_size")]
    {
        let value = td_benchmark::StackProfiling::stack_usage().unwrap();
        println!("max stack usage: {}", value);
    }
}

#[cfg(feature = "test_heap_size")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    use std::thread;

    #[cfg(feature = "test_heap_size")]
    let _profiler = dhat::Profiler::builder().testing().build();

    thread::Builder::new()
        .stack_size(EMU_STACK_SIZE)
        .spawn(emu_main)
        .unwrap()
        .join()
        .unwrap();

    #[cfg(feature = "test_heap_size")]
    log::info!("max heap usage: {}", dhat::HeapStats::get().max_bytes);
}

pub const MMIO_RANGE_COUNT: usize = 4;
pub const DEVICE_SPECIFIC_INFO: &[u8; 9] = b"tdisp emu";
pub const DEVICE_SPECIFIC_INFO_LEN: usize = DEVICE_SPECIFIC_INFO.len();

#[derive(Debug, Copy, Clone)]
pub struct TdiReportStructure {
    pub interface_info: InterfaceInfo,
    pub msi_x_message_control: u16,
    pub lnr_control: u16,
    pub tph_control: u32,
    pub mmio_range_count: u32,
    pub mmio_range: [TdispMmioRange; MMIO_RANGE_COUNT],
    pub device_specific_info_len: u32,
    pub device_specific_info: [u8; DEVICE_SPECIFIC_INFO_LEN],
}

impl Default for TdiReportStructure {
    fn default() -> Self {
        Self {
            interface_info: InterfaceInfo::default(),
            msi_x_message_control: 0u16,
            lnr_control: 0u16,
            tph_control: 0u32,
            mmio_range_count: 0u32,
            mmio_range: [TdispMmioRange::default(); MMIO_RANGE_COUNT],
            device_specific_info_len: 0u32,
            device_specific_info: [0u8; DEVICE_SPECIFIC_INFO_LEN],
        }
    }
}

impl Codec for TdiReportStructure {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0;

        cnt += self.interface_info.encode(bytes)?;
        cnt += 0u16.encode(bytes)?;
        cnt += self.msi_x_message_control.encode(bytes)?;
        cnt += self.lnr_control.encode(bytes)?;
        cnt += self.tph_control.encode(bytes)?;
        cnt += self.mmio_range_count.encode(bytes)?;
        for mr in self.mmio_range.iter().take(self.mmio_range_count as usize) {
            cnt += mr.encode(bytes)?;
        }
        cnt += self.device_specific_info_len.encode(bytes)?;
        for dsi in self
            .device_specific_info
            .iter()
            .take(self.device_specific_info_len as usize)
        {
            cnt += dsi.encode(bytes)?;
        }

        Ok(cnt)
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let interface_info = InterfaceInfo::read(r)?;
        u16::read(r)?;
        let msi_x_message_control = u16::read(r)?;
        let lnr_control = u16::read(r)?;
        let tph_control = u32::read(r)?;
        let mmio_range_count = u32::read(r)?;
        if mmio_range_count as usize > MMIO_RANGE_COUNT {
            return None;
        }
        let mut mmio_range = [TdispMmioRange::default(); MMIO_RANGE_COUNT];
        for mr in mmio_range.iter_mut().take(mmio_range_count as usize) {
            *mr = TdispMmioRange::read(r)?;
        }
        let device_specific_info_len = u32::read(r)?;
        if device_specific_info_len as usize > DEVICE_SPECIFIC_INFO_LEN {
            return None;
        }
        let mut device_specific_info = [0u8; DEVICE_SPECIFIC_INFO_LEN];
        for dsi in device_specific_info
            .iter_mut()
            .take(device_specific_info_len as usize)
        {
            *dsi = u8::read(r)?;
        }

        Some(Self {
            interface_info,
            msi_x_message_control,
            lnr_control,
            tph_control,
            mmio_range_count,
            mmio_range,
            device_specific_info_len,
            device_specific_info,
        })
    }
}

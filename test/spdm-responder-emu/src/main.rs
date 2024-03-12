// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

mod spdm_device_idekm_example;
use idekm::pci_ide_km_responder::pci_ide_km_rsp_dispatcher;
use idekm::pci_idekm::{vendor_id, IDEKM_PROTOCOL_ID};
use spdm_device_idekm_example::init_device_idekm_instance;

mod spdm_device_tdisp_example;
use spdm_device_tdisp_example::init_device_tdisp_instance;

use log::LevelFilter;
use simple_logger::SimpleLogger;

#[cfg(not(feature = "is_sync"))]
use spdm_emu::async_runtime::block_on;
use spdm_emu::watchdog_impl_sample::init_watchdog;
use spdmlib::common::{SecuredMessageVersion, SpdmOpaqueSupport};
use spdmlib::config::{MAX_ROOT_CERT_SUPPORT, RECEIVER_BUFFER_SIZE};
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_MSG_FIELD};
use spdmlib::message::{
    VendorDefinedReqPayloadStruct, VendorDefinedRspPayloadStruct, VendorDefinedStruct,
    VendorIDStruct,
};
use tdisp::pci_tdisp::{
    FunctionId, InterfaceId, LockInterfaceFlag, TdiState, START_INTERFACE_NONCE_LEN,
    TDISP_PROTOCOL_ID,
};
use tdisp::pci_tdisp_responder::pci_tdisp_rsp_dispatcher;

use std::net::{TcpListener, TcpStream};
use std::u32;

use codec::{Codec, Reader, Writer};
use common::SpdmTransportEncap;
use core::convert::TryFrom;
use mctp_transport::MctpTransportEncap;
use pcidoe_transport::{
    PciDoeDataObjectType, PciDoeMessageHeader, PciDoeTransportEncap, PciDoeVendorId,
};
use spdm_emu::crypto_callback::SECRET_ASYM_IMPL_INSTANCE;
use spdm_emu::socket_io_transport::SocketIoTransport;
use spdm_emu::spdm_emu::*;
use spdm_emu::{secret_impl_sample::*, EMU_STACK_SIZE};
use spdmlib::{common, config, protocol::*, responder};
use zeroize::Zeroize;

use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;
use core::ops::DerefMut;
use std::ops::Deref;

use crate::spdm_device_tdisp_example::DeviceContext;

#[maybe_async::maybe_async]
async fn process_socket_message(
    stream: Arc<Mutex<TcpStream>>,
    transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    buffer: Arc<Mutex<[u8; RECEIVER_BUFFER_SIZE]>>,
    buffer_size: usize,
) -> bool {
    if buffer_size < SOCKET_HEADER_LEN {
        return false;
    }
    let buffer_ref = buffer.lock();
    let buffer_ref = buffer_ref.deref();
    let mut reader = Reader::init(&buffer_ref[..SOCKET_HEADER_LEN]);
    let socket_header = SpdmSocketHeader::read(&mut reader).unwrap();

    let res = (
        socket_header.transport_type.to_be(),
        socket_header.command.to_be(),
        &buffer_ref[SOCKET_HEADER_LEN..],
    );

    match socket_header.command.to_be() {
        SOCKET_SPDM_COMMAND_TEST => {
            send_hello(stream.clone(), transport_encap.clone(), res.0).await;
            true
        }
        SOCKET_SPDM_COMMAND_STOP => {
            send_stop(stream.clone(), transport_encap.clone(), res.0).await;
            false
        }
        SOCKET_SPDM_COMMAND_NORMAL => true,
        _ => {
            if USE_PCIDOE {
                send_pci_discovery(
                    stream.clone(),
                    transport_encap.clone(),
                    res.0,
                    &buffer_ref[..buffer_size],
                )
                .await
            } else {
                send_unknown(stream, transport_encap, res.0).await;
                false
            }
        }
    }
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
    const EMU_MAIN_FUNCTION_STACK: usize = 0x60000;

    td_benchmark::StackProfiling::init(
        0x5aa5_5aa5_5aa5_5aa5,
        EMU_STACK_SIZE - EMU_MAIN_FUNCTION_STACK, // main function stack
    );
    emu_main_inner()
}

#[cfg(not(feature = "test_stack_size"))]
fn emu_main() {
    emu_main_inner()
}

fn emu_main_inner() {
    new_logger_from_env().init().unwrap();

    #[cfg(feature = "spdm-mbedtls")]
    spdm_emu::crypto::crypto_mbedtls_register_handles();

    spdmlib::secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
    spdmlib::secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

    let tdisp_rsp_context = DeviceContext {
        bus: 0x2a,
        device: 0x00,
        function: 0x00,
        negotiated_version: None,
        interface_id: InterfaceId {
            function_id: FunctionId {
                requester_id: 0x1234,
                requester_segment: 0,
                requester_segment_valid: false,
            },
        },
        dsm_caps: 0,
        dev_addr_width: 52,
        num_req_this: 1,
        num_req_all: 1,
        flags: LockInterfaceFlag::empty(),
        tdi_state: TdiState::CONFIG_UNLOCKED,
        default_stream_id: 0,
        mmio_reporting_offset: 0,
        bind_p2p_address_mask: 0,
        start_interface_nonce: [0u8; START_INTERFACE_NONCE_LEN],
        p2p_stream_id: 0,
    };

    let device_context_handle = &tdisp_rsp_context as *const DeviceContext as usize;
    spdmlib::message::vendor::register_vendor_defined_struct(VendorDefinedStruct {
        vendor_defined_request_handler: pci_idekm_tdisp_rsp_dispatcher,
        vdm_handle: device_context_handle,
    });

    let listener = TcpListener::bind("127.0.0.1:2323").expect("Couldn't bind to the server");
    println!("server start!");

    let pcidoe_transport_encap: Arc<Mutex<(dyn SpdmTransportEncap + Send + Sync)>> =
        Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let mctp_transport_encap: Arc<Mutex<(dyn SpdmTransportEncap + Send + Sync)>> =
        Arc::new(Mutex::new(MctpTransportEncap {}));

    if let Some(stream) = listener.incoming().next() {
        let stream = stream.expect("Read stream error!");
        let stream = Arc::new(Mutex::new(stream));
        println!("new connection!");
        let mut need_continue;
        let raw_packet = [0u8; RECEIVER_BUFFER_SIZE];
        let raw_packet = Arc::new(Mutex::new(raw_packet));
        loop {
            #[cfg(not(feature = "is_sync"))]
            {
                let sz = block_on(Box::pin(handle_message(
                    stream.clone(),
                    if USE_PCIDOE {
                        pcidoe_transport_encap.clone()
                    } else {
                        mctp_transport_encap.clone()
                    },
                    raw_packet.clone(),
                )));

                need_continue = block_on(Box::pin(process_socket_message(
                    stream.clone(),
                    if USE_PCIDOE {
                        pcidoe_transport_encap.clone()
                    } else {
                        mctp_transport_encap.clone()
                    },
                    raw_packet.clone(),
                    sz,
                )));
            }

            #[cfg(feature = "is_sync")]
            {
                let sz = handle_message(
                    stream.clone(),
                    if USE_PCIDOE {
                        pcidoe_transport_encap.clone()
                    } else {
                        mctp_transport_encap.clone()
                    },
                    raw_packet.clone(),
                );

                need_continue = process_socket_message(
                    stream.clone(),
                    if USE_PCIDOE {
                        pcidoe_transport_encap.clone()
                    } else {
                        mctp_transport_encap.clone()
                    },
                    raw_packet.clone(),
                    sz,
                );
            }

            if !need_continue {
                // TBD: return or break??
                #[cfg(feature = "test_stack_size")]
                {
                    let value = td_benchmark::StackProfiling::stack_usage().unwrap();
                    println!("max stack usage: {}", value);
                }
                return;
            }
        }
    }
}

#[maybe_async::maybe_async]
async fn handle_message(
    stream: Arc<Mutex<TcpStream>>,
    transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    raw_packet: Arc<Mutex<[u8; RECEIVER_BUFFER_SIZE]>>,
) -> usize {
    println!("handle_message!");
    let socket_io_transport = SocketIoTransport::new(stream);
    let socket_io_transport = Arc::new(Mutex::new(socket_io_transport));
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
        | SpdmResponseCapabilityFlags::KEY_UPD_CAP;
    // | SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
    // | SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP
    let rsp_capabilities = if cfg!(feature = "mut-auth") {
        rsp_capabilities | SpdmResponseCapabilityFlags::MUT_AUTH_CAP
    } else {
        rsp_capabilities
    };

    let config_info = common::SpdmConfigInfo {
        spdm_version: [
            Some(SpdmVersion::SpdmVersion10),
            Some(SpdmVersion::SpdmVersion11),
            Some(SpdmVersion::SpdmVersion12),
        ],
        rsp_capabilities,
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
    my_cert_chain_data.data_size = (ca_len + inter_len + leaf_len) as u16;
    my_cert_chain_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());
    my_cert_chain_data.data[ca_len..(ca_len + inter_len)].copy_from_slice(inter_cert.as_ref());
    my_cert_chain_data.data[(ca_len + inter_len)..(ca_len + inter_len + leaf_len)]
        .copy_from_slice(leaf_cert.as_ref());

    let provision_info = common::SpdmProvisionInfo {
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

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    init_watchdog();
    let mut context = responder::ResponderContext::new(
        socket_io_transport,
        transport_encap,
        config_info,
        provision_info,
    );
    loop {
        let mut raw_packet = raw_packet.lock();
        let raw_packet = raw_packet.deref_mut();
        raw_packet.zeroize();
        let res = context.process_message(false, 0, raw_packet).await;
        match res {
            Ok(spdm_result) => match spdm_result {
                Ok(_) => continue,
                Err(status) => panic!("process_message failed with {:?}", status),
            },
            Err(used) => {
                return used; // not spdm cmd, let caller to handle the received buffer
            }
        }
    }
}

#[maybe_async::maybe_async]
pub async fn send_hello(
    stream: Arc<Mutex<TcpStream>>,
    transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    tranport_type: u32,
) {
    println!("get hello");

    let mut payload = [0u8; 1024];

    let mut transport_encap = transport_encap.lock();
    let transport_encap = transport_encap.deref_mut();

    let used = transport_encap
        .encap(
            Arc::new(b"Server Hello!\0"),
            Arc::new(Mutex::new(&mut payload[..])),
            false,
        )
        .await
        .unwrap();

    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream,
        tranport_type,
        spdm_emu::spdm_emu::SOCKET_SPDM_COMMAND_TEST,
        &payload[..used],
    );
}

#[maybe_async::maybe_async]
pub async fn send_unknown(
    stream: Arc<Mutex<TcpStream>>,
    transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    transport_type: u32,
) {
    println!("get unknown");

    let mut payload = [0u8; 1024];
    let mut transport_encap = transport_encap.lock();
    let transport_encap = transport_encap.deref_mut();
    let used = transport_encap
        .encap(Arc::new(b""), Arc::new(Mutex::new(&mut payload[..])), false)
        .await
        .unwrap();

    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream,
        transport_type,
        spdm_emu::spdm_emu::SOCKET_SPDM_COMMAND_UNKOWN,
        &payload[..used],
    );
}

#[maybe_async::maybe_async]
pub async fn send_stop(
    stream: Arc<Mutex<TcpStream>>,
    _transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    transport_type: u32,
) {
    println!("get stop");

    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream,
        transport_type,
        spdm_emu::spdm_emu::SOCKET_SPDM_COMMAND_STOP,
        &[],
    );
}

#[maybe_async::maybe_async]
pub async fn send_pci_discovery(
    stream: Arc<Mutex<TcpStream>>,
    transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    transport_type: u32,
    buffer: &[u8],
) -> bool {
    let mut reader = Reader::init(buffer);
    let mut unknown_message = false;
    match PciDoeMessageHeader::read(&mut reader) {
        Some(pcidoe_header) => {
            match pcidoe_header.vendor_id {
                PciDoeVendorId::PciDoeVendorIdPciSig => {}
                _ => unknown_message = true,
            }
            match pcidoe_header.data_object_type {
                PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery => {}
                _ => unknown_message = true,
            }
        }
        None => unknown_message = true,
    }

    let payload = &mut [1u8, 0u8, 0u8, 0u8];

    match u8::read(&mut reader) {
        None => unknown_message = true,
        Some(discovery_index) => match discovery_index {
            0 => {
                payload[2] = 0;
                payload[3] = 1;
            }
            1 => {
                payload[2] = 1;
                payload[3] = 2;
            }
            2 => {
                payload[2] = 2;
                payload[3] = 0;
            }
            _ => unknown_message = true,
        },
    }
    if unknown_message {
        send_unknown(stream.clone(), transport_encap, transport_type).await;
        return false;
    }

    let payload_len = 4;
    let mut transport_buffer = [0u8; 1024];
    let mut writer = Writer::init(&mut transport_buffer);
    let pcidoe_header = PciDoeMessageHeader {
        vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
        data_object_type: PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery,
        payload_length: 4,
    };
    assert!(pcidoe_header.encode(&mut writer).is_ok());
    let header_size = writer.used();
    transport_buffer[header_size..(header_size + payload_len)].copy_from_slice(payload);
    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream,
        SOCKET_TRANSPORT_TYPE_PCI_DOE,
        spdm_emu::spdm_emu::SOCKET_SPDM_COMMAND_NORMAL,
        &transport_buffer[..(header_size + payload_len)],
    );
    //need continue
    true
}

fn pci_idekm_tdisp_rsp_dispatcher(
    vdm_handle: usize,
    vendor_id_struct: &VendorIDStruct,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    if vendor_defined_req_payload_struct.req_length < 1 || vendor_id_struct != &vendor_id() {
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    match vendor_defined_req_payload_struct.vendor_defined_req_payload[0] {
        IDEKM_PROTOCOL_ID => pci_ide_km_rsp_dispatcher(
            vdm_handle,
            vendor_id_struct,
            vendor_defined_req_payload_struct,
        ),
        TDISP_PROTOCOL_ID => pci_tdisp_rsp_dispatcher(
            vdm_handle,
            vendor_id_struct,
            vendor_defined_req_payload_struct,
        ),
        _ => Err(SPDM_STATUS_INVALID_MSG_FIELD),
    }
}

#[cfg(feature = "test_heap_size")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    use std::thread;

    #[cfg(feature = "test_heap_size")]
    let _profiler = dhat::Profiler::builder().testing().build();

    init_device_idekm_instance();
    init_device_tdisp_instance();

    thread::Builder::new()
        .stack_size(EMU_STACK_SIZE)
        .spawn(emu_main)
        .unwrap()
        .join()
        .unwrap();

    #[cfg(feature = "test_heap_size")]
    log::info!("max heap usage: {}", dhat::HeapStats::get().max_bytes);
}

// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Reader, Writer};
use spdmlib::common::SpdmCodec;
use spdmlib::config;
use spdmlib::protocol::*;
use spdmlib::responder::ResponderContext;
use spdmlib::{message::*, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

const CERT_PORTION_LEN: usize = 512;
const TEST_DATA_TRANSFER_SIZE: u32 = 1024;

#[test]
fn test_encode_encap_requst_get_certificate() {
    let (mut config_info, provision_info) = create_info();
    config_info.data_transfer_size = TEST_DATA_TRANSFER_SIZE;
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let shared_buffer = SharedBuffer::new();
    let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());

    let mut context = ResponderContext::new(
        socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );
    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    context.common.negotiate_info.req_capabilities_sel |= SpdmRequestCapabilityFlags::CERT_CAP;

    let encap_request = &mut [0u8; config::MAX_SPDM_MSG_SIZE];
    let mut writer = Writer::init(encap_request);

    assert!(context
        .encode_encap_requst_get_certificate(&mut writer)
        .is_ok());
    let mut reader = Reader::init(writer.used_slice());
    let header = SpdmMessageHeader::read(&mut reader).unwrap();
    let payload =
        SpdmGetCertificateRequestPayload::spdm_read(&mut context.common, &mut reader).unwrap();

    assert!(context.common.peer_info.peer_cert_chain_temp.is_some());
    assert_eq!(header.version, SpdmVersion::SpdmVersion12);
    assert_eq!(
        header.request_response_code,
        SpdmRequestResponseCode::SpdmRequestGetCertificate
    );
    assert_eq!(
        payload.length,
        TEST_DATA_TRANSFER_SIZE - DELIVER_ENCAPSULATED_RESPONSE_HEADER_SIZE - 8
    );
    assert_eq!(payload.offset, 0);
    assert_eq!(payload.slot_id, 0);
}

#[test]
fn test_handle_encap_response_certificate() {
    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let shared_buffer = SharedBuffer::new();
    let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::pqc_asym_sign::register(SECRET_PQC_ASYM_IMPL_INSTANCE.clone());

    let mut context = ResponderContext::new(
        socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );
    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    context.common.negotiate_info.req_capabilities_sel |= SpdmRequestCapabilityFlags::CERT_CAP;

    let encap_response = &mut [0u8; config::MAX_SPDM_MSG_SIZE];
    let mut writer = Writer::init(encap_response);
    let mut cert_rsp = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmResponseCertificate,
        },
        payload: SpdmMessagePayload::SpdmCertificateResponse(SpdmCertificateResponsePayload {
            slot_id: 0,
            portion_length: CERT_PORTION_LEN as u32,
            remainder_length: 0x600,
            cert_chain: vec![0xa; MAX_SPDM_CERT_PORTION_LEN]
                .into_boxed_slice()
                .try_into()
                .unwrap(),
        }),
    };
    assert!(cert_rsp
        .spdm_encode(&mut context.common, &mut writer)
        .is_ok());

    // peer_cert_chain_temp is not initialized, error is expected
    assert!(context
        .handle_encap_response_certificate(encap_response)
        .is_err());

    if context.common.peer_info.peer_cert_chain_temp.is_none() {
        context.common.peer_info.peer_cert_chain_temp = Some(SpdmCertChainBuffer::default());
    }
    let result = context
        .handle_encap_response_certificate(encap_response)
        .unwrap();

    // remainder_length is not zero, continue expected
    assert!(result);
    let offset = context
        .common
        .peer_info
        .peer_cert_chain_temp
        .as_mut()
        .unwrap()
        .data_size;
    assert_eq!(offset, CERT_PORTION_LEN as u32);
    assert_eq!(context.common.encap_context.encap_cert_size, offset + 0x600);

    let mut writer = Writer::init(encap_response);
    cert_rsp.payload =
        SpdmMessagePayload::SpdmCertificateResponse(SpdmCertificateResponsePayload {
            slot_id: 0xa,
            portion_length: CERT_PORTION_LEN as u32,
            remainder_length: 0x400,
            cert_chain: vec![0xa; MAX_SPDM_CERT_PORTION_LEN]
                .into_boxed_slice()
                .try_into()
                .unwrap(),
        });
    assert!(cert_rsp
        .spdm_encode(&mut context.common, &mut writer)
        .is_ok());

    // slot_id does not match the req_slot_id, error is expected
    assert!(context
        .handle_encap_response_certificate(encap_response)
        .is_err());

    let mut writer = Writer::init(encap_response);
    cert_rsp.payload =
        SpdmMessagePayload::SpdmCertificateResponse(SpdmCertificateResponsePayload {
            slot_id: 0,
            portion_length: CERT_PORTION_LEN as u32,
            remainder_length: 0x400,
            cert_chain: vec![0xa; MAX_SPDM_CERT_PORTION_LEN]
                .into_boxed_slice()
                .try_into()
                .unwrap(),
        });
    assert!(cert_rsp
        .spdm_encode(&mut context.common, &mut writer)
        .is_ok());

    assert!(context
        .handle_encap_response_certificate(encap_response)
        .is_ok());
    let offset = context
        .common
        .peer_info
        .peer_cert_chain_temp
        .as_mut()
        .unwrap()
        .data_size;
    assert_eq!(offset, 0x400_u32);
    assert_eq!(context.common.encap_context.encap_cert_size, offset + 0x400);
}

#[test]
fn test_verify_requester_cert_chain_uses_req_asym_sel() {
    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let shared_buffer = SharedBuffer::new();
    let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));

    let mut context = ResponderContext::new(
        socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );
    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context
        .common
        .provision_info
        .peer_root_cert_data
        .iter_mut()
        .for_each(|root| *root = None);

    let chain = &include_bytes!("../../../../test_key/ecp384/bundle_requester.certchain.der")[..];
    let (root_begin, root_end) =
        spdmlib::crypto::cert_operation::get_cert_from_cert_chain(chain, 0).unwrap();
    let root_hash = spdmlib::crypto::hash::hash_all(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        &chain[root_begin..root_end],
    )
    .unwrap();

    let mut cert_chain = SpdmCertChainBuffer::default();
    let header_size = 4 + root_hash.data_size as usize;
    cert_chain.data_size = (header_size + chain.len()) as u32;
    cert_chain.data[..4].copy_from_slice(&cert_chain.data_size.to_le_bytes());
    cert_chain.data[4..header_size].copy_from_slice(root_hash.as_ref());
    cert_chain.data[header_size..header_size + chain.len()].copy_from_slice(chain);
    context.common.peer_info.peer_cert_chain_temp = Some(cert_chain);

    // The Requester's P-384 chain is judged by ReqBaseAsymAlg, not BaseAsymAlgo.
    context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
    context.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    assert!(context.verify_spdm_certificate_chain().is_ok());

    context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    context.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
    assert!(context.verify_spdm_certificate_chain().is_err());
}

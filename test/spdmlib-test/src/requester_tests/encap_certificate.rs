// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Reader, Writer};
use spdmlib::common::SpdmCodec;
use spdmlib::config;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{message::*, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

const CERT_PORTION_LEN: usize = 512;

#[test]
fn test_encap_handle_get_certificate() {
    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let shared_buffer = SharedBuffer::new();
    let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let mut context = RequesterContext::new(
        socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );
    context.common.provision_info.my_cert_chain = [
        Some(SpdmCertChainBuffer {
            data_size: 1024u16,
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
    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    context.common.negotiate_info.req_capabilities_sel |= SpdmRequestCapabilityFlags::CERT_CAP;

    let encap_request = &mut [0u8; 1024];
    let mut writer = Writer::init(encap_request);
    let get_cert = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmRequestGetCertificate,
        },
        payload: SpdmMessagePayload::SpdmGetCertificateRequest(SpdmGetCertificateRequestPayload {
            slot_id: 0,
            offset: 0,
            length: CERT_PORTION_LEN as u16,
        }),
    };
    assert!(get_cert
        .spdm_encode(&mut context.common, &mut writer)
        .is_ok());

    let encap_response = &mut [0u8; config::MAX_SPDM_MSG_SIZE];
    let mut writer = Writer::init(encap_response);

    context.encap_handle_get_certificate(encap_request, &mut writer);
    let mut reader = Reader::init(encap_response);
    let header = SpdmMessageHeader::read(&mut reader).unwrap();
    let cert_rsp =
        SpdmCertificateResponsePayload::spdm_read(&mut context.common, &mut reader).unwrap();

    assert_eq!(header.version, SpdmVersion::SpdmVersion12);
    assert_eq!(
        header.request_response_code,
        SpdmRequestResponseCode::SpdmResponseCertificate
    );
    assert_eq!(cert_rsp.portion_length, 512);
    assert_eq!(cert_rsp.remainder_length, 512);
    assert_eq!(cert_rsp.slot_id, 0);
}

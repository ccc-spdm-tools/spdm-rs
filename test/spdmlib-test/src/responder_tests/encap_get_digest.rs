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
use spdmlib::responder::ResponderContext;
use spdmlib::{message::*, secret};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_encode_encap_requst_get_digest() {
    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let shared_buffer = SharedBuffer::new();
    let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

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

    assert!(context.encode_encap_request_get_digest(&mut writer).is_ok());
    assert_eq!(writer.used(), 4);

    let mut reader = Reader::init(writer.used_slice());
    let header = SpdmMessageHeader::read(&mut reader).unwrap();
    let _ = SpdmGetDigestsRequestPayload::spdm_read(&mut context.common, &mut reader).unwrap();

    assert_eq!(header.version, SpdmVersion::SpdmVersion12);
    assert_eq!(
        header.request_response_code,
        SpdmRequestResponseCode::SpdmRequestGetDigests
    );
}

#[test]
fn test_handle_encap_response_digest() {
    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let shared_buffer = SharedBuffer::new();
    let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

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
    let digests_rsp = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion12,
            request_response_code: SpdmRequestResponseCode::SpdmResponseDigests,
        },
        payload: SpdmMessagePayload::SpdmDigestsResponse(SpdmDigestsResponsePayload {
            slot_mask: 1,
            digests: gen_array_clone(
                SpdmDigestStruct {
                    data_size: SpdmBaseHashAlgo::TPM_ALG_SHA_384.get_size(),
                    data: Box::new([0xffu8; SPDM_MAX_HASH_SIZE]),
                },
                SPDM_MAX_SLOT_NUMBER,
            ),
        }),
    };
    assert!(digests_rsp
        .spdm_encode(&mut context.common, &mut writer)
        .is_ok());

    assert!(context.handle_encap_response_digest(encap_response).is_ok());
}

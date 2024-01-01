// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Reader, Writer};
use spdmlib::common::SpdmCodec;
use spdmlib::config;
use spdmlib::protocol::*;
use spdmlib::{message::*, requester};
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

#[test]
fn test_encode_encap_error_response() {
    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let shared_buffer = SharedBuffer::new();
    let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));

    let mut context = requester::RequesterContext::new(
        socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );
    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;

    let encap_response = &mut [0u8; config::MAX_SPDM_MSG_SIZE];
    let mut writer = Writer::init(encap_response);
    context.encode_encap_error_response(SpdmErrorCode::SpdmErrorInvalidRequest, 0xa, &mut writer);

    let mut reader = Reader::init(encap_response);
    let header = SpdmMessageHeader::read(&mut reader).unwrap();
    let error_rsp = SpdmErrorResponsePayload::spdm_read(&mut context.common, &mut reader).unwrap();

    assert_eq!(reader.used(), 4);
    assert_eq!(header.version, SpdmVersion::SpdmVersion12);
    assert_eq!(
        header.request_response_code,
        SpdmRequestResponseCode::SpdmResponseError
    );
    assert_eq!(error_rsp.error_code, SpdmErrorCode::SpdmErrorInvalidRequest);
    assert_eq!(error_rsp.error_data, 0xa);
}

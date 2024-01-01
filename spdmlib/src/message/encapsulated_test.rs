// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};
extern crate alloc;

#[test]
fn test_get_encapsulated_request_payload() {
    create_spdm_context!(context);

    let get_encap_req = SpdmGetEncapsulatedRequestPayload {};
    let mut buffer = [0u8; 16];

    let mut writer = Writer::init(&mut buffer);
    let size = get_encap_req
        .spdm_encode(&mut context, &mut writer)
        .unwrap();
    assert_eq!(size, 2);

    let mut reader = Reader::init(&mut buffer);
    let ret = SpdmGetEncapsulatedRequestPayload::spdm_read(&mut context, &mut reader);
    assert!(ret.is_some());
}

#[test]
fn test_encapsulated_request_payload() {
    create_spdm_context!(context);

    let encap_req = SpdmEncapsulatedRequestPayload { request_id: 0xa };
    let mut buffer = [0u8; 16];

    let mut writer = Writer::init(&mut buffer);
    let size = encap_req.spdm_encode(&mut context, &mut writer).unwrap();
    assert_eq!(size, 2);

    let mut reader = Reader::init(&mut buffer);
    let encap_req = SpdmEncapsulatedRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(encap_req.request_id, 0xa);
}

#[test]
fn test_deliver_encapsulated_response_payload() {
    create_spdm_context!(context);

    let deliver_encap_rsp = SpdmDeliverEncapsulatedResponsePayload { request_id: 0xa };
    let mut buffer = [0u8; 16];

    let mut writer = Writer::init(&mut buffer);
    let size = deliver_encap_rsp
        .spdm_encode(&mut context, &mut writer)
        .unwrap();
    assert_eq!(size, 2);

    let mut reader = Reader::init(&mut buffer);
    let deliver_encap_rsp =
        SpdmDeliverEncapsulatedResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(deliver_encap_rsp.request_id, 0xa);
}

#[test]
fn test_encapsulated_response_ack_payload() {
    create_spdm_context!(context);
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;

    let encap_rsp_ack = SpdmEncapsulatedResponseAckPayload {
        request_id: 0xa,
        payload_type: SpdmEncapsulatedResponseAckPayloadType::Present,
        ack_request_id: 0x1,
    };
    let mut buffer = [0u8; 16];

    let mut writer = Writer::init(&mut buffer);
    let size = encap_rsp_ack
        .spdm_encode(&mut context, &mut writer)
        .unwrap();
    assert_eq!(size, 6);

    let mut reader = Reader::init(&mut buffer);
    let encap_rsp_ack =
        SpdmEncapsulatedResponseAckPayload::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(encap_rsp_ack.request_id, 0xa);
    assert_eq!(
        encap_rsp_ack.payload_type,
        SpdmEncapsulatedResponseAckPayloadType::Present
    );
    assert_eq!(encap_rsp_ack.ack_request_id, 0x1);
}

#[test]
fn test_encapsulated_response_ack_payload_ver11() {
    create_spdm_context!(context);
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

    let encap_rsp_ack = SpdmEncapsulatedResponseAckPayload {
        request_id: 0xa,
        payload_type: SpdmEncapsulatedResponseAckPayloadType::Present,
        ack_request_id: 0x1,
    };
    let mut buffer = [0u8; 16];

    let mut writer = Writer::init(&mut buffer);
    let size = encap_rsp_ack
        .spdm_encode(&mut context, &mut writer)
        .unwrap();
    assert_eq!(size, 2);

    let mut reader = Reader::init(&mut buffer);
    let encap_rsp_ack =
        SpdmEncapsulatedResponseAckPayload::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(encap_rsp_ack.request_id, 0xa);
}

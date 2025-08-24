// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::*;
use crate::common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
use byteorder::{ByteOrder, LittleEndian};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};
extern crate alloc;

#[test]
fn test_chunk_send_struct() {
    create_spdm_context!(context);
    let context = &mut context;
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;

    let u8_slice = &mut [0u8; config::SPDM_SENDER_DATA_TRANSFER_SIZE];
    let writer = &mut Writer::init(u8_slice);

    context.chunk_context.chunk_message_size = 0x100;
    context.chunk_context.chunk_message_data = [0u8; config::MAX_SPDM_MSG_SIZE];
    context.chunk_context.transferred_size = 0;
    assert!(context.chunk_context.chunk_message_size <= config::MAX_SPDM_MSG_SIZE);
    let chunk_size = config::SPDM_SENDER_DATA_TRANSFER_SIZE
        - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_FIRST_CHUNK_SEND;
    let large_message_size = context.chunk_context.chunk_message_size as u32;

    let request = SpdmChunkSendRequestPayload {
        chunk_sender_attributes: SpdmChunkSenderAttributes::default(),
        handle: 1,
        chunk_seq_num: 0,
        chunk_size: chunk_size as u32,
        large_message_size: Some(large_message_size),
    };

    let field_slice = &mut [0u8; 4];
    assert!(request.spdm_encode(context, writer).is_ok());
    assert_eq!(writer.used(), config::SPDM_SENDER_DATA_TRANSFER_SIZE - 2);
    assert_eq!(u8_slice[0..4], [0, 1, 0, 0]);
    assert_eq!(u8_slice[4..6], [0, 0]);
    LittleEndian::write_u32(field_slice, chunk_size as u32);
    assert_eq!(u8_slice[6..10], field_slice[..]);
    LittleEndian::write_u32(field_slice, large_message_size as u32);
    assert_eq!(u8_slice[10..14], field_slice[..]);
    assert_eq!(
        u8_slice[14..(14 + chunk_size)],
        [0u8; config::SPDM_SENDER_DATA_TRANSFER_SIZE
            - SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_FIRST_CHUNK_SEND]
    );

    context.chunk_context.transferred_size = 0;
    context.chunk_context.chunk_status = common::SpdmChunkStatus::Idle;

    let reader = &mut Reader::init(u8_slice);
    let read_request = SpdmChunkSendRequestPayload::spdm_read(context, reader).unwrap();
    assert_eq!(
        read_request.chunk_sender_attributes,
        SpdmChunkSenderAttributes::default()
    );
    assert_eq!(read_request.handle, 1);
    assert_eq!(read_request.chunk_seq_num, 0);
    assert_eq!(read_request.chunk_size, chunk_size as u32);
    assert_eq!(read_request.large_message_size.unwrap(), large_message_size);
}

#[test]
fn test_chunk_send_ack_struct() {
    create_spdm_context!(context);
    let context = &mut context;
    context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;

    let u8_slice = &mut [0u8; config::SPDM_SENDER_DATA_TRANSFER_SIZE];
    let writer = &mut Writer::init(u8_slice);

    context.chunk_context.chunk_message_size = 36;
    context.chunk_context.chunk_message_data[..36].copy_from_slice(&[0u8; 36]);

    let request = SpdmChunkSendAckResponsePayload {
        chunk_receiver_attributes: SpdmChunkReceiverAttributes::default(),
        handle: 1,
        chunk_seq_num: 0,
        response_to_large_request_size: 36,
    };

    assert!(request.spdm_encode(context, writer).is_ok());
    assert_eq!(writer.used(), 40);
    assert_eq!(u8_slice[0..4], [0, 1, 0, 0]);
    assert_eq!(u8_slice[4..40], [0u8; 36]);

    context.chunk_context.transferred_size = 36;
    context.chunk_context.chunk_message_size = 36;
    let reader = &mut Reader::init(&u8_slice[..40]);
    let read_request = SpdmChunkSendAckResponsePayload::spdm_read(context, reader).unwrap();

    assert_eq!(
        read_request.chunk_receiver_attributes,
        SpdmChunkReceiverAttributes::default()
    );
    assert_eq!(read_request.handle, 1);
    assert_eq!(read_request.chunk_seq_num, 0);
    assert_eq!(read_request.response_to_large_request_size, 36);
    assert_eq!(context.chunk_context.chunk_message_size, 36);
    assert_eq!(context.chunk_context.chunk_message_data[..36], [0u8; 36]);
}

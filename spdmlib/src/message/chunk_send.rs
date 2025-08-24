// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common;
use crate::config;
use crate::message::*;

pub const SPDM_VERSION_1_2_OFFSET_OF_RESPONSE_OF_LARGE_REQUEST_IN_CHUNK_SEND_ACK: usize = 6;
pub const SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_FIRST_CHUNK_SEND: usize = 16;
pub const SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_CHUNK_SEND: usize = 12;

#[derive(Debug, Clone, Default)]
pub struct SpdmChunkSendRequestPayload {
    pub chunk_sender_attributes: SpdmChunkSenderAttributes,
    pub handle: u8,
    pub chunk_seq_num: u16,
    pub chunk_size: u32,
    pub large_message_size: Option<u32>, // Only present in the first chunk
}

impl SpdmCodec for SpdmChunkSendRequestPayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;

        cnt += self
            .chunk_sender_attributes
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Param1
        cnt += self
            .handle
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Param2
        cnt += self
            .chunk_seq_num
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Chunk Seq No
        cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Reserved
        cnt += self
            .chunk_size
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Chunk Size

        if self.large_message_size.is_some() {
            cnt += self
                .large_message_size
                .unwrap()
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Large Message Size
        }

        let data_slice =
            &context.chunk_context.chunk_message_data[context.chunk_context.transferred_size
                ..context.chunk_context.transferred_size + self.chunk_size as usize];
        cnt += bytes.extend_from_slice(data_slice).unwrap(); // SPDM Chunk Data

        context.chunk_context.transferred_size += self.chunk_size as usize;

        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmChunkSendRequestPayload> {
        let chunk_sender_attributes = SpdmChunkSenderAttributes::read(r)?; // Param1
        let handle = u8::read(r)?; // Param2
        let chunk_seq_num = u16::read(r)?; // Chunk Seq No
        u16::read(r)?; // Reserved
        let chunk_size = u32::read(r)?; // Chunk Size
        let large_message_size = if chunk_seq_num == 0 {
            u32::read(r) // Large Message Size
        } else {
            None
        };

        if chunk_seq_num == 0 {
            if context.chunk_context.chunk_status == common::SpdmChunkStatus::Idle
                && chunk_size <= config::MAX_SPDM_MSG_SIZE as u32
            {
                context.chunk_context.transferred_size = 0;
            } else {
                return None;
            }
        } else if chunk_size as usize
            > context.chunk_context.chunk_message_size - context.chunk_context.transferred_size
        {
            return None;
        }

        let data_slice = r.take(chunk_size as usize)?;
        context.chunk_context.chunk_message_data[context.chunk_context.transferred_size
            ..context.chunk_context.transferred_size + chunk_size as usize]
            .copy_from_slice(data_slice);
        context.chunk_context.transferred_size += chunk_size as usize;

        Some(SpdmChunkSendRequestPayload {
            chunk_sender_attributes,
            handle,
            chunk_seq_num,
            chunk_size,
            large_message_size,
        })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmChunkSenderAttributes: u8 {
        const LAST_CHUNK = 0b0000_0001;
        const VALID_MASK = Self::LAST_CHUNK.bits;
    }
}

impl Codec for SpdmChunkSenderAttributes {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmChunkSenderAttributes> {
        let bits = u8::read(r)?;

        SpdmChunkSenderAttributes::from_bits(bits & SpdmChunkSenderAttributes::VALID_MASK.bits)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmChunkSendAckResponsePayload {
    pub chunk_receiver_attributes: SpdmChunkReceiverAttributes,
    pub handle: u8,
    pub chunk_seq_num: u16,
    pub response_to_large_request_size: usize,
}

impl SpdmCodec for SpdmChunkSendAckResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .chunk_receiver_attributes
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Param1
        cnt += self
            .handle
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Param2
        cnt += self
            .chunk_seq_num
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Chunk Seq No
        if self.response_to_large_request_size > 0 {
            cnt += bytes
                .extend_from_slice(
                    &context.chunk_context.chunk_message_data
                        [..self.response_to_large_request_size],
                )
                .unwrap(); // Response to Large Request
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmChunkSendAckResponsePayload> {
        let chunk_receiver_attributes = SpdmChunkReceiverAttributes::read(r)?; // Param1
        let handle = u8::read(r)?; // Param2
        let chunk_seq_num = u16::read(r)?; // Chunk Seq No
        let response_to_large_request_size;
        if context.chunk_context.transferred_size >= context.chunk_context.chunk_message_size
            || chunk_receiver_attributes.contains(SpdmChunkReceiverAttributes::EARLY_ERROR_DETECTED)
        {
            let remaining = r.left();
            if remaining > 0 && remaining <= config::MAX_SPDM_MSG_SIZE {
                response_to_large_request_size = remaining;
                context.chunk_context.chunk_message_size = remaining;
                context.chunk_context.chunk_message_data[..remaining]
                    .copy_from_slice(r.take(remaining)?);
                context.chunk_context.transferred_size = remaining;
            } else {
                return None; // Invalid Chunk Send Ack Response
            }
        } else {
            response_to_large_request_size = 0;
        };

        Some(SpdmChunkSendAckResponsePayload {
            chunk_receiver_attributes,
            handle,
            chunk_seq_num,
            response_to_large_request_size,
        })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmChunkReceiverAttributes: u8 {
        const EARLY_ERROR_DETECTED = 0b0000_0001;
        const VALID_MASK = Self::EARLY_ERROR_DETECTED.bits;
    }
}

impl Codec for SpdmChunkReceiverAttributes {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmChunkReceiverAttributes> {
        let bits = u8::read(r)?;

        SpdmChunkReceiverAttributes::from_bits(bits & SpdmChunkReceiverAttributes::VALID_MASK.bits)
    }
}

#[cfg(test)]
#[path = "chunk_send_test.rs"]
mod chunk_send_test;

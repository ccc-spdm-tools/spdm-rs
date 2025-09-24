// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common;
use crate::config;
use crate::message::*;

pub const SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_FIRST_CHUNK_RESPONSE: usize = 16;
pub const SPDM_VERSION_1_2_OFFSET_OF_SPDM_CHUNK_IN_CHUNK_RESPONSE: usize = 12;

#[derive(Debug, Clone, Default)]
pub struct SpdmChunkGetRequestPayload {
    pub handle: u8,
    pub chunk_seq_num: u32,
}

impl SpdmCodec for SpdmChunkGetRequestPayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let large_chunk = context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14;
        let mut cnt = 0usize;
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Param1
        cnt += self
            .handle
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Param2
        if large_chunk {
            cnt += self
                .chunk_seq_num
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Chunk Seq No
        } else {
            cnt += (self.chunk_seq_num as u16)
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Chunk Seq No
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmChunkGetRequestPayload> {
        let large_chunk = context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14;
        u8::read(r)?; // Param1
        let handle = u8::read(r)?; // Param2
        let chunk_seq_num = if large_chunk {
            u32::read(r)?
        } else {
            u16::read(r)? as u32
        }; // Chunk Seq No
        Some(SpdmChunkGetRequestPayload {
            handle,
            chunk_seq_num,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmChunkResponsePayload {
    pub response_attributes: SpdmChunkSenderAttributes,
    pub handle: u8,
    pub chunk_seq_num: u32,
    pub chunk_size: u32,
    pub large_message_size: Option<u32>,
}

impl SpdmCodec for SpdmChunkResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let large_chunk = context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14;
        let mut cnt = 0usize;
        cnt += self
            .response_attributes
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Param1
        cnt += self
            .handle
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Param2
        if large_chunk {
            cnt += self
                .chunk_seq_num
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Chunk Seq No
        } else {
            cnt += (self.chunk_seq_num as u16)
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Chunk Seq No
            cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Reserved
        }
        cnt += self
            .chunk_size
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Chunk Size
        if let Some(large_message_size) = self.large_message_size {
            cnt += large_message_size
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // Large Message Size
        }
        let slice = &context.chunk_context.chunk_message_data[context.chunk_context.transferred_size
            ..context.chunk_context.transferred_size + self.chunk_size as usize];
        context.chunk_context.transferred_size += self.chunk_size as usize;
        cnt += bytes.extend_from_slice(slice).unwrap(); // Reserved

        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmChunkResponsePayload> {
        let large_chunk = context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14;
        let response_attributes = SpdmChunkSenderAttributes::read(r)?; // Param1
        let handle = u8::read(r)?; // Param2
        let chunk_seq_num = if large_chunk {
            u32::read(r)?
        } else {
            u16::read(r)? as u32
        }; // Chunk Seq No
        if !large_chunk {
            u16::read(r)?;
        } // Reserved
        let chunk_size = u32::read(r)?; // Chunk Size
        let large_message_size = if chunk_seq_num == 0 {
            Some(u32::read(r)?) // Large Message Size
        } else {
            None
        };
        let data_slice = r.take(chunk_size as usize)?;
        if chunk_size as usize + context.chunk_context.transferred_size > config::MAX_SPDM_MSG_SIZE
            || (chunk_seq_num != 0
                && chunk_size as usize + context.chunk_context.transferred_size
                    > context.chunk_context.chunk_message_size)
        {
            return None;
        } else {
            context.chunk_context.chunk_message_data[context.chunk_context.transferred_size
                ..context.chunk_context.transferred_size + chunk_size as usize]
                .copy_from_slice(data_slice); // Chunk Data
            context.chunk_context.transferred_size += chunk_size as usize;
        }

        Some(SpdmChunkResponsePayload {
            response_attributes,
            handle,
            chunk_seq_num,
            chunk_size,
            large_message_size,
        })
    }
}

#[cfg(test)]
#[path = "chunk_get_test.rs"]
mod chunk_get_test;

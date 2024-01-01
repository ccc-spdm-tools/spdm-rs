// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::spdm_emu::*;
use std::net::TcpStream;

use spdmlib::common::SpdmDeviceIo;
use spdmlib::config;
use spdmlib::error::SpdmResult;
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;
use core::ops::DerefMut;

pub const DEVICE_IO_STACK_SIZE: usize = core::mem::size_of::<SocketIoTransport>()
    + config::RECEIVER_BUFFER_SIZE
    + core::mem::size_of::<usize>() * 256; // for general stack case;

pub struct SocketIoTransport {
    pub data: Arc<Mutex<TcpStream>>,
    transport_type: u32,
}
impl SocketIoTransport {
    pub fn new(stream: Arc<Mutex<TcpStream>>) -> Self {
        SocketIoTransport {
            data: stream,
            transport_type: if USE_PCIDOE {
                SOCKET_TRANSPORT_TYPE_PCI_DOE
            } else {
                SOCKET_TRANSPORT_TYPE_MCTP
            },
        }
    }
}

#[maybe_async::maybe_async]
impl SpdmDeviceIo for SocketIoTransport {
    async fn receive(
        &mut self,
        read_buffer: Arc<Mutex<&mut [u8]>>,
        timeout: usize,
    ) -> Result<usize, usize> {
        let mut buffer = [0u8; config::RECEIVER_BUFFER_SIZE];

        let mut read_buffer = read_buffer.lock();
        let read_buffer = read_buffer.deref_mut();

        if let Some((_, command, payload)) =
            receive_message(self.data.clone(), &mut buffer[..], timeout).await
        {
            // TBD: do we need this?
            // self.transport_type = transport_type;
            let used = payload.len();
            let total = used + SOCKET_HEADER_LEN;
            if command == SOCKET_SPDM_COMMAND_NORMAL {
                read_buffer[..used].copy_from_slice(payload);
                Ok(used)
            } else {
                // this commmand need caller to deal.
                read_buffer[..total].copy_from_slice(&buffer[..total]);
                Err(total)
            }
        } else {
            // socket header can't be received.
            Err(0)
        }
    }

    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        send_message(
            self.data.clone(),
            self.transport_type,
            SOCKET_SPDM_COMMAND_NORMAL,
            &buffer,
        );
        Ok(())
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

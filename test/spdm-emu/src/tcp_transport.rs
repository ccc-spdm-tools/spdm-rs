// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

// use codec::{Reader, Codec, Writer};
use std::io::{Read, Write};
use std::net::TcpStream;

use spdmlib::common::SpdmDeviceIo;
use spdmlib::error::{SpdmResult, SPDM_STATUS_SEND_FAIL};

pub struct TcpTransport<'a> {
    pub data: &'a mut TcpStream,
}

impl SpdmDeviceIo for TcpTransport<'_> {
    fn receive(&mut self, buffer: &mut [u8], _timeout: usize) -> Result<usize, usize> {
        let res = self.data.read(buffer).ok();
        if let Some(size) = res {
            Ok(size)
        } else {
            Err(0)
        }
    }

    fn send(&mut self, buffer: &[u8]) -> SpdmResult {
        let res = self.data.write(buffer);
        if res.is_ok() {
            Ok(())
        } else {
            Err(SPDM_STATUS_SEND_FAIL)
        }
    }

    fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![forbid(unsafe_code)]

use super::*;
use crate::spdmlib::error::SPDM_STATUS_SEND_FAIL;
use async_trait::async_trait;
use spdmlib_test::common::device_io::SharedBuffer;

use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::borrow::BorrowMut;
use core::ops::DerefMut;

pub struct FakeSpdmDeviceIoReceve {
    data: Arc<SharedBuffer>,
}

impl FakeSpdmDeviceIoReceve {
    pub fn new(data: Arc<SharedBuffer>) -> Self {
        FakeSpdmDeviceIoReceve { data: data }
    }
}

#[async_trait]
impl SpdmDeviceIo for FakeSpdmDeviceIoReceve {
    async fn receive(
        &mut self,
        read_buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        let len = self.data.get_buffer(read_buffer.clone());
        let mut read_buffer = read_buffer.lock();
        let read_buffer = read_buffer.deref_mut();
        log::info!("responder receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        self.data.set_buffer_ref(buffer.clone());
        log::info!("responder send    RAW - {:02x?}\n", buffer);
        Ok(())
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub struct FuzzTmpSpdmDeviceIoReceve {
    data: Arc<SharedBuffer>,
    fuzzdata: [[u8; 528]; 4],
    current: usize,
}

impl FuzzTmpSpdmDeviceIoReceve {
    pub fn new(data: Arc<SharedBuffer>, fuzzdata: [[u8; 528]; 4], current: usize) -> Self {
        FuzzTmpSpdmDeviceIoReceve {
            data: data,
            fuzzdata,
            current,
        }
    }
}

#[async_trait]
impl SpdmDeviceIo for FuzzTmpSpdmDeviceIoReceve {
    async fn receive(
        &mut self,
        read_buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        let len = self.data.get_buffer(read_buffer.clone());
        let mut read_buffer = read_buffer.lock();
        let read_buffer = read_buffer.deref_mut();
        log::info!("responder receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        let buffer: &[u8] = &self.fuzzdata[self.current];
        self.data.set_buffer_ref(Arc::new(buffer));
        log::info!("responder send    RAW - {:02x?}\n", buffer);
        self.current += 1;
        Ok(())
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub struct FuzzSpdmDeviceIoReceve {
    data: Arc<SharedBuffer>,
    fuzzdata: Arc<[u8]>,
}

impl FuzzSpdmDeviceIoReceve {
    pub fn new(data: Arc<SharedBuffer>, fuzzdata: Arc<[u8]>) -> Self {
        FuzzSpdmDeviceIoReceve {
            data: data,
            fuzzdata,
        }
    }
}

#[async_trait]
impl SpdmDeviceIo for FuzzSpdmDeviceIoReceve {
    async fn receive(
        &mut self,
        read_buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        let len = self.data.get_buffer(read_buffer.clone());
        let mut read_buffer = read_buffer.lock();
        let read_buffer = read_buffer.deref_mut();
        log::info!("responder receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        self.data.set_buffer(self.fuzzdata.clone());
        log::info!("responder send    RAW - {:02x?}\n", buffer);
        Ok(())
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub struct FakeSpdmDeviceIo {
    pub rx: Arc<SharedBuffer>,
}

impl FakeSpdmDeviceIo {
    pub fn new(rx: Arc<SharedBuffer>) -> Self {
        FakeSpdmDeviceIo { rx }
    }
    pub fn set_rx(&mut self, buffer: &[u8]) {
        self.rx.set_buffer_ref(Arc::new(buffer));
    }
}

#[async_trait]
impl SpdmDeviceIo for FakeSpdmDeviceIo {
    async fn receive(
        &mut self,
        read_buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        let len = self.rx.get_buffer(read_buffer.clone());
        let mut read_buffer = read_buffer.lock();
        let read_buffer = read_buffer.deref_mut();
        log::info!("requester receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        log::info!("requester send    RAW - {:02x?}\n", buffer);
        Ok(())
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

#[test]
fn test_single_run() {
    let buffer = SharedBuffer::new();
    let mut server = FakeSpdmDeviceIoReceve::new(&buffer);
    let mut client = FakeSpdmDeviceIoReceve::new(&buffer);
    client.send(&[1, 2]).unwrap();
    let mut rev = [0u8, 64];
    client.receive(&mut rev, 0).unwrap();
    println!("rev: {:?}", rev);
}

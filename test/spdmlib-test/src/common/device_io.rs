// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![allow(unused)]

use async_trait::async_trait;
use spdmlib::common::{SpdmDeviceIo, SpdmTransportEncap, ST1};
use spdmlib::config::RECEIVER_BUFFER_SIZE;
use spdmlib::error::{SpdmResult, SPDM_STATUS_DECAP_FAIL, SPDM_STATUS_ERROR_PEER};
use spdmlib::responder;
use std::cell::RefCell;
use std::collections::VecDeque;

use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::borrow::BorrowMut;
use core::ops::DerefMut;

pub struct MySpdmDeviceIo;

#[async_trait]
impl SpdmDeviceIo for MySpdmDeviceIo {
    async fn send(&mut self, _buffer: Arc<&[u8]>) -> SpdmResult {
        todo!()
    }

    async fn receive(
        &mut self,
        _buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        todo!()
    }

    async fn flush_all(&mut self) -> SpdmResult {
        todo!()
    }
}

pub struct FakeSpdmDeviceIo {
    pub data: Arc<SharedBuffer>,
    pub responder: Arc<Mutex<responder::ResponderContext>>,
}

impl FakeSpdmDeviceIo {
    pub fn new(
        data: Arc<SharedBuffer>,
        responder: Arc<Mutex<responder::ResponderContext>>,
    ) -> Self {
        FakeSpdmDeviceIo { data, responder }
    }
}

#[async_trait]
impl SpdmDeviceIo for FakeSpdmDeviceIo {
    async fn receive(
        &mut self,
        read_buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        let mut responder = self.responder.lock();
        let mut responder = responder.deref_mut();

        let len = {
            let mut device_io = responder.common.device_io.lock();
            let device_io = device_io.deref_mut();
            device_io.receive(read_buffer.clone(), 0).await.unwrap()
        };
        let mut read_buffer = read_buffer.lock();
        let mut read_buffer = read_buffer.to_vec();
        let read_buffer = Arc::new(read_buffer.as_slice());
        self.data.set_buffer_ref(read_buffer.clone());
        println!("requester receive RAW - {:02x?}\n", &read_buffer[0..len]);

        Ok(len)
    }

    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        self.data.set_buffer_ref(buffer.clone());
        log::info!("requester send    RAW - {:02x?}\n", &buffer);

        let mut responder = self.responder.lock();
        let mut responder = responder.deref_mut();

        {
            let mut device_io = responder.common.device_io.lock();
            let device_io = device_io.deref_mut();
            log::info!("0:{:?}", buffer);
            device_io.send(buffer).await;
        }

        let mut raw_packet = [0u8; RECEIVER_BUFFER_SIZE];

        if responder
            .process_message(false, 0, &mut raw_packet)
            .await
            .is_err()
        {
            return Err(SPDM_STATUS_ERROR_PEER);
        }
        Ok(())
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub struct SpdmDeviceIoReceve {
    data: Arc<SharedBuffer>,
    fuzzdata: Arc<[u8]>,
}

impl SpdmDeviceIoReceve {
    pub fn new(data: Arc<SharedBuffer>, fuzzdata: Arc<[u8]>) -> Self {
        SpdmDeviceIoReceve { data, fuzzdata }
    }
}

#[async_trait]
impl SpdmDeviceIo for SpdmDeviceIoReceve {
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

pub struct FakeSpdmDeviceIoReceve {
    pub data: Arc<SharedBuffer>,
}

impl FakeSpdmDeviceIoReceve {
    pub fn new(data: Arc<SharedBuffer>) -> Self {
        FakeSpdmDeviceIoReceve { data }
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
        println!("responder receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        self.data.set_buffer_ref(buffer.clone());
        println!("responder send    RAW - {:02x?}\n", &buffer);
        Ok(())
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub struct SharedBuffer {
    queue: Arc<Mutex<VecDeque<u8>>>,
}

impl SharedBuffer {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        SharedBuffer {
            queue: Arc::new(Mutex::new(VecDeque::<u8>::new())),
        }
    }

    pub fn set_buffer_ref(&self, b: Arc<&[u8]>) {
        log::info!("send    {:02x?}\n", b);
        let mut queue = self.queue.lock();
        let queue = queue.deref_mut();
        for i in *b {
            queue.push_back(*i);
        }
    }

    pub fn set_buffer(&self, b: Arc<[u8]>) {
        log::info!("send    {:02x?}\n", b);
        let mut queue = self.queue.lock();
        let queue = queue.deref_mut();
        for i in &*b {
            queue.push_back(*i);
        }
    }

    pub fn get_buffer(&self, b: Arc<Mutex<&mut [u8]>>) -> usize {
        let mut queue = self.queue.lock();
        let queue = queue.deref_mut();
        let mut len = 0usize;
        let mut b = b.lock();
        let b = b.deref_mut();
        for i in b.iter_mut() {
            if queue.is_empty() {
                break;
            }
            *i = queue.pop_front().unwrap();
            len += 1;
        }
        log::info!("recieve {:02x?}\n", &b[..len]);
        len
    }
}

#[test]
fn test_fake_device_io() {
    let future = async {
        let buffer = SharedBuffer::new();
        let buffer = Arc::new(buffer);
        let mut server = FakeSpdmDeviceIoReceve::new(buffer.clone());
        let mut client = FakeSpdmDeviceIoReceve::new(buffer.clone());
        const SEND_DATA: &[u8] = &[1, 2];
        client.send(Arc::new(SEND_DATA)).await.unwrap();
        let mut rev = [0u8, 64];
        server
            .receive(Arc::new(Mutex::new(&mut rev)), ST1)
            .await
            .unwrap();
        assert_eq!(rev[..=1], *SEND_DATA)
    };
    executor::block_on(future);
}

pub struct TestTransportEncap;
#[async_trait]
impl SpdmTransportEncap for TestTransportEncap {
    async fn encap(
        &mut self,
        spdm_buffer: Arc<&[u8]>,
        transport_buffer: Arc<Mutex<&mut [u8]>>,
        secured_message: bool,
    ) -> SpdmResult<usize> {
        // format
        //   secure_message u8
        let mut transport_buffer = transport_buffer.lock();
        let len = spdm_buffer.len();
        transport_buffer[0] = secured_message as u8;

        if transport_buffer.len() < len + 1 {
            return Err(SPDM_STATUS_DECAP_FAIL);
        }
        transport_buffer[1..(1 + len)].copy_from_slice(&spdm_buffer[..]);
        Ok(1 + len)
    }

    async fn decap(
        &mut self,
        transport_buffer: Arc<&[u8]>,
        spdm_buffer: Arc<Mutex<&mut [u8]>>,
    ) -> SpdmResult<(usize, bool)> {
        let mut spdm_buffer = spdm_buffer.lock();
        let spdm_buffer_len = transport_buffer.len() - 1;
        let secure_message = if transport_buffer[0] == 0 {
            false
        } else {
            true
        };
        spdm_buffer[0..spdm_buffer_len].copy_from_slice(&transport_buffer[1..]);
        Ok((spdm_buffer_len, secure_message))
    }

    async fn encap_app(
        &mut self,
        spdm_buffer: Arc<&[u8]>,
        app_buffer: Arc<Mutex<&mut [u8]>>,
        _is_app_message: bool,
    ) -> SpdmResult<usize> {
        let mut app_buffer = app_buffer.lock();
        app_buffer[0..spdm_buffer.len()].copy_from_slice(&spdm_buffer);
        Ok(spdm_buffer.len())
    }

    async fn decap_app(
        &mut self,
        app_buffer: Arc<&[u8]>,
        spdm_buffer: Arc<Mutex<&mut [u8]>>,
    ) -> SpdmResult<(usize, bool)> {
        let mut spdm_buffer = spdm_buffer.lock();
        spdm_buffer[0..app_buffer.len()].copy_from_slice(&app_buffer);
        Ok((app_buffer.len(), false))
    }
    fn get_sequence_number_count(&mut self) -> u8 {
        todo!()
    }

    fn get_max_random_count(&mut self) -> u16 {
        todo!()
    }
}

pub struct TestSpdmDeviceIo {
    pub rx: Arc<Mutex<VecDeque<u8>>>,
    pub tx: Arc<Mutex<VecDeque<u8>>>,
}

impl TestSpdmDeviceIo {
    pub fn new(rx: Arc<Mutex<VecDeque<u8>>>, tx: Arc<Mutex<VecDeque<u8>>>) -> Self {
        Self { rx, tx }
    }
}

#[async_trait]
impl SpdmDeviceIo for TestSpdmDeviceIo {
    async fn receive(
        &mut self,
        out_buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        let mut rx = self.rx.lock();
        if (rx.len() < 4) {
            return Err(0);
        }
        // Length 4 bytes
        let length_buf: Vec<u8> = rx.drain(0..4).collect();
        let length =
            u32::from_le_bytes([length_buf[0], length_buf[1], length_buf[2], length_buf[3]]);
        let length = length as usize;
        // Data length bytes
        let mut out_buffer = out_buffer.lock();
        if out_buffer.len() < length {
            return Err(0);
        }
        for index in 0..length {
            out_buffer[index] = rx.pop_front().unwrap();
        }
        println!("RECV RAW - {:02x?}", &out_buffer[..length]);
        Ok(length)
    }
    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        {
            let mut tx = self.tx.lock();
            let length = buffer.len() as u32;
            tx.extend(length.to_le_bytes());
            tx.extend(buffer.iter());
        }
        println!("SEND RAW - {:02x?}", &buffer);
        Ok(())
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub fn test_header_generater_callback(secure: u8, spdm_msg: &[u8]) -> VecDeque<u8> {
    // This function is used to generate the header
    // Note: The same method as device_io and transport encap should be use
    //       Current implementation is for TestDeviceIo and TestTransportEncap
    let mut ret = VecDeque::new();
    let length = (spdm_msg.len() + 1) as u32;
    ret.extend(length.to_le_bytes());
    ret.push_back(secure);
    ret.extend(spdm_msg);
    ret
}

#[test]
fn test_test_device_io() {
    let rx = Arc::new(Mutex::new(VecDeque::<u8>::new()));
    let tx = Arc::new(Mutex::new(VecDeque::<u8>::new()));
    let rx_shared = Arc::clone(&rx);
    let tx_shared = Arc::clone(&tx);
    let future = async {
        let mut server = TestSpdmDeviceIo::new(rx, tx);
        let _ = server.send(Arc::new(b"hello")).await;
    };
    executor::block_on(future);

    let tx = tx_shared.lock();
    let res = tx.as_slices();
    assert_eq!(
        res.0,
        [0x05, 0x00, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f]
    )
}

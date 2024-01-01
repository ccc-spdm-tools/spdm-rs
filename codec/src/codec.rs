// Taken from rustls <https://github.com/rustls/rustls>
//
// Copyright (c) 2016 Joe Birr-Pixton and rustls project contributors
// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[cfg(feature = "alloc")]
extern crate alloc;

use core::{fmt::Debug, mem};

/// Read from a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    offs: usize,
}

impl<'a> Reader<'a> {
    pub fn init(bytes: &[u8]) -> Reader {
        Reader {
            buf: bytes,
            offs: 0,
        }
    }

    pub fn rest(&mut self) -> &[u8] {
        let ret = &self.buf[self.offs..];
        self.offs = self.buf.len();
        ret
    }

    pub fn take(&mut self, len: usize) -> Option<&[u8]> {
        if self.left() < len {
            return None;
        }

        let current = self.offs;
        self.offs += len;
        Some(&self.buf[current..current + len])
    }

    pub fn any_left(&self) -> bool {
        self.offs < self.buf.len()
    }

    pub fn left(&self) -> usize {
        self.buf.len() - self.offs
    }

    pub fn used(&self) -> usize {
        self.offs
    }

    pub fn sub(&mut self, len: usize) -> Option<Reader> {
        self.take(len).map(Reader::init)
    }
}

impl AsRef<[u8]> for Reader<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[self.offs..]
    }
}

/// Write to a byte slice.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    offs: usize,
}

impl<'a> Writer<'a> {
    pub fn init(bytes: &mut [u8]) -> Writer {
        Writer {
            buf: bytes,
            offs: 0,
        }
    }

    pub fn clear(&mut self) {
        self.offs = 0;
    }

    pub fn extend_from_slice(&mut self, value: &[u8]) -> Option<usize> {
        if self.left() < value.len() {
            return None;
        }
        let added = value.len();
        for (i, v) in value.iter().enumerate().take(added) {
            self.buf[self.offs + i] = *v;
        }
        self.offs += added;
        Some(added)
    }

    pub fn push(&mut self, value: u8) -> Option<u8> {
        if self.left() < 1 {
            return None;
        }
        self.buf[self.offs] = value;
        self.offs += 1;
        Some(value)
    }

    pub fn left(&self) -> usize {
        self.buf.len() - self.offs
    }

    pub fn left_slice(&self) -> &[u8] {
        &self.buf[self.offs..]
    }

    pub fn mut_left_slice(&mut self) -> &mut [u8] {
        &mut self.buf[self.offs..]
    }

    pub fn used(&self) -> usize {
        self.offs
    }

    pub fn used_slice(&self) -> &[u8] {
        &self.buf[..self.offs]
    }

    pub fn mut_used_slice(&mut self) -> &mut [u8] {
        &mut self.buf[..self.offs]
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EncodeErr;

/// Things we can encode and read from a Reader.
pub trait Codec: Debug + Sized {
    /// Encode yourself by appending onto `bytes`.
    /// Return Ok(encoded size) or Err(())
    fn encode(&self, bytes: &mut Writer) -> Result<usize, EncodeErr>;

    /// Decode yourself by fiddling with the `Reader`.
    /// Return Some if it worked, None if not.
    fn read(_: &mut Reader) -> Option<Self>;

    /// Read one of these from the front of `bytes` and
    /// return it.
    fn read_bytes(bytes: &[u8]) -> Option<Self> {
        let mut rd = Reader::init(bytes);
        Self::read(&mut rd)
    }

    #[cfg(feature = "alloc")]
    /// Read count T's and returns Vec<T>
    /// count: the number of T wants to read.
    fn read_vec<T: Codec>(reader: &mut Reader, count: usize) -> Option<alloc::vec::Vec<T>> {
        let mut data = alloc::vec::Vec::new();
        for _ in 0..count {
            let t = T::read(reader)?;
            data.push(t)
        }
        Some(data)
    }
}

#[cfg(feature = "alloc")]
impl<T: Codec + Copy> Codec for alloc::vec::Vec<T> {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, EncodeErr> {
        let used = bytes.used();
        for t in self.iter() {
            let _ = t.encode(bytes)?;
        }
        Ok(bytes.used() - used)
    }

    fn read(_reader: &mut Reader) -> Option<Self> {
        // Not support can't known the length
        panic!("Should not call this API for reading vec. Use read_vec instead.")
    }
}

// Encoding functions.
pub fn decode_u8(bytes: &[u8]) -> Option<u8> {
    Some(bytes[0])
}

impl Codec for u8 {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, EncodeErr> {
        bytes.push(*self).ok_or(EncodeErr)?;
        Ok(1)
    }
    fn read(r: &mut Reader) -> Option<u8> {
        r.take(1).and_then(decode_u8)
    }
}

pub fn put_u16(v: u16, out: &mut [u8]) {
    out[0] = v as u8;
    out[1] = (v >> 8) as u8;
}

pub fn decode_u16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from(bytes[0]) | (u16::from(bytes[1]) << 8))
}

impl Codec for u16 {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, EncodeErr> {
        let mut b16 = [0u8; 2];
        put_u16(*self, &mut b16);
        bytes.extend_from_slice(&b16).ok_or(EncodeErr)?;
        Ok(2)
    }

    fn read(r: &mut Reader) -> Option<u16> {
        r.take(2).and_then(decode_u16)
    }
}

// Make a distinct type for u24, even though it's a u32 underneath
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, Default)]
pub struct u24(u32);

impl u24 {
    pub fn new(v: u32) -> u24 {
        assert_eq!(v >> 24, 0);
        u24(v)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    fn decode(bytes: &[u8]) -> Option<u24> {
        Some(u24(u32::from(bytes[0])
            | (u32::from(bytes[1]) << 8)
            | (u32::from(bytes[2]) << 16)))
    }
}

impl Codec for u24 {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, EncodeErr> {
        bytes.push(self.0 as u8).ok_or(EncodeErr)?;
        bytes.push((self.0 >> 8) as u8).ok_or(EncodeErr)?;
        bytes.push((self.0 >> 16) as u8).ok_or(EncodeErr)?;
        Ok(3)
    }

    fn read(r: &mut Reader) -> Option<u24> {
        r.take(3).and_then(u24::decode)
    }
}

pub fn decode_u32(bytes: &[u8]) -> Option<u32> {
    Some(
        u32::from(bytes[0])
            | (u32::from(bytes[1]) << 8)
            | (u32::from(bytes[2]) << 16)
            | (u32::from(bytes[3]) << 24),
    )
}

impl Codec for u32 {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, EncodeErr> {
        bytes.push(*self as u8).ok_or(EncodeErr)?;
        bytes.push((*self >> 8) as u8).ok_or(EncodeErr)?;
        bytes.push((*self >> 16) as u8).ok_or(EncodeErr)?;
        bytes.push((*self >> 24) as u8).ok_or(EncodeErr)?;
        Ok(4)
    }

    fn read(r: &mut Reader) -> Option<u32> {
        r.take(4).and_then(decode_u32)
    }
}

pub fn put_u64(v: u64, bytes: &mut [u8]) {
    bytes[0] = v as u8;
    bytes[1] = (v >> 8) as u8;
    bytes[2] = (v >> 16) as u8;
    bytes[3] = (v >> 24) as u8;
    bytes[4] = (v >> 32) as u8;
    bytes[5] = (v >> 40) as u8;
    bytes[6] = (v >> 48) as u8;
    bytes[7] = (v >> 56) as u8;
}

pub fn decode_u64(bytes: &[u8]) -> Option<u64> {
    Some(
        u64::from(bytes[0])
            | (u64::from(bytes[1]) << 8)
            | (u64::from(bytes[2]) << 16)
            | (u64::from(bytes[3]) << 24)
            | (u64::from(bytes[4]) << 32)
            | (u64::from(bytes[5]) << 40)
            | (u64::from(bytes[6]) << 48)
            | (u64::from(bytes[7]) << 56),
    )
}

impl Codec for u64 {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, EncodeErr> {
        let mut b64 = [0u8; 8];
        put_u64(*self, &mut b64);
        bytes.extend_from_slice(&b64).ok_or(EncodeErr)?;
        Ok(8)
    }

    fn read(r: &mut Reader) -> Option<u64> {
        r.take(8).and_then(decode_u64)
    }
}

impl Codec for u128 {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, EncodeErr> {
        bytes
            .extend_from_slice(&u128::to_le_bytes(*self))
            .ok_or(EncodeErr)?;
        Ok(16)
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let mut v = [0u8; mem::size_of::<u128>()];
        v.copy_from_slice(r.take(mem::size_of::<u128>())?);

        Some(u128::from_le_bytes(v))
    }
}

impl<T: Codec + Copy + Default, const N: usize> Codec for [T; N] {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, EncodeErr> {
        let used = bytes.used();
        for d in self.iter() {
            let _ = d.encode(bytes)?;
        }
        Ok(bytes.used() - used)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let mut target = [T::default(); N];
        for t in target.iter_mut() {
            *t = T::read(reader)?;
        }

        Some(target)
    }
}

#[cfg(test)]
mod tests {
    use crate::codec::Codec;
    use crate::codec::{Reader, Writer};
    use crate::u24;

    #[test]
    fn test_u128() {
        let u8_slice = &mut [0u8; 16];
        {
            let mut writer = Writer::init(u8_slice);
            let value = 0x1234567890FFFEFEFFFFFE1234567890u128;
            assert_eq!(value.encode(&mut writer), Ok(16));
        }
        let mut ser_data = [
            0x12u8, 0x34, 0x56, 0x78, 0x90, 0xFF, 0xFE, 0xFE, 0xFF, 0xFF, 0xFE, 0x12, 0x34, 0x56,
            0x78, 0x90,
        ];
        ser_data.reverse();

        let mut reader = Reader::init(u8_slice);
        assert_eq!(16, reader.left());
        assert_eq!(u8_slice, &ser_data);
        assert_eq!(
            u128::read(&mut reader).unwrap(),
            0x1234567890FFFEFEFFFFFE1234567890u128
        );
    }

    #[test]
    fn test_u64() {
        let u8_slice = &mut [0u8; 8];
        u8_slice[1] = 1;
        {
            let mut writer = Writer::init(u8_slice);
            let value = 100u64;
            assert_eq!(value.encode(&mut writer), Ok(8));
        }

        let mut reader = Reader::init(u8_slice);
        assert_eq!(8, reader.left());
        assert_eq!(u64::read(&mut reader).unwrap(), 100);
    }
    #[test]
    fn test_u32() {
        let u8_slice = &mut [0u8; 4];
        let mut witer = Writer::init(u8_slice);
        let value = 100u32;
        assert_eq!(value.encode(&mut witer), Ok(4));

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(u32::read(&mut reader).unwrap(), 100);
    }
    #[test]
    fn test_u16() {
        let u8_slice = &mut [0u8; 2];
        let mut witer = Writer::init(u8_slice);
        let value = 10u16;
        assert_eq!(value.encode(&mut witer), Ok(2));

        let mut reader = Reader::init(u8_slice);
        assert_eq!(2, reader.left());
        assert_eq!(u16::read(&mut reader).unwrap(), 10);
    }
    #[test]
    fn test_u24() {
        let u8_slice = &mut [0u8; 3];
        let mut witer = Writer::init(u8_slice);
        let value = u24::new(100);
        assert_eq!(value.encode(&mut witer), Ok(3));
        let mut reader = Reader::init(u8_slice);
        assert_eq!(3, reader.left());
        assert_eq!(u24::read(&mut reader).unwrap().0, u24::new(100).0);
    }
    #[test]
    #[should_panic]
    fn test_u24_max_size() {
        let _ = u24::new(1 << 24);
    }
    #[test]
    fn test_u8() {
        let u8_slice = &mut [0u8; 4];
        let mut witer = Writer::init(u8_slice);
        let value = 100u8;
        assert_eq!(value.encode(&mut witer), Ok(1));
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(u8::read(&mut reader).unwrap(), 100);
    }
    #[test]
    fn test_case0_rest() {
        let u8_slice = &mut [0u8; 4];
        let mut witer = Writer::init(u8_slice);
        let value = 0xAA5555AAu32;
        assert_eq!(value.encode(&mut witer), Ok(4));
        let mut reader = Reader::init(u8_slice);
        let rust_ret = reader.rest();
        assert_eq!(rust_ret[0], 0xAA);
        assert_eq!(rust_ret[1], 0x55);
        assert_eq!(rust_ret[2], 0x55);
        assert_eq!(rust_ret[3], 0xAA);
    }
    #[test]
    fn test_case0_any_left() {
        let u8_slice = &mut [0u8; 4];
        let reader = Reader {
            buf: u8_slice,
            offs: 0,
        };
        assert_eq!(reader.any_left(), true);
    }
    #[test]
    fn test_case1_any_left() {
        let u8_slice = &mut [0u8; 4];
        let reader = Reader {
            buf: u8_slice,
            offs: 4,
        };
        assert_eq!(reader.any_left(), false);
    }
    #[test]
    fn test_case0_read_bytes() {
        let u8_slice = &mut [0u8; 4];
        let mut witer = Writer::init(u8_slice);
        let value = 0xAA5555AAu32;
        assert_eq!(value.encode(&mut witer), Ok(4));
        assert_eq!(u32::read_bytes(u8_slice).unwrap(), 0xAA5555AAu32);
    }
    #[test]
    fn test_case0_sub() {
        let u8_slice = &mut [100u8; 4];
        let mut reader = Reader {
            buf: u8_slice,
            offs: 4,
        };
        assert_eq!(reader.sub(4).is_none(), true);
    }

    #[test]
    fn test_case0_array() {
        let u8_slice = &mut [0x0u8; 2];
        let value = [0x5au8; 2];
        let writer = &mut Writer::init(u8_slice);
        value.encode(writer).unwrap();
        let reader = &mut Reader::init(u8_slice);
        assert_eq!(value, <[u8; 2]>::read(reader).unwrap());
    }
}

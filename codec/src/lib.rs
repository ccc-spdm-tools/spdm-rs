// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![forbid(unsafe_code)]
#![no_std]

pub mod codec;
pub use crate::codec::*;

#[allow(unused_macros)]
#[macro_use]
pub mod macros;

#[cfg(test)]
mod tests {

    use crate::{Codec, Reader, Writer};

    enum_builder! {
        @U8
        EnumName: TestEnum;
        EnumVal{
            Value1 => 0x1,
            Value2 => 0x2
        }
    }

    #[test]
    fn it_works() {
        let u8_slice = &[1u8; 2];
        let mut r = Reader::init(u8_slice);
        assert_eq!(TestEnum::Value1, TestEnum::read(&mut r).unwrap());
        assert_eq!(2 + 2, 4);
    }
}

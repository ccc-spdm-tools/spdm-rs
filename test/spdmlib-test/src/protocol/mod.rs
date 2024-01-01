// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

// The naming rules are ignored here to align with spdmspec
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use codec::Codec;

pub mod algorithm;
pub mod capability;
pub mod certificate;
pub mod challenge;
pub mod digest;
pub mod measurement;
pub mod version;

#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    GET_VERSION(version::GET_VERSION),
    VERSION(version::VERSION),
    GET_CAPABILITIES(capability::GET_CAPABILITIES),
    CAPABILITIES(capability::CAPABILITIES),
    NEGOTIATE_ALGORITHMS(algorithm::NEGOTIATE_ALGORITHMS),
    ALGORITHMS(algorithm::ALGORITHMS),
    GET_CERTIFICATE(certificate::GET_CERTIFICATE),
    CERTIFICATE(certificate::CERTIFICATE),
    CHALLENGE(challenge::CHALLENGE),
    CHALLENGE_AUTH(challenge::CHALLENGE_AUTH),
    GET_DIGESTS(digest::GET_DIGESTS),
    DIGESTS(digest::DIGESTS),
    GET_MEASUREMENTS(measurement::GET_MEASUREMENTS),
    MEASUREMENTS(measurement::MEASUREMENTS),
}

impl Codec for Message {
    fn encode(&self, bytes: &mut codec::Writer) -> Result<usize, codec::EncodeErr> {
        match self {
            Message::GET_VERSION(m) => m.encode(bytes),
            Message::VERSION(m) => m.encode(bytes),
            Message::GET_CAPABILITIES(m) => m.encode(bytes),
            Message::CAPABILITIES(m) => m.encode(bytes),
            Message::NEGOTIATE_ALGORITHMS(m) => m.encode(bytes),
            Message::ALGORITHMS(m) => m.encode(bytes),
            Message::GET_CERTIFICATE(m) => m.encode(bytes),
            Message::CERTIFICATE(m) => m.encode(bytes),
            Message::CHALLENGE(m) => m.encode(bytes),
            Message::CHALLENGE_AUTH(m) => m.encode(bytes),
            Message::GET_DIGESTS(m) => m.encode(bytes),
            Message::DIGESTS(m) => m.encode(bytes),
            Message::GET_MEASUREMENTS(m) => m.encode(bytes),
            Message::MEASUREMENTS(m) => m.encode(bytes),
        }
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let header = reader.rest();
        if header.len() < 4 {
            return None;
        }
        let reader = &mut codec::Reader::init(header);
        let RequestResponseCode = header[1];
        match RequestResponseCode {
            0x84 => Some(Message::GET_VERSION(version::GET_VERSION::read(reader)?)),
            0x04 => Some(Message::VERSION(version::VERSION::read(reader)?)),
            0xE1 => Some(Message::GET_CAPABILITIES(
                capability::GET_CAPABILITIES::read(reader)?,
            )),
            0x61 => Some(Message::CAPABILITIES(capability::CAPABILITIES::read(
                reader,
            )?)),
            0xE3 => Some(Message::NEGOTIATE_ALGORITHMS(
                algorithm::NEGOTIATE_ALGORITHMS::read(reader)?,
            )),
            0x63 => Some(Message::ALGORITHMS(algorithm::ALGORITHMS::read(reader)?)),
            0x82 => Some(Message::GET_CERTIFICATE(
                certificate::GET_CERTIFICATE::read(reader)?,
            )),
            0x02 => Some(Message::CERTIFICATE(certificate::CERTIFICATE::read(
                reader,
            )?)),
            _ => panic!("not support type"),
        }
    }
}

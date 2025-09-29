// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

extern crate alloc;
use alloc::boxed::Box;

use crate::crypto::{
    SpdmKemCipherTextExchange, SpdmKemDecap, SpdmKemEncap, SpdmKemEncapKeyExchange,
};
use crate::protocol::{SpdmKemAlgo, SpdmKemEncapKeyStruct};

pub static DEFAULT_DECAP: SpdmKemDecap = SpdmKemDecap {
    generate_key_pair_cb: kem_generate_key_pair,
};

fn kem_generate_key_pair(
    kem_algo: SpdmKemAlgo,
) -> Option<(
    SpdmKemEncapKeyStruct,
    Box<dyn SpdmKemEncapKeyExchange + Send>,
)> {
    unimplemented!()
}

pub static DEFAULT_ENCAP: SpdmKemEncap = SpdmKemEncap {
    new_key_cb: kem_new_key,
};

fn kem_new_key(
    kem_algo: SpdmKemAlgo,
    kem_encap_key: &SpdmKemEncapKeyStruct,
) -> Option<Box<dyn SpdmKemCipherTextExchange + Send>> {
    unimplemented!()
}

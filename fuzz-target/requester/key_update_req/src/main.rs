// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::spdmlib::message::*;
use fuzzlib::{
    spdmlib::common::session::{SpdmSession, SpdmSessionState},
    *,
};
use spdmlib::protocol::*;
use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ops::DerefMut;

async fn fuzz_send_receive_spdm_key_update(data: Arc<Vec<u8>>) {
    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    spdmlib::crypto::hkdf::register(FAKE_HKDF.clone());
    spdmlib::crypto::aead::register(FAKE_AEAD.clone());

    async fn f(fuzzdata: &[u8], key_update_op: SpdmKeyUpdateOperation) {
        let (req_config_info, req_provision_info) = req_create_info();

        let shared_buffer = SharedBuffer::new();

        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(Arc::new(shared_buffer));
        device_io_requester.set_rx(&fuzzdata);
        let device_io_requester = Arc::new(Mutex::new(device_io_requester));

        let mut requester = requester::RequesterContext::new(
            device_io_requester,
            pcidoe_transport_encap,
            req_config_info,
            req_provision_info,
        );
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.session[0] = SpdmSession::new();
        requester.common.session[0].setup(4294836221).unwrap();
        requester.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );

        let mut dhe_secret = SpdmDheFinalKeyStruct::default();
        dhe_secret.data_size = SpdmDheAlgo::SECP_384_R1.get_size();
        requester.common.session[0]
            .set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret)
            .unwrap();
        let digest = [0xFF; SPDM_MAX_HASH_SIZE];
        let digest_struct = SpdmDigestStruct::from(digest.as_ref());
        let _ = requester.common.session[0]
            .generate_data_secret(SpdmVersion::SpdmVersion12, &digest_struct);

        let _ = requester
            .send_receive_spdm_key_update(4294836221, key_update_op)
            .await;
    }

    f(&data, SpdmKeyUpdateOperation::SpdmUpdateAllKeys).await;
    f(&data, SpdmKeyUpdateOperation::SpdmUpdateSingleKey).await;
}

#[cfg(not(feature = "use_libfuzzer"))]
fn main() {
    #[cfg(all(feature = "fuzzlogfile", feature = "fuzz"))]
    flexi_logger::Logger::try_with_str("info")
        .unwrap()
        .log_to_file(
            FileSpec::default()
                .directory("traces")
                .basename("foo")
                .discriminant("Sample4711A")
                .suffix("trc"),
        )
        .print_message()
        .create_symlink("current_run")
        .start()
        .unwrap();

    #[cfg(not(feature = "fuzz"))]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            // Here you can replace the single-step debugging value in the fuzzdata array.
            let fuzzdata = vec![
                0x1, 0x0, 0x2, 0x0, 0x9, 0x0, 0x0, 0x0, 0xfe, 0xff, 0xfe, 0xff, 0x16, 0x0, 0xca,
                0xa7, 0x51, 0x54, 0x4f, 0x61, 0x62, 0xc2, 0x9a, 0x57, 0xb1, 0xb8, 0x69, 0x32, 0x32,
                0x6, 0xf5, 0xaf, 0x4, 0x9c, 0x42, 0x3c,
            ];

            executor::block_on(fuzz_send_receive_spdm_key_update(Arc::new(fuzzdata)));
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            executor::block_on(fuzz_send_receive_spdm_key_update(Arc::new(data)));
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        executor::block_on(fuzz_send_receive_spdm_key_update(Arc::new(data.to_vec())));
    });
}

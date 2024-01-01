// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use async_recursion::async_recursion;
// import commonly used items from the prelude:
use fuzzlib::*;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ops::DerefMut;

async fn run_spdm(spdm: Vec<i32>) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let device_io_responder = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        shared_buffer,
    ))));

    let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let responder = responder::ResponderContext::new(
        device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );

    let shared_buffer = SharedBuffer::new();
    let pcidoe_transport_encap2 = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let device_io_requester = Arc::new(Mutex::new(fake_device_io::FakeSpdmDeviceIo::new(
        Arc::new(shared_buffer),
    )));

    let mut requester = requester::RequesterContext::new(
        device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );
    println!("Run sequence {:?}", &spdm);
    for i in spdm.iter() {
        match i {
            1 => {
                if requester.send_receive_spdm_version().await.is_err() {
                    println!("{:?} error in send_receive_spdm_version", &spdm);
                    return;
                }
            }
            2 => {
                if requester.send_receive_spdm_capability().await.is_err() {
                    println!("{:?} error in send_receive_spdm_capability", &spdm);
                    return;
                }
            }
            3 => {
                if requester.send_receive_spdm_algorithm().await.is_err() {
                    println!("{:?} error in send_receive_spdm_algorithm", &spdm);
                    return;
                }
            }
            4 => {
                if requester.send_receive_spdm_digest(None).await.is_err() {
                    println!("{:?} 4, error in send_receive_spdm_digest", &spdm);
                    return;
                }
            }
            5 => {
                if requester
                    .send_receive_spdm_certificate(None, 0)
                    .await
                    .is_err()
                {
                    println!("{:?} 5, error in send_receive_spdm_certificate", &spdm);
                    return;
                }
            }
            6 => {
                if requester
                    .send_receive_spdm_challenge(
                        0,
                        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                    )
                    .await
                    .is_err()
                {
                    println!("{:?} 6, error in send_receive_spdm_challenge", &spdm);
                    return;
                }
            }
            7 => {
                let mut total_number = 0;
                let mut spdm_measurement_record_structure =
                    SpdmMeasurementRecordStructure::default();
                let mut content_changed = None;
                let mut transcript_meas = None;

                if requester
                    .send_receive_spdm_measurement(
                        None,
                        0,
                        SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                        SpdmMeasurementOperation::SpdmMeasurementRequestAll,
                        &mut content_changed,
                        &mut total_number,
                        &mut spdm_measurement_record_structure,
                        &mut transcript_meas,
                    )
                    .await
                    .is_err()
                {
                    println!("{:?} 7, error in send_receive_spdm_measurement", &spdm);
                    return;
                }
            }
            8 => {
                if requester
                    .send_receive_spdm_key_exchange(
                        0,
                        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                    )
                    .await
                    .is_err()
                {
                    println!("{:?} 8, error in send_receive_spdm_key_exchange", &spdm);
                    return;
                };
            }
            9 => {
                if requester
                    .send_receive_spdm_psk_exchange(
                        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                        None,
                    )
                    .await
                    .is_err()
                {
                    println!("{:?} 9, error in send_receive_spdm_psk_exchange", &spdm);
                    return;
                };
            }
            _ => {}
        }
    }
}

#[async_recursion]
async fn permutation(
    from: Arc<&[i32]>,
    count: usize,
    bool_array: Arc<Mutex<&mut [bool]>>,
    last_vec: Vec<i32>,
) {
    if last_vec.len() == count {
        run_spdm(last_vec).await;
        return;
    }

    for (i, &n) in from.iter().enumerate() {
        let last_vec = {
            let mut bool_array = bool_array.lock();
            let bool_array = bool_array.deref_mut();

            if bool_array[i] {
                continue;
            }

            let mut last_vec = last_vec.clone();
            last_vec.push(n);
            bool_array[i] = true;
            last_vec
        };

        permutation(from.clone(), count, bool_array.clone(), last_vec).await;

        {
            let mut bool_array = bool_array.lock();
            let bool_array = bool_array.deref_mut();
            bool_array[i] = false;
        }
    }
}

fn main() {
    let nums: &[i32] = &[1, 2, 3, 4, 5, 6, 7, 8, 9];
    executor::block_on(permutation(
        Arc::new(nums),
        nums.len(),
        Arc::new(Mutex::new(&mut vec![false; nums.len()])),
        Vec::new(),
    ));
}

// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

mod time_callbacks;

pub use time_callbacks::SpdmTime;

use conquer_once::spin::OnceCell;

static TIME_INSTANCE: OnceCell<SpdmTime> = OnceCell::uninit();

static DEFAULT: SpdmTime = SpdmTime {
    sleep_cb: |_: usize| unimplemented!(),
};

pub fn register(context: SpdmTime) -> bool {
    TIME_INSTANCE.try_init_once(|| context).is_ok()
}

pub fn sleep(us: usize) {
    (TIME_INSTANCE
        .try_get_or_init(|| DEFAULT.clone())
        .ok()
        .unwrap()
        .sleep_cb)(us)
}

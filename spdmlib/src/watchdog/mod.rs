// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

mod watchdog_callbacks;

pub use watchdog_callbacks::SpdmWatchDog;

use conquer_once::spin::OnceCell;

static WATCHDOG_INSTANCE: OnceCell<SpdmWatchDog> = OnceCell::uninit();

static DEFAULT: SpdmWatchDog = SpdmWatchDog {
    start_watchdog_cb: |_session_id: u32, _seconds: u16| unimplemented!(),
    stop_watchdog_cb: |_session_id: u32| unimplemented!(),
    reset_watchdog_cb: |_session_id: u32| unimplemented!(),
};

pub fn register(context: SpdmWatchDog) -> bool {
    WATCHDOG_INSTANCE.try_init_once(|| context).is_ok()
}

pub fn start_watchdog(session_id: u32, seconds: u16) {
    (WATCHDOG_INSTANCE
        .try_get_or_init(|| DEFAULT.clone())
        .ok()
        .unwrap()
        .start_watchdog_cb)(session_id, seconds)
}

pub fn stop_watchdog(session_id: u32) {
    (WATCHDOG_INSTANCE
        .try_get_or_init(|| DEFAULT.clone())
        .ok()
        .unwrap()
        .stop_watchdog_cb)(session_id)
}

pub fn reset_watchdog(session_id: u32) {
    (WATCHDOG_INSTANCE
        .try_get_or_init(|| DEFAULT.clone())
        .ok()
        .unwrap()
        .reset_watchdog_cb)(session_id)
}

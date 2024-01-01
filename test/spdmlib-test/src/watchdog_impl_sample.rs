// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use spdmlib::watchdog::SpdmWatchDog;

fn start_watchdog(session_id: u32, seconds: u16) {
    if seconds == 0 {
        log::info!("seconds is 0, watch dog is set to idle all the time.");
    }
    log::info!(
        "Starting watch dog with session id: {:X?}, seconds: {:X?}",
        session_id,
        seconds
    );
}

fn stop_watchdog(session_id: u32) {
    log::info!("Stoping watch dog with session id: {:X?}", session_id);
}

fn reset_watchdog(session_id: u32) {
    log::info!("Resetting watch dog with session id: {:X?}", session_id);
}

pub fn init_watchdog() {
    spdmlib::watchdog::register(SpdmWatchDog {
        start_watchdog_cb: start_watchdog,
        stop_watchdog_cb: stop_watchdog,
        reset_watchdog_cb: reset_watchdog,
    });
}

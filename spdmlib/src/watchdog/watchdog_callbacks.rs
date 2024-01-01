// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[derive(Clone)]
pub struct SpdmWatchDog {
    pub start_watchdog_cb: fn(session_id: u32, seconds: u16),
    pub stop_watchdog_cb: fn(session_id: u32),
    pub reset_watchdog_cb: fn(session_id: u32),
}

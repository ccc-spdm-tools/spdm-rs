// @file
//
// Copyright (c) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0 or MIT
//

#![cfg_attr(any(target_os = "uefi", target_os = "none"), no_std)]

mod executor;
use crate::executor::*;
use core::future::Future;
extern crate alloc;
use alloc::boxed::Box;
use core::task::Poll;

pub fn run<T>(future: impl Future<Output = T> + 'static + Send) -> Poll<T>
where
    T: Send + 'static,
{
    DEFAULT_EXECUTOR.lock().run(Box::pin(future))
}

pub fn block_on<T>(future: impl Future<Output = T> + 'static + Send) -> T
where
    T: Send + 'static,
{
    DEFAULT_EXECUTOR.lock().block_on(Box::pin(future))
}

pub fn add_task<T>(future: impl Future<Output = T> + 'static + Send)
where
    T: Send + 'static,
{
    DEFAULT_EXECUTOR.lock().add_task(Box::pin(future))
}

// output: left?
pub fn poll_tasks() -> bool {
    DEFAULT_EXECUTOR.lock().poll_tasks()
}

pub fn active_tasks_count() -> usize {
    DEFAULT_EXECUTOR.lock().active_tasks_count()
}

// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

extern crate alloc;
use alloc::boxed::Box;
use core::{future::Future, pin::Pin};

// Run async task
pub fn block_on<T>(future: Pin<Box<dyn Future<Output = T> + 'static + Send>>) -> T
where
    T: Send + 'static,
{
    #[cfg(feature = "is_sync")]
    compile_error!("block_on function is not available when feature is `is_sync`");

    #[cfg(all(feature = "async-executor", feature = "async-tokio"))]
    compile_error!("features `async-executor` and `async-tokio` are mutually exclusive");

    if cfg!(feature = "async-executor") {
        executor::block_on(future)
    } else if cfg!(feature = "async-tokio") {
        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(future)
    } else {
        panic!("Calling block_on require one of `async-executor` or `async-tokio` is enabled!");
    }
}

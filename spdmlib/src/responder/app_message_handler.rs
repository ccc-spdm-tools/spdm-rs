// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::Writer;
use conquer_once::spin::OnceCell;

use crate::error::SpdmResult;
use crate::responder::ResponderContext;

type DispatchSecuredAppMessageCbType = for<'a> fn(
    &mut ResponderContext,
    u32,
    &[u8],
    usize,
    &'a mut Writer,
) -> (SpdmResult, Option<&'a [u8]>);

#[derive(Clone)]
pub struct SpdmAppMessageHandler {
    pub dispatch_secured_app_message_cb: DispatchSecuredAppMessageCbType,
}

static SPDM_APP_MESSAGE_HANDLER: OnceCell<SpdmAppMessageHandler> = OnceCell::uninit();

static DEFAULT: SpdmAppMessageHandler = SpdmAppMessageHandler {
    dispatch_secured_app_message_cb: |_ctx: &mut ResponderContext,
                                      _session_id: u32,
                                      _app_buffer: &[u8],
                                      _app_handle: usize,
                                      _writer: &mut Writer|
     -> (SpdmResult, Option<&[u8]>) { unimplemented!() },
};

#[allow(dead_code)]
pub fn register(context: SpdmAppMessageHandler) -> bool {
    SPDM_APP_MESSAGE_HANDLER.try_init_once(|| context).is_ok()
}

pub fn dispatch_secured_app_message_cb<'a>(
    ctx: &mut ResponderContext,
    session_id: u32,
    app_buffer: &[u8],
    app_handle: usize, // interpreted/managed by User
    writer: &'a mut Writer,
) -> (SpdmResult, Option<&'a [u8]>) {
    (SPDM_APP_MESSAGE_HANDLER
        .try_get_or_init(|| DEFAULT.clone())
        .unwrap_or(&DEFAULT)
        .dispatch_secured_app_message_cb)(ctx, session_id, app_buffer, app_handle, writer)
}

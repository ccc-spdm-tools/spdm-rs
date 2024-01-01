// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Writer};
use conquer_once::spin::OnceCell;
use spdmlib::{
    error::{
        SpdmResult, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_INVALID_MSG_FIELD,
        SPDM_STATUS_INVALID_STATE_LOCAL,
    },
    message::{
        VendorDefinedReqPayloadStruct, VendorDefinedRspPayloadStruct,
        MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE,
    },
};

use crate::pci_tdisp::{
    InterfaceId, ReqBindP2PStreamRequest, RspBindP2PStreamResponse, TdispErrorCode,
    TdispMessageHeader, TdispRequestResponseCode, TdispVersion,
};

use super::pci_tdisp_rsp_tdisp_error::write_error;

static PCI_TDISP_DEVICE_BING_P2P_STREAM_INSTANCE: OnceCell<PciTdispDeviceBindP2pStream> =
    OnceCell::uninit();

#[derive(Clone)]
pub struct PciTdispDeviceBindP2pStream {
    pub pci_tdisp_device_bind_p2p_stream_cb: fn(
        //IN
        vdm_handle: usize,
        p2p_stream_id: u8,
        //OUT
        interface_id: &mut InterfaceId,
        tdisp_error_code: &mut Option<TdispErrorCode>,
    ) -> SpdmResult,
}

pub fn register(context: PciTdispDeviceBindP2pStream) -> bool {
    PCI_TDISP_DEVICE_BING_P2P_STREAM_INSTANCE
        .try_init_once(|| context)
        .is_ok()
}

static UNIMPLETEMTED: PciTdispDeviceBindP2pStream = PciTdispDeviceBindP2pStream {
    pci_tdisp_device_bind_p2p_stream_cb: |//IN
                                          _vdm_handle: usize,
                                          _p2p_stream_id: u8,
                                          //OUT
                                          _interface_id: &mut InterfaceId,
                                          _tdisp_error_code: &mut Option<TdispErrorCode>|
     -> SpdmResult { unimplemented!() },
};

pub(crate) fn pci_tdisp_device_bind_p2p_stream(
    //IN
    vdm_handle: usize,
    p2p_stream_id: u8,
    //OUT
    interface_id: &mut InterfaceId,
    tdisp_error_code: &mut Option<TdispErrorCode>,
) -> SpdmResult {
    (PCI_TDISP_DEVICE_BING_P2P_STREAM_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
        .pci_tdisp_device_bind_p2p_stream_cb)(
        vdm_handle,
        p2p_stream_id,
        interface_id,
        tdisp_error_code,
    )
}

pub(crate) fn pci_tdisp_rsp_bind_p2p_stream(
    vdm_handle: usize,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    let req_bind_p2_pstream_request = ReqBindP2PStreamRequest::read_bytes(
        &vendor_defined_req_payload_struct.vendor_defined_req_payload
            [..vendor_defined_req_payload_struct.req_length as usize],
    )
    .ok_or(SPDM_STATUS_INVALID_MSG_FIELD)?;

    let mut interface_id = InterfaceId::default();
    let mut tdisp_error_code = None;

    pci_tdisp_device_bind_p2p_stream(
        vdm_handle,
        req_bind_p2_pstream_request.p2p_stream_id,
        &mut interface_id,
        &mut tdisp_error_code,
    )?;

    let mut vendor_defined_rsp_payload_struct = VendorDefinedRspPayloadStruct {
        rsp_length: 0,
        vendor_defined_rsp_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
    };

    if let Some(tdisp_error_code) = tdisp_error_code {
        let len = write_error(
            vdm_handle,
            tdisp_error_code,
            0,
            &[],
            &mut vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload,
        )?;
        vendor_defined_rsp_payload_struct.rsp_length = len as u16;
        return Ok(vendor_defined_rsp_payload_struct);
    }

    let mut writer =
        Writer::init(&mut vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload);

    let cnt = RspBindP2PStreamResponse {
        message_header: TdispMessageHeader {
            interface_id,
            message_type: TdispRequestResponseCode::BIND_P2P_STREAM_RESPONSE,
            tdisp_version: TdispVersion {
                major_version: 1,
                minor_version: 0,
            },
        },
    }
    .encode(&mut writer)
    .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    if cnt > u16::MAX as usize {
        Err(SPDM_STATUS_INVALID_STATE_LOCAL)
    } else {
        vendor_defined_rsp_payload_struct.rsp_length = cnt as u16;
        Ok(vendor_defined_rsp_payload_struct)
    }
}

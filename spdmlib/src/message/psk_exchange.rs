// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common;
use crate::common::opaque::{SpdmOpaqueStruct, MAX_SPDM_OPAQUE_SIZE};
use crate::common::spdm_codec::SpdmCodec;
use crate::config::{MAX_SPDM_PSK_CONTEXT_SIZE, MAX_SPDM_PSK_HINT_SIZE};
use crate::error::{SpdmStatus, SPDM_STATUS_BUFFER_FULL};
use crate::protocol::{
    SpdmDigestStruct, SpdmMeasurementSummaryHashType, SpdmPskContextStruct, SpdmPskHintStruct,
    SpdmResponseCapabilityFlags,
};
use codec::{Codec, Reader, Writer};

#[derive(Debug, Clone, Default)]
pub struct SpdmPskExchangeRequestPayload {
    pub measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    pub req_session_id: u16,
    pub psk_hint: SpdmPskHintStruct,
    pub psk_context: SpdmPskContextStruct,
    pub opaque: SpdmOpaqueStruct,
}

impl SpdmCodec for SpdmPskExchangeRequestPayload {
    fn spdm_encode(
        &self,
        _context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .measurement_summary_hash_type
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        cnt += self
            .req_session_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        cnt += self
            .psk_hint
            .data_size
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .psk_context
            .data_size
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .opaque
            .data_size
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        for d in self
            .psk_hint
            .data
            .iter()
            .take(self.psk_hint.data_size as usize)
        {
            cnt += d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        for d in self
            .psk_context
            .data
            .iter()
            .take(self.psk_context.data_size as usize)
        {
            cnt += d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        for d in self.opaque.data.iter().take(self.opaque.data_size as usize) {
            cnt += d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmPskExchangeRequestPayload> {
        let measurement_summary_hash_type = SpdmMeasurementSummaryHashType::read(r)?; // param1
        match measurement_summary_hash_type {
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone => {}
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll
            | SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb => {
                if !context
                    .negotiate_info
                    .rsp_capabilities_sel
                    .contains(SpdmResponseCapabilityFlags::MEAS_CAP_SIG)
                    && !context
                        .negotiate_info
                        .rsp_capabilities_sel
                        .contains(SpdmResponseCapabilityFlags::MEAS_CAP_NO_SIG)
                {
                    return None;
                }
            }
            SpdmMeasurementSummaryHashType::Unknown(_) => return None,
        }
        u8::read(r)?; // param2
        let req_session_id = u16::read(r)?;

        let mut psk_hint = SpdmPskHintStruct::default();
        let mut psk_context = SpdmPskContextStruct::default();
        let mut opaque = SpdmOpaqueStruct::default();

        psk_hint.data_size = u16::read(r)?;
        if psk_hint.data_size > MAX_SPDM_PSK_HINT_SIZE as u16 {
            return None;
        }
        psk_context.data_size = u16::read(r)?;
        if psk_context.data_size > MAX_SPDM_PSK_CONTEXT_SIZE as u16 {
            return None;
        }
        opaque.data_size = u16::read(r)?;
        if opaque.data_size > MAX_SPDM_OPAQUE_SIZE as u16 {
            return None;
        }

        for d in psk_hint.data.iter_mut().take(psk_hint.data_size as usize) {
            *d = u8::read(r)?;
        }
        for d in psk_context
            .data
            .iter_mut()
            .take(psk_context.data_size as usize)
        {
            *d = u8::read(r)?;
        }
        for d in opaque.data.iter_mut().take(opaque.data_size as usize) {
            *d = u8::read(r)?;
        }

        Some(SpdmPskExchangeRequestPayload {
            measurement_summary_hash_type,
            req_session_id,
            psk_hint,
            psk_context,
            opaque,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmPskExchangeResponsePayload {
    pub heartbeat_period: u8,
    pub rsp_session_id: u16,
    pub measurement_summary_hash: SpdmDigestStruct,
    pub psk_context: SpdmPskContextStruct,
    pub opaque: SpdmOpaqueStruct,
    pub verify_data: SpdmDigestStruct,
}

impl SpdmCodec for SpdmPskExchangeResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .heartbeat_period
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        cnt += self
            .rsp_session_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        let psk_without_context = context
            .negotiate_info
            .rsp_capabilities_sel
            .contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT);
        if psk_without_context {
            cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        } else {
            cnt += self
                .psk_context
                .data_size
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        cnt += self
            .opaque
            .data_size
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

        if context.runtime_info.need_measurement_summary_hash {
            cnt += self.measurement_summary_hash.spdm_encode(context, bytes)?;
        }
        if !psk_without_context {
            for d in self
                .psk_context
                .data
                .iter()
                .take(self.psk_context.data_size as usize)
            {
                cnt += d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            }
        }
        for d in self.opaque.data.iter().take(self.opaque.data_size as usize) {
            cnt += d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        cnt += self.verify_data.spdm_encode(context, bytes)?;
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmPskExchangeResponsePayload> {
        let heartbeat_period = u8::read(r)?; // param1
        u8::read(r)?; // param2

        let rsp_session_id = u16::read(r)?; // reserved
        u16::read(r)?;

        let mut psk_context = SpdmPskContextStruct::default();
        let mut opaque = SpdmOpaqueStruct::default();

        psk_context.data_size = u16::read(r)?;
        let psk_without_context = context
            .negotiate_info
            .rsp_capabilities_sel
            .contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT);
        if (psk_without_context && (psk_context.data_size != 0))
            || (!psk_without_context && (psk_context.data_size == 0))
        {
            return None;
        }
        if psk_context.data_size > MAX_SPDM_PSK_CONTEXT_SIZE as u16 {
            return None;
        }

        opaque.data_size = u16::read(r)?;
        if opaque.data_size > MAX_SPDM_OPAQUE_SIZE as u16 {
            return None;
        }

        let measurement_summary_hash = if context.runtime_info.need_measurement_summary_hash {
            SpdmDigestStruct::spdm_read(context, r)?
        } else {
            SpdmDigestStruct::default()
        };

        for d in psk_context
            .data
            .iter_mut()
            .take(psk_context.data_size as usize)
        {
            *d = u8::read(r)?;
        }
        for d in opaque.data.iter_mut().take(opaque.data_size as usize) {
            *d = u8::read(r)?;
        }
        let verify_data = SpdmDigestStruct::spdm_read(context, r)?;

        Some(SpdmPskExchangeResponsePayload {
            heartbeat_period,
            rsp_session_id,
            measurement_summary_hash,
            psk_context,
            opaque,
            verify_data,
        })
    }
}

#[cfg(test)]
#[path = "mod_test.common.inc.rs"]
mod testlib;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::*;
    use crate::common::{SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
    use crate::protocol::*;
    use testlib::{create_spdm_context, DeviceIO, TransportEncap};
    extern crate alloc;

    #[test]
    fn test_case0_spdm_psk_exchange_request_payload() {
        let u8_slice = &mut [0u8; 10
            + MAX_SPDM_PSK_HINT_SIZE
            + MAX_SPDM_PSK_CONTEXT_SIZE
            + MAX_SPDM_OPAQUE_SIZE];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmPskExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            req_session_id: 100u16,
            psk_hint: SpdmPskHintStruct {
                data_size: MAX_SPDM_PSK_HINT_SIZE as u16,
                data: [100u8; MAX_SPDM_PSK_HINT_SIZE],
            },
            psk_context: SpdmPskContextStruct {
                data_size: MAX_SPDM_PSK_CONTEXT_SIZE as u16,
                data: [100u8; MAX_SPDM_PSK_CONTEXT_SIZE],
            },
            opaque: SpdmOpaqueStruct {
                data_size: MAX_SPDM_OPAQUE_SIZE as u16,
                data: [100u8; MAX_SPDM_OPAQUE_SIZE],
            },
        };

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(
            10 + MAX_SPDM_PSK_HINT_SIZE + MAX_SPDM_PSK_CONTEXT_SIZE + MAX_SPDM_OPAQUE_SIZE,
            reader.left()
        );
        let psk_exchange_request =
            SpdmPskExchangeRequestPayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(
            psk_exchange_request.measurement_summary_hash_type,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone
        );
        assert_eq!(
            psk_exchange_request.psk_hint.data_size,
            MAX_SPDM_PSK_HINT_SIZE as u16
        );
        assert_eq!(
            psk_exchange_request.psk_context.data_size,
            MAX_SPDM_PSK_CONTEXT_SIZE as u16
        );
        assert_eq!(
            psk_exchange_request.opaque.data_size,
            MAX_SPDM_OPAQUE_SIZE as u16
        );
        for i in 0..MAX_SPDM_PSK_HINT_SIZE {
            assert_eq!(psk_exchange_request.psk_hint.data[i], 100);
        }
        for i in 0..MAX_SPDM_PSK_CONTEXT_SIZE {
            assert_eq!(psk_exchange_request.psk_context.data[i], 100);
        }
        for i in 0..MAX_SPDM_OPAQUE_SIZE {
            assert_eq!(psk_exchange_request.opaque.data[i], 100);
        }
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case1_spdm_psk_exchange_request_payload() {
        let u8_slice = &mut [0u8; 10];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmPskExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            req_session_id: 100u16,
            psk_hint: SpdmPskHintStruct {
                data_size: 0,
                data: [100u8; MAX_SPDM_PSK_HINT_SIZE],
            },
            psk_context: SpdmPskContextStruct {
                data_size: 0,
                data: [100u8; MAX_SPDM_PSK_CONTEXT_SIZE],
            },
            opaque: SpdmOpaqueStruct {
                data_size: 0,
                data: [100u8; MAX_SPDM_OPAQUE_SIZE],
            },
        };

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(10, reader.left());
        let psk_exchange_request =
            SpdmPskExchangeRequestPayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(
            psk_exchange_request.measurement_summary_hash_type,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone
        );
        assert_eq!(psk_exchange_request.psk_hint.data_size, 0);
        assert_eq!(psk_exchange_request.psk_context.data_size, 0);
        assert_eq!(psk_exchange_request.opaque.data_size, 0);
        for i in 0..MAX_SPDM_PSK_HINT_SIZE {
            assert_eq!(psk_exchange_request.psk_hint.data[i], 0);
        }
        for i in 0..MAX_SPDM_PSK_CONTEXT_SIZE {
            assert_eq!(psk_exchange_request.psk_context.data[i], 0);
        }
        for i in 0..MAX_SPDM_OPAQUE_SIZE {
            assert_eq!(psk_exchange_request.opaque.data[i], 0);
        }
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_psk_exchange_response_payload() {
        let u8_slice = &mut [0u8; 10
            + SPDM_MAX_HASH_SIZE
            + MAX_SPDM_PSK_CONTEXT_SIZE
            + MAX_SPDM_OPAQUE_SIZE
            + SPDM_MAX_HASH_SIZE];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmPskExchangeResponsePayload {
            heartbeat_period: 0xaau8,
            rsp_session_id: 0xaa55u16,
            measurement_summary_hash: SpdmDigestStruct {
                data_size: SPDM_MAX_HASH_SIZE as u16,
                data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
            },
            psk_context: SpdmPskContextStruct {
                data_size: MAX_SPDM_PSK_CONTEXT_SIZE as u16,
                data: [100u8; MAX_SPDM_PSK_CONTEXT_SIZE],
            },
            opaque: SpdmOpaqueStruct {
                data_size: MAX_SPDM_OPAQUE_SIZE as u16,
                data: [100u8; MAX_SPDM_OPAQUE_SIZE],
            },
            verify_data: SpdmDigestStruct {
                data_size: SPDM_MAX_HASH_SIZE as u16,
                data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
            },
        };

        create_spdm_context!(context);

        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.runtime_info.need_measurement_summary_hash = true;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(
            10 + SPDM_MAX_HASH_SIZE
                + MAX_SPDM_PSK_CONTEXT_SIZE
                + MAX_SPDM_OPAQUE_SIZE
                + SPDM_MAX_HASH_SIZE,
            reader.left()
        );
        let psk_exchange_response =
            SpdmPskExchangeResponsePayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(psk_exchange_response.heartbeat_period, 0xaau8);
        assert_eq!(psk_exchange_response.rsp_session_id, 0xaa55u16);

        assert_eq!(
            psk_exchange_response.measurement_summary_hash.data_size,
            SHA512_DIGEST_SIZE as u16
        );
        assert_eq!(
            psk_exchange_response.psk_context.data_size,
            MAX_SPDM_PSK_CONTEXT_SIZE as u16
        );
        assert_eq!(
            psk_exchange_response.opaque.data_size,
            MAX_SPDM_OPAQUE_SIZE as u16
        );
        assert_eq!(
            psk_exchange_response.verify_data.data_size,
            SHA512_DIGEST_SIZE as u16
        );

        for i in 0..SHA512_DIGEST_SIZE {
            assert_eq!(psk_exchange_response.measurement_summary_hash.data[i], 100);
        }
        for i in 0..MAX_SPDM_PSK_CONTEXT_SIZE {
            assert_eq!(psk_exchange_response.psk_context.data[i], 100);
        }
        for i in 0..MAX_SPDM_OPAQUE_SIZE {
            assert_eq!(psk_exchange_response.opaque.data[i], 100);
        }
        for i in 0..SHA512_DIGEST_SIZE {
            assert_eq!(psk_exchange_response.verify_data.data[i], 100u8);
        }
        assert_eq!(0, reader.left());

        let u8_slice =
            &mut [0u8; 10 + MAX_SPDM_PSK_CONTEXT_SIZE + MAX_SPDM_OPAQUE_SIZE + SPDM_MAX_HASH_SIZE];
        let mut writer = Writer::init(u8_slice);

        context.runtime_info.need_measurement_summary_hash = false;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(
            10 + MAX_SPDM_PSK_CONTEXT_SIZE + MAX_SPDM_OPAQUE_SIZE + SPDM_MAX_HASH_SIZE,
            reader.left()
        );
        let psk_exchange_response =
            SpdmPskExchangeResponsePayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(psk_exchange_response.measurement_summary_hash.data_size, 0);
        for i in 0..SHA512_DIGEST_SIZE {
            assert_eq!(psk_exchange_response.measurement_summary_hash.data[i], 0);
        }
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case1_spdm_psk_exchange_response_payload() {
        let u8_slice = &mut [0u8; 10 + SPDM_MAX_HASH_SIZE + SPDM_MAX_HASH_SIZE];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmPskExchangeResponsePayload {
            heartbeat_period: 0xaau8,
            rsp_session_id: 0xaa55u16,
            measurement_summary_hash: SpdmDigestStruct {
                data_size: SPDM_MAX_HASH_SIZE as u16,
                data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
            },
            psk_context: SpdmPskContextStruct {
                data_size: 0,
                data: [100u8; MAX_SPDM_PSK_CONTEXT_SIZE],
            },
            opaque: SpdmOpaqueStruct {
                data_size: 0,
                data: [100u8; MAX_SPDM_OPAQUE_SIZE],
            },
            verify_data: SpdmDigestStruct {
                data_size: SPDM_MAX_HASH_SIZE as u16,
                data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
            },
        };

        create_spdm_context!(context);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT;

        context.runtime_info.need_measurement_summary_hash = true;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(10 + SPDM_MAX_HASH_SIZE + SPDM_MAX_HASH_SIZE, reader.left());
        let psk_exchange_response =
            SpdmPskExchangeResponsePayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(psk_exchange_response.heartbeat_period, 0xaau8);
        assert_eq!(psk_exchange_response.rsp_session_id, 0xaa55u16);

        assert_eq!(
            psk_exchange_response.measurement_summary_hash.data_size,
            SHA512_DIGEST_SIZE as u16
        );
        assert_eq!(psk_exchange_response.psk_context.data_size, 0);
        assert_eq!(psk_exchange_response.opaque.data_size, 0);
        assert_eq!(
            psk_exchange_response.verify_data.data_size,
            SHA512_DIGEST_SIZE as u16
        );

        for i in 0..SHA512_DIGEST_SIZE {
            assert_eq!(psk_exchange_response.measurement_summary_hash.data[i], 100);
        }
        for i in 0..MAX_SPDM_PSK_CONTEXT_SIZE {
            assert_eq!(psk_exchange_response.psk_context.data[i], 0);
        }
        for i in 0..MAX_SPDM_OPAQUE_SIZE {
            assert_eq!(psk_exchange_response.opaque.data[i], 0);
        }
        for i in 0..SHA512_DIGEST_SIZE {
            assert_eq!(psk_exchange_response.verify_data.data[i], 100);
        }
        assert_eq!(0, reader.left());
    }
}

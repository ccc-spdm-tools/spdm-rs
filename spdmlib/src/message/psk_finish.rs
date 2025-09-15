// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::SpdmVersion;
use crate::common::opaque::SpdmOpaqueStruct;
use crate::common::spdm_codec::SpdmCodec;
use crate::error::SPDM_STATUS_BUFFER_FULL;
use crate::protocol::SpdmDigestStruct;
use crate::{common, error::SpdmStatus};
use codec::{Codec, Reader, Writer};

#[derive(Debug, Clone, Default)]
pub struct SpdmPskFinishRequestPayload {
    pub verify_data: SpdmDigestStruct,
    pub opaque: SpdmOpaqueStruct, // Spdm 1.4
}

impl SpdmCodec for SpdmPskFinishRequestPayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
            cnt += self.opaque.spdm_encode(context, bytes)?;
        }
        cnt += self.verify_data.spdm_encode(context, bytes)?;
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmPskFinishRequestPayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2
        let mut opaque = SpdmOpaqueStruct::default();
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
            opaque = SpdmOpaqueStruct::spdm_read(context, r)?;
        }
        let verify_data = SpdmDigestStruct::spdm_read(context, r)?;

        Some(SpdmPskFinishRequestPayload {
            verify_data,
            opaque,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmPskFinishResponsePayload {
    pub opaque: SpdmOpaqueStruct, // Spdm 1.4
}

impl SpdmCodec for SpdmPskFinishResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
            cnt += self.opaque.spdm_encode(context, bytes)?;
        }
        Ok(cnt)
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmPskFinishResponsePayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2
        let mut opaque = SpdmOpaqueStruct::default();
        if context.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion14 {
            opaque = SpdmOpaqueStruct::spdm_read(context, r)?;
        }

        Some(SpdmPskFinishResponsePayload { opaque })
    }
}

#[cfg(test)]
#[path = "mod_test.common.inc.rs"]
mod testlib;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{SpdmConfigInfo, SpdmContext, SpdmProvisionInfo, MAX_SPDM_OPAQUE_SIZE};
    use crate::protocol::*;
    use testlib::{create_spdm_context, DeviceIO, TransportEncap};
    extern crate alloc;
    use alloc::boxed::Box;

    #[test]
    fn test_case0_spdm_psk_finish_request_payload() {
        let u8_slice = &mut [0u8; 2 + SPDM_MAX_HASH_SIZE];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmPskFinishRequestPayload {
            verify_data: SpdmDigestStruct {
                data_size: SPDM_MAX_HASH_SIZE as u16,
                data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
            },
            opaque: SpdmOpaqueStruct {
                data_size: MAX_SPDM_OPAQUE_SIZE as u16,
                data: [100u8; MAX_SPDM_OPAQUE_SIZE],
            },
        };

        create_spdm_context!(context);

        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(2 + SPDM_MAX_HASH_SIZE, reader.left());
        let psk_finish_request =
            SpdmPskFinishRequestPayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(
            psk_finish_request.verify_data.data_size,
            SHA512_DIGEST_SIZE as u16
        );
        for i in 0..SHA512_DIGEST_SIZE {
            assert_eq!(psk_finish_request.verify_data.data[i], 100u8);
        }
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_psk_finish_response_payload() {
        let u8_slice = &mut [0u8; 2];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmPskFinishResponsePayload {
            opaque: SpdmOpaqueStruct {
                data_size: MAX_SPDM_OPAQUE_SIZE as u16,
                data: [100u8; MAX_SPDM_OPAQUE_SIZE],
            },
        };

        create_spdm_context!(context);

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        SpdmPskFinishResponsePayload::spdm_read(&mut context, &mut reader);
    }
}

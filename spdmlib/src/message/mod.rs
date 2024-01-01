// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::{SpdmCodec, SpdmContext};
use crate::error::{SpdmStatus, SPDM_STATUS_BUFFER_FULL};
use crate::protocol::*;
use codec::enum_builder;
use codec::{Codec, Reader, Writer};

// SPDM 1.0
pub mod algorithm;
pub mod capability;
pub mod certificate;
pub mod challenge;
pub mod digest;
#[cfg(feature = "mut-auth")]
pub mod encapsulated;
pub mod error;
pub mod measurement;
pub mod vendor;
pub mod version;
// SPDM 1.1
pub mod end_session;
pub mod finish;
pub mod heartbeat;
pub mod key_exchange;
pub mod key_update;
pub mod psk_exchange;
pub mod psk_finish;
pub mod respond_if_ready;

pub use algorithm::*;
pub use capability::*;
pub use certificate::*;
pub use challenge::*;
pub use digest::*;
#[cfg(feature = "mut-auth")]
pub use encapsulated::*;
pub use end_session::*;
pub use error::*;
pub use finish::*;
pub use heartbeat::*;
pub use key_exchange::*;
pub use key_update::*;
pub use measurement::*;
pub use psk_exchange::*;
pub use psk_finish::*;
pub use version::*;
// Add new SPDM command here.
pub use respond_if_ready::*;
pub use vendor::*;

enum_builder! {
    @U8
    EnumName: SpdmRequestResponseCode;
    EnumVal{
        // 1.0 response
        SpdmResponseDigests => 0x01,
        SpdmResponseCertificate => 0x02,
        SpdmResponseChallengeAuth => 0x03,
        SpdmResponseVersion => 0x04,
        SpdmResponseMeasurements => 0x60,
        SpdmResponseCapabilities => 0x61,
        SpdmResponseAlgorithms => 0x63,
        SpdmResponseVendorDefinedResponse => 0x7E,
        SpdmResponseError => 0x7F,
        // 1.1 response
        SpdmResponseKeyExchangeRsp => 0x64,
        SpdmResponseFinishRsp => 0x65,
        SpdmResponsePskExchangeRsp => 0x66,
        SpdmResponsePskFinishRsp => 0x67,
        SpdmResponseHeartbeatAck => 0x68,
        SpdmResponseKeyUpdateAck => 0x69,
        SpdmResponseEncapsulatedRequest => 0x6A,
        SpdmResponseEncapsulatedResponseAck => 0x6B,
        SpdmResponseEndSessionAck => 0x6C,

        // 1.0 rerquest
        SpdmRequestGetDigests => 0x81,
        SpdmRequestGetCertificate => 0x82,
        SpdmRequestChallenge => 0x83,
        SpdmRequestGetVersion => 0x84,
        SpdmRequestGetMeasurements => 0xE0,
        SpdmRequestGetCapabilities => 0xE1,
        SpdmRequestNegotiateAlgorithms => 0xE3,
        SpdmRequestVendorDefinedRequest => 0xFE,
        SpdmRequestResponseIfReady => 0xFF,
        // 1.1 request
        SpdmRequestKeyExchange => 0xE4,
        SpdmRequestFinish => 0xE5,
        SpdmRequestPskExchange => 0xE6,
        SpdmRequestPskFinish => 0xE7,
        SpdmRequestHeartbeat => 0xE8,
        SpdmRequestKeyUpdate => 0xE9,
        SpdmRequestGetEncapsulatedRequest => 0xEA,
        SpdmRequestDeliverEncapsulatedResponse => 0xEB,
        SpdmRequestEndSession => 0xEC
    }
}
impl Default for SpdmRequestResponseCode {
    fn default() -> SpdmRequestResponseCode {
        SpdmRequestResponseCode::Unknown(0)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmMessageHeader {
    pub version: SpdmVersion,
    pub request_response_code: SpdmRequestResponseCode,
}

impl Codec for SpdmMessageHeader {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += self.version.encode(bytes)?;
        cnt += self.request_response_code.encode(bytes)?;
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<SpdmMessageHeader> {
        let version = SpdmVersion::read(r)?;
        let request_response_code = SpdmRequestResponseCode::read(r)?;
        Some(SpdmMessageHeader {
            version,
            request_response_code,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmMessageGeneralPayload {
    pub param1: u8,
    pub param2: u8,
    //pub payload: [u8],
}

impl Codec for SpdmMessageGeneralPayload {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += self.param1.encode(bytes)?;
        cnt += self.param2.encode(bytes)?;
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<SpdmMessageGeneralPayload> {
        let param1 = u8::read(r)?;
        let param2 = u8::read(r)?;
        Some(SpdmMessageGeneralPayload { param1, param2 })
    }
}

impl SpdmCodec for SpdmMessageGeneralPayload {
    fn spdm_encode(
        &self,
        _context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        Ok(2)
    }

    fn spdm_read(_context: &mut SpdmContext, r: &mut Reader) -> Option<SpdmMessageGeneralPayload> {
        let param1 = u8::read(r)?; // param1
        let param2 = u8::read(r)?; // param2

        Some(SpdmMessageGeneralPayload { param1, param2 })
    }
}

#[derive(Debug)]
pub struct SpdmMessage {
    pub header: SpdmMessageHeader,
    pub payload: SpdmMessagePayload,
}

//
// we have to define big payload to hold the possible data from responder,
// such as, cert_chain, measurement_record, etc.
//
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum SpdmMessagePayload {
    SpdmMessageGeneral(SpdmMessageGeneralPayload),

    SpdmGetVersionRequest(SpdmGetVersionRequestPayload),
    SpdmVersionResponse(SpdmVersionResponsePayload),

    SpdmGetCapabilitiesRequest(SpdmGetCapabilitiesRequestPayload),
    SpdmCapabilitiesResponse(SpdmCapabilitiesResponsePayload),

    SpdmNegotiateAlgorithmsRequest(SpdmNegotiateAlgorithmsRequestPayload),
    SpdmAlgorithmsResponse(SpdmAlgorithmsResponsePayload),

    SpdmGetDigestsRequest(SpdmGetDigestsRequestPayload),
    SpdmDigestsResponse(SpdmDigestsResponsePayload),

    SpdmGetCertificateRequest(SpdmGetCertificateRequestPayload),
    SpdmCertificateResponse(SpdmCertificateResponsePayload),

    SpdmChallengeRequest(SpdmChallengeRequestPayload),
    SpdmChallengeAuthResponse(SpdmChallengeAuthResponsePayload),

    SpdmGetMeasurementsRequest(SpdmGetMeasurementsRequestPayload),
    SpdmMeasurementsResponse(SpdmMeasurementsResponsePayload),

    SpdmKeyExchangeRequest(SpdmKeyExchangeRequestPayload),
    SpdmKeyExchangeResponse(SpdmKeyExchangeResponsePayload),

    SpdmFinishRequest(SpdmFinishRequestPayload),
    SpdmFinishResponse(SpdmFinishResponsePayload),

    SpdmPskExchangeRequest(SpdmPskExchangeRequestPayload),
    SpdmPskExchangeResponse(SpdmPskExchangeResponsePayload),

    #[cfg(feature = "mut-auth")]
    SpdmGetEncapsulatedRequestPayload(SpdmGetEncapsulatedRequestPayload),
    #[cfg(feature = "mut-auth")]
    SpdmEncapsulatedRequestPayload(SpdmEncapsulatedRequestPayload),
    #[cfg(feature = "mut-auth")]
    SpdmDeliverEncapsulatedResponsePayload(SpdmDeliverEncapsulatedResponsePayload),
    #[cfg(feature = "mut-auth")]
    SpdmEncapsulatedResponseAckPayload(SpdmEncapsulatedResponseAckPayload),

    SpdmPskFinishRequest(SpdmPskFinishRequestPayload),
    SpdmPskFinishResponse(SpdmPskFinishResponsePayload),

    SpdmHeartbeatRequest(SpdmHeartbeatRequestPayload),
    SpdmHeartbeatResponse(SpdmHeartbeatResponsePayload),

    SpdmKeyUpdateRequest(SpdmKeyUpdateRequestPayload),
    SpdmKeyUpdateResponse(SpdmKeyUpdateResponsePayload),

    SpdmEndSessionRequest(SpdmEndSessionRequestPayload),
    SpdmEndSessionResponse(SpdmEndSessionResponsePayload),

    // Add new SPDM command here.
    SpdmErrorResponse(SpdmErrorResponsePayload),
    SpdmVendorDefinedRequest(SpdmVendorDefinedRequestPayload),
    SpdmVendorDefinedResponse(SpdmVendorDefinedResponsePayload),
}

impl SpdmMessage {
    pub fn read_with_detailed_error(
        context: &mut SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmMessage> {
        let header = SpdmMessageHeader::read(r)?;

        let payload = match header.request_response_code {
            SpdmRequestResponseCode::SpdmResponseVersion => {
                Some(SpdmMessagePayload::SpdmVersionResponse(
                    SpdmVersionResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestGetVersion => {
                Some(SpdmMessagePayload::SpdmGetVersionRequest(
                    SpdmGetVersionRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseCapabilities => {
                Some(SpdmMessagePayload::SpdmCapabilitiesResponse(
                    SpdmCapabilitiesResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestGetCapabilities => {
                Some(SpdmMessagePayload::SpdmGetCapabilitiesRequest(
                    SpdmGetCapabilitiesRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseAlgorithms => {
                Some(SpdmMessagePayload::SpdmAlgorithmsResponse(
                    SpdmAlgorithmsResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms => {
                Some(SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(
                    SpdmNegotiateAlgorithmsRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseDigests => {
                Some(SpdmMessagePayload::SpdmDigestsResponse(
                    SpdmDigestsResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestGetDigests => {
                Some(SpdmMessagePayload::SpdmGetDigestsRequest(
                    SpdmGetDigestsRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseCertificate => {
                Some(SpdmMessagePayload::SpdmCertificateResponse(
                    SpdmCertificateResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestGetCertificate => {
                Some(SpdmMessagePayload::SpdmGetCertificateRequest(
                    SpdmGetCertificateRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseChallengeAuth => {
                Some(SpdmMessagePayload::SpdmChallengeAuthResponse(
                    SpdmChallengeAuthResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestChallenge => {
                Some(SpdmMessagePayload::SpdmChallengeRequest(
                    SpdmChallengeRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseMeasurements => {
                Some(SpdmMessagePayload::SpdmMeasurementsResponse(
                    SpdmMeasurementsResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestGetMeasurements => {
                Some(SpdmMessagePayload::SpdmGetMeasurementsRequest(
                    SpdmGetMeasurementsRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseKeyExchangeRsp => {
                Some(SpdmMessagePayload::SpdmKeyExchangeResponse(
                    SpdmKeyExchangeResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestKeyExchange => {
                Some(SpdmMessagePayload::SpdmKeyExchangeRequest(
                    SpdmKeyExchangeRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseFinishRsp => {
                Some(SpdmMessagePayload::SpdmFinishResponse(
                    SpdmFinishResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestFinish => {
                Some(SpdmMessagePayload::SpdmFinishRequest(
                    SpdmFinishRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponsePskExchangeRsp => {
                Some(SpdmMessagePayload::SpdmPskExchangeResponse(
                    SpdmPskExchangeResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestPskExchange => {
                Some(SpdmMessagePayload::SpdmPskExchangeRequest(
                    SpdmPskExchangeRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponsePskFinishRsp => {
                Some(SpdmMessagePayload::SpdmPskFinishResponse(
                    SpdmPskFinishResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestPskFinish => {
                Some(SpdmMessagePayload::SpdmPskFinishRequest(
                    SpdmPskFinishRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseHeartbeatAck => {
                Some(SpdmMessagePayload::SpdmHeartbeatResponse(
                    SpdmHeartbeatResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestHeartbeat => {
                Some(SpdmMessagePayload::SpdmHeartbeatRequest(
                    SpdmHeartbeatRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseKeyUpdateAck => {
                Some(SpdmMessagePayload::SpdmKeyUpdateResponse(
                    SpdmKeyUpdateResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestKeyUpdate => {
                Some(SpdmMessagePayload::SpdmKeyUpdateRequest(
                    SpdmKeyUpdateRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseEndSessionAck => {
                Some(SpdmMessagePayload::SpdmEndSessionResponse(
                    SpdmEndSessionResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestEndSession => {
                Some(SpdmMessagePayload::SpdmEndSessionRequest(
                    SpdmEndSessionRequestPayload::spdm_read(context, r)?,
                ))
            }

            // Add new SPDM command here.
            SpdmRequestResponseCode::SpdmResponseError => {
                Some(SpdmMessagePayload::SpdmErrorResponse(
                    SpdmErrorResponsePayload::spdm_read(context, r)?,
                ))
            }

            _ => None,
        }?;

        Some(SpdmMessage { header, payload })
    }
}

impl SpdmCodec for SpdmMessage {
    fn spdm_encode(
        &self,
        context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .header
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        match &self.payload {
            SpdmMessagePayload::SpdmMessageGeneral(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmGetVersionRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmVersionResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            SpdmMessagePayload::SpdmGetCapabilitiesRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmCapabilitiesResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmAlgorithmsResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            SpdmMessagePayload::SpdmGetDigestsRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmDigestsResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            SpdmMessagePayload::SpdmGetCertificateRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmCertificateResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            SpdmMessagePayload::SpdmChallengeRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmChallengeAuthResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            SpdmMessagePayload::SpdmGetMeasurementsRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmMeasurementsResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            SpdmMessagePayload::SpdmKeyExchangeRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmKeyExchangeResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            SpdmMessagePayload::SpdmFinishRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmFinishResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            SpdmMessagePayload::SpdmPskExchangeRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmPskExchangeResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            SpdmMessagePayload::SpdmPskFinishRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmPskFinishResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            SpdmMessagePayload::SpdmEndSessionRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmEndSessionResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            SpdmMessagePayload::SpdmHeartbeatRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmHeartbeatResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            SpdmMessagePayload::SpdmKeyUpdateRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmKeyUpdateResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            #[cfg(feature = "mut-auth")]
            SpdmMessagePayload::SpdmGetEncapsulatedRequestPayload(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            #[cfg(feature = "mut-auth")]
            SpdmMessagePayload::SpdmEncapsulatedRequestPayload(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            #[cfg(feature = "mut-auth")]
            SpdmMessagePayload::SpdmDeliverEncapsulatedResponsePayload(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            #[cfg(feature = "mut-auth")]
            SpdmMessagePayload::SpdmEncapsulatedResponseAckPayload(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }

            // Add new SPDM command here.
            SpdmMessagePayload::SpdmErrorResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmVendorDefinedRequest(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
            SpdmMessagePayload::SpdmVendorDefinedResponse(payload) => {
                cnt += payload.spdm_encode(context, bytes)?;
            }
        }
        Ok(cnt)
    }

    fn spdm_read(context: &mut SpdmContext, r: &mut Reader) -> Option<SpdmMessage> {
        SpdmMessage::read_with_detailed_error(context, r)
    }
}

#[cfg(test)]
#[path = "mod_test.common.inc.rs"]
mod testlib;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::opaque::MAX_SPDM_OPAQUE_SIZE;
    use crate::common::SpdmMeasurementContentChanged;
    use crate::common::{
        SpdmConfigInfo, SpdmContext, SpdmOpaqueStruct, SpdmOpaqueSupport, SpdmProvisionInfo,
    };
    use crate::config::{self, *};
    use codec::u24;
    use testlib::{create_spdm_context, new_spdm_message, DeviceIO, TransportEncap};
    extern crate alloc;

    #[test]
    fn test_case0_spdm_message_header() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        let spdm_message_header = SpdmMessageHeader::read(&mut reader).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestChallenge
        );
    }

    #[test]
    fn test_case0_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseVersion,
            },
            payload: SpdmMessagePayload::SpdmVersionResponse(SpdmVersionResponsePayload {
                version_number_entry_count: 0x02,
                versions: gen_array_clone(
                    SpdmVersionStruct {
                        update: 100,
                        version: SpdmVersion::SpdmVersion11,
                    },
                    MAX_SPDM_VERSION_COUNT,
                ),
            }),
        };

        create_spdm_context!(context);

        let spdm_message = new_spdm_message(value, context);
        assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseVersion
        );
        if let SpdmMessagePayload::SpdmVersionResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.version_number_entry_count, 0x02);
            for i in 0..2 {
                assert_eq!(payload.versions[i].update, 100);
                assert_eq!(payload.versions[i].version, SpdmVersion::SpdmVersion11);
            }
        }
    }
    #[test]
    fn test_case1_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetCapabilities,
            },
            payload: SpdmMessagePayload::SpdmGetCapabilitiesRequest(
                SpdmGetCapabilitiesRequestPayload {
                    ct_exponent: 0x02,
                    flags: SpdmRequestCapabilityFlags::CERT_CAP
                        | SpdmRequestCapabilityFlags::CHAL_CAP,
                    data_transfer_size: 0,
                    max_spdm_msg_size: 0,
                },
            ),
        };
        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestGetCapabilities
        );
        if let SpdmMessagePayload::SpdmGetCapabilitiesRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.ct_exponent, 0x02);
            assert_eq!(
                payload.flags,
                SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::CHAL_CAP
            );
        }
    }
    #[test]
    fn test_case2_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseCapabilities,
            },
            payload: SpdmMessagePayload::SpdmCapabilitiesResponse(
                SpdmCapabilitiesResponsePayload {
                    ct_exponent: 0x03,
                    flags: SpdmResponseCapabilityFlags::CACHE_CAP,
                    data_transfer_size: 0,
                    max_spdm_msg_size: 0,
                },
            ),
        };
        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseCapabilities
        );
        if let SpdmMessagePayload::SpdmCapabilitiesResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.ct_exponent, 0x03);
            assert_eq!(payload.flags, SpdmResponseCapabilityFlags::CACHE_CAP);
        }
    }
    #[test]
    fn test_case3_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
            },
            payload: SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(
                SpdmNegotiateAlgorithmsRequestPayload {
                    measurement_specification: SpdmMeasurementSpecification::DMTF,
                    other_params_support: SpdmOpaqueSupport::empty(),
                    base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
                    base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                    alg_struct_count: 4,
                    alg_struct: [
                        SpdmAlgStruct {
                            alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                            alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1),
                        },
                        SpdmAlgStruct {
                            alg_type: SpdmAlgType::SpdmAlgTypeAEAD,
                            alg_supported: SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::AES_128_GCM),
                        },
                        SpdmAlgStruct {
                            alg_type: SpdmAlgType::SpdmAlgTypeReqAsym,
                            alg_supported: SpdmAlg::SpdmAlgoReqAsym(
                                SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                            ),
                        },
                        SpdmAlgStruct {
                            alg_type: SpdmAlgType::SpdmAlgTypeKeySchedule,
                            alg_supported: SpdmAlg::SpdmAlgoKeySchedule(
                                SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
                            ),
                        },
                    ],
                },
            ),
        };
        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms
        );
        if let SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(payload) = &spdm_message.payload {
            assert_eq!(
                payload.measurement_specification,
                SpdmMeasurementSpecification::DMTF
            );
            assert_eq!(
                payload.base_asym_algo,
                SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048
            );
            assert_eq!(payload.base_hash_algo, SpdmBaseHashAlgo::TPM_ALG_SHA_256);
            assert_eq!(payload.alg_struct_count, 4);
            assert_eq!(payload.alg_struct[0].alg_type, SpdmAlgType::SpdmAlgTypeDHE);
            assert_eq!(
                payload.alg_struct[0].alg_supported,
                SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1)
            );
            assert_eq!(payload.alg_struct[1].alg_type, SpdmAlgType::SpdmAlgTypeAEAD);
            assert_eq!(
                payload.alg_struct[1].alg_supported,
                SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::AES_128_GCM)
            );
            assert_eq!(
                payload.alg_struct[2].alg_type,
                SpdmAlgType::SpdmAlgTypeReqAsym
            );
            assert_eq!(
                payload.alg_struct[2].alg_supported,
                SpdmAlg::SpdmAlgoReqAsym(SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,)
            );
            assert_eq!(
                payload.alg_struct[3].alg_type,
                SpdmAlgType::SpdmAlgTypeKeySchedule
            );
            assert_eq!(
                payload.alg_struct[3].alg_supported,
                SpdmAlg::SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,)
            );
        }
    }
    #[test]
    fn test_case4_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseAlgorithms,
            },
            payload: SpdmMessagePayload::SpdmAlgorithmsResponse(SpdmAlgorithmsResponsePayload {
                measurement_specification_sel: SpdmMeasurementSpecification::DMTF,
                other_params_selection: SpdmOpaqueSupport::empty(),
                measurement_hash_algo: SpdmMeasurementHashAlgo::RAW_BIT_STREAM,
                base_asym_sel: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
                base_hash_sel: SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                alg_struct_count: 4,
                alg_struct: [
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                        alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1),
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeAEAD,
                        alg_supported: SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::AES_128_GCM),
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeReqAsym,
                        alg_supported: SpdmAlg::SpdmAlgoReqAsym(
                            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                        ),
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeKeySchedule,
                        alg_supported: SpdmAlg::SpdmAlgoKeySchedule(
                            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
                        ),
                    },
                ],
            }),
        };
        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        context.config_info.measurement_specification = SpdmMeasurementSpecification::DMTF;
        context.config_info.measurement_hash_algo = SpdmMeasurementHashAlgo::RAW_BIT_STREAM;
        context.config_info.base_asym_algo = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048;
        context.config_info.base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;

        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseAlgorithms
        );
        if let SpdmMessagePayload::SpdmAlgorithmsResponse(payload) = &spdm_message.payload {
            assert_eq!(
                payload.measurement_specification_sel,
                SpdmMeasurementSpecification::DMTF
            );
            assert_eq!(
                payload.measurement_hash_algo,
                SpdmMeasurementHashAlgo::RAW_BIT_STREAM
            );
            assert_eq!(payload.base_asym_sel, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048);
            assert_eq!(payload.base_hash_sel, SpdmBaseHashAlgo::TPM_ALG_SHA_256);
            assert_eq!(payload.alg_struct_count, 4);
            assert_eq!(payload.alg_struct[0].alg_type, SpdmAlgType::SpdmAlgTypeDHE);
            assert_eq!(
                payload.alg_struct[0].alg_supported,
                SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1)
            );
            assert_eq!(payload.alg_struct[1].alg_type, SpdmAlgType::SpdmAlgTypeAEAD);
            assert_eq!(
                payload.alg_struct[1].alg_supported,
                SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::AES_128_GCM)
            );
            assert_eq!(
                payload.alg_struct[2].alg_type,
                SpdmAlgType::SpdmAlgTypeReqAsym
            );
            assert_eq!(
                payload.alg_struct[2].alg_supported,
                SpdmAlg::SpdmAlgoReqAsym(SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,)
            );
            assert_eq!(
                payload.alg_struct[3].alg_type,
                SpdmAlgType::SpdmAlgTypeKeySchedule
            );
            assert_eq!(
                payload.alg_struct[3].alg_supported,
                SpdmAlg::SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,)
            );
        }
    }
    #[test]
    fn test_case5_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseCertificate,
            },
            payload: SpdmMessagePayload::SpdmCertificateResponse(SpdmCertificateResponsePayload {
                slot_id: 100,
                portion_length: MAX_SPDM_CERT_PORTION_LEN as u16,
                remainder_length: 100,
                cert_chain: [100u8; MAX_SPDM_CERT_PORTION_LEN],
            }),
        };
        create_spdm_context!(context);

        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseCertificate
        );
        if let SpdmMessagePayload::SpdmCertificateResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_id, 100);
            assert_eq!(payload.portion_length, MAX_SPDM_CERT_PORTION_LEN as u16);
            assert_eq!(payload.remainder_length, 100);
            for i in 0..MAX_SPDM_CERT_PORTION_LEN {
                assert_eq!(payload.cert_chain[i], 100u8);
            }
        }
    }
    #[test]
    fn test_case6_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
            },
            payload: SpdmMessagePayload::SpdmChallengeRequest(SpdmChallengeRequestPayload {
                slot_id: 100,
                measurement_summary_hash_type:
                    SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                nonce: SpdmNonceStruct {
                    data: [100u8; SPDM_NONCE_SIZE],
                },
            }),
        };

        create_spdm_context!(context);

        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestChallenge
        );
        if let SpdmMessagePayload::SpdmChallengeRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_id, 100);
            assert_eq!(
                payload.measurement_summary_hash_type,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone
            );
            for i in 0..SPDM_NONCE_SIZE {
                assert_eq!(payload.nonce.data[i], 100u8);
            }
        }
    }
    #[test]
    fn test_case7_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseChallengeAuth,
            },
            payload: SpdmMessagePayload::SpdmChallengeAuthResponse(
                SpdmChallengeAuthResponsePayload {
                    slot_id: 0x0f,
                    slot_mask: 100,
                    challenge_auth_attribute: SpdmChallengeAuthAttribute::BASIC_MUT_AUTH_REQ,
                    cert_chain_hash: SpdmDigestStruct {
                        data_size: SPDM_MAX_HASH_SIZE as u16,
                        data: Box::new([0xAAu8; SPDM_MAX_HASH_SIZE]),
                    },
                    nonce: SpdmNonceStruct {
                        data: [100u8; SPDM_NONCE_SIZE],
                    },
                    measurement_summary_hash: SpdmDigestStruct {
                        data_size: SPDM_MAX_HASH_SIZE as u16,
                        data: Box::new([0x55u8; SPDM_MAX_HASH_SIZE]),
                    },
                    opaque: SpdmOpaqueStruct {
                        data_size: MAX_SPDM_OPAQUE_SIZE as u16,
                        data: [0xAAu8; MAX_SPDM_OPAQUE_SIZE],
                    },
                    signature: SpdmSignatureStruct {
                        data_size: SPDM_MAX_ASYM_KEY_SIZE as u16,
                        data: [0x55u8; SPDM_MAX_ASYM_KEY_SIZE],
                    },
                },
            ),
        };
        create_spdm_context!(context);

        context.runtime_info.need_measurement_summary_hash = true;
        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseChallengeAuth
        );
        if let SpdmMessagePayload::SpdmChallengeAuthResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_id, 0x0f);
            assert_eq!(payload.slot_mask, 100);
            assert_eq!(
                payload.challenge_auth_attribute,
                SpdmChallengeAuthAttribute::BASIC_MUT_AUTH_REQ
            );
            assert_eq!(payload.cert_chain_hash.data_size, SHA512_DIGEST_SIZE as u16);
            assert_eq!(
                payload.measurement_summary_hash.data_size,
                SHA512_DIGEST_SIZE as u16
            );
            assert_eq!(payload.opaque.data_size, MAX_SPDM_OPAQUE_SIZE as u16);
            assert_eq!(payload.signature.data_size, RSASSA_4096_KEY_SIZE as u16);

            for i in 0..SHA512_DIGEST_SIZE {
                assert_eq!(payload.cert_chain_hash.data[i], 0xAAu8);
            }
            for i in 0..MAX_SPDM_OPAQUE_SIZE {
                assert_eq!(payload.opaque.data[i], 0xAAu8);
            }
            for i in 0..SHA512_DIGEST_SIZE {
                assert_eq!(payload.measurement_summary_hash.data[i], 0x55u8);
            }
            for i in 0..SPDM_NONCE_SIZE {
                assert_eq!(payload.nonce.data[i], 100u8);
            }
            for i in 0..RSASSA_4096_KEY_SIZE {
                assert_eq!(payload.signature.data[i], 0x55u8);
            }
        }
    }
    #[test]
    fn test_case8_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetMeasurements,
            },
            payload: SpdmMessagePayload::SpdmGetMeasurementsRequest(
                SpdmGetMeasurementsRequestPayload {
                    measurement_attributes: SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                    measurement_operation:
                        SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
                    nonce: SpdmNonceStruct {
                        data: [100u8; SPDM_NONCE_SIZE],
                    },
                    slot_id: 0x7,
                },
            ),
        };
        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestGetMeasurements
        );
        if let SpdmMessagePayload::SpdmGetMeasurementsRequest(payload) = &spdm_message.payload {
            assert_eq!(
                payload.measurement_attributes,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED
            );
            assert_eq!(
                payload.measurement_operation,
                SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
            );
            assert_eq!(payload.slot_id, 0x7);
            for i in 0..SPDM_NONCE_SIZE {
                assert_eq!(payload.nonce.data[i], 100u8);
            }
        }
    }
    #[test]
    fn test_case9_spdm_message() {
        let mut spdm_measurement_block_structure = SpdmMeasurementBlockStructure {
            index: 1u8,
            measurement_specification: SpdmMeasurementSpecification::DMTF,
            measurement_size: 3 + SHA512_DIGEST_SIZE as u16,
            measurement: SpdmDmtfMeasurementStructure {
                r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
                representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                value_size: SHA512_DIGEST_SIZE as u16,
                value: [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN],
            },
        };

        let mut measurement_record_data = [0u8; config::MAX_SPDM_MEASUREMENT_RECORD_SIZE];
        let mut writer = Writer::init(&mut measurement_record_data);
        for _i in 0..5 {
            assert!(spdm_measurement_block_structure.encode(&mut writer).is_ok());
            spdm_measurement_block_structure.index += 1;
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseMeasurements,
            },
            payload: SpdmMessagePayload::SpdmMeasurementsResponse(
                SpdmMeasurementsResponsePayload {
                    number_of_measurement: 100u8,
                    slot_id: 7u8,
                    content_changed: SpdmMeasurementContentChanged::NOT_SUPPORTED,
                    measurement_record: SpdmMeasurementRecordStructure {
                        number_of_blocks: 5,
                        measurement_record_length: u24::new(writer.used() as u32),
                        measurement_record_data,
                    },
                    nonce: SpdmNonceStruct {
                        data: [100u8; SPDM_NONCE_SIZE],
                    },
                    opaque: SpdmOpaqueStruct {
                        data_size: MAX_SPDM_OPAQUE_SIZE as u16,
                        data: [100u8; MAX_SPDM_OPAQUE_SIZE],
                    },
                    signature: SpdmSignatureStruct {
                        data_size: SPDM_MAX_ASYM_KEY_SIZE as u16,
                        data: [100u8; SPDM_MAX_ASYM_KEY_SIZE],
                    },
                    measurement_operation:
                        SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
                },
            ),
        };
        create_spdm_context!(context);
        context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        context.runtime_info.need_measurement_signature = true;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseMeasurements
        );
        if let SpdmMessagePayload::SpdmMeasurementsResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.number_of_measurement, 100);
            assert_eq!(payload.slot_id, 7);
            assert_eq!(
                payload.content_changed,
                SpdmMeasurementContentChanged::NOT_SUPPORTED
            );
            assert_eq!(payload.measurement_record.number_of_blocks, 5);
            for i in 0..SPDM_NONCE_SIZE {
                assert_eq!(payload.nonce.data[i], 100);
            }
            assert_eq!(payload.opaque.data_size, MAX_SPDM_OPAQUE_SIZE as u16);
            for i in 0..MAX_SPDM_OPAQUE_SIZE {
                assert_eq!(payload.opaque.data[i], 100);
            }
            assert_eq!(payload.signature.data_size, RSASSA_4096_KEY_SIZE as u16);
            for i in 0..RSASSA_4096_KEY_SIZE {
                assert_eq!(payload.signature.data[i], 100);
            }
        }
    }
    #[test]
    fn test_case10_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestKeyExchange,
            },
            payload: SpdmMessagePayload::SpdmKeyExchangeRequest(SpdmKeyExchangeRequestPayload {
                measurement_summary_hash_type:
                    SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                slot_id: 100u8,
                req_session_id: 100u16,
                session_policy: 1,
                random: SpdmRandomStruct {
                    data: [100u8; SPDM_RANDOM_SIZE],
                },
                exchange: SpdmDheExchangeStruct {
                    data_size: SPDM_MAX_DHE_KEY_SIZE as u16,
                    data: [100u8; SPDM_MAX_DHE_KEY_SIZE],
                },
                opaque: SpdmOpaqueStruct {
                    data_size: MAX_SPDM_OPAQUE_SIZE as u16,
                    data: [100u8; MAX_SPDM_OPAQUE_SIZE],
                },
            }),
        };
        create_spdm_context!(context);
        context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestKeyExchange
        );
        if let SpdmMessagePayload::SpdmKeyExchangeRequest(payload) = &spdm_message.payload {
            assert_eq!(
                payload.measurement_summary_hash_type,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone
            );
            assert_eq!(payload.slot_id, 100);
            for i in 0..SPDM_RANDOM_SIZE {
                assert_eq!(payload.random.data[i], 100);
            }
            assert_eq!(
                payload.exchange.data_size,
                ECDSA_ECC_NIST_P384_KEY_SIZE as u16
            );
            for i in 0..ECDSA_ECC_NIST_P384_KEY_SIZE {
                assert_eq!(payload.exchange.data[i], 100);
            }
            assert_eq!(payload.opaque.data_size, MAX_SPDM_OPAQUE_SIZE as u16);
            for i in 0..MAX_SPDM_OPAQUE_SIZE {
                assert_eq!(payload.opaque.data[i], 100);
            }
        }
    }
    #[test]
    fn test_case12_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestFinish,
            },
            payload: SpdmMessagePayload::SpdmFinishRequest(SpdmFinishRequestPayload {
                finish_request_attributes: SpdmFinishRequestAttributes::SIGNATURE_INCLUDED,
                req_slot_id: 100,
                signature: SpdmSignatureStruct {
                    data_size: SPDM_MAX_ASYM_KEY_SIZE as u16,
                    data: [0xa5u8; SPDM_MAX_ASYM_KEY_SIZE],
                },
                verify_data: SpdmDigestStruct {
                    data_size: SPDM_MAX_HASH_SIZE as u16,
                    data: Box::new([0x5au8; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };
        create_spdm_context!(context);
        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestFinish
        );
        if let SpdmMessagePayload::SpdmFinishRequest(payload) = &spdm_message.payload {
            assert_eq!(
                payload.finish_request_attributes,
                SpdmFinishRequestAttributes::SIGNATURE_INCLUDED
            );
            assert_eq!(payload.req_slot_id, 100);
            assert_eq!(payload.signature.data_size, RSASSA_4096_KEY_SIZE as u16);
            for i in 0..RSASSA_4096_KEY_SIZE {
                assert_eq!(payload.signature.data[i], 0xa5u8);
            }
            assert_eq!(payload.verify_data.data_size, SHA512_DIGEST_SIZE as u16);
            for i in 0..SHA512_DIGEST_SIZE {
                assert_eq!(payload.verify_data.data[i], 0x5au8);
            }
        }
    }
    #[test]
    fn test_case13_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseFinishRsp,
            },
            payload: SpdmMessagePayload::SpdmFinishResponse(SpdmFinishResponsePayload {
                verify_data: SpdmDigestStruct {
                    data_size: SPDM_MAX_HASH_SIZE as u16,
                    data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };
        create_spdm_context!(context);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.req_capabilities_sel =
            SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        context.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseFinishRsp
        );
        if let SpdmMessagePayload::SpdmFinishResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.verify_data.data_size, SHA512_DIGEST_SIZE as u16);
            for i in 0..SHA512_DIGEST_SIZE {
                assert_eq!(payload.verify_data.data[i], 100u8);
            }
        }
    }
    #[test]
    fn test_case114_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestPskExchange,
            },
            payload: SpdmMessagePayload::SpdmPskExchangeRequest(SpdmPskExchangeRequestPayload {
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
            }),
        };
        create_spdm_context!(context);

        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestPskExchange
        );
        if let SpdmMessagePayload::SpdmPskExchangeRequest(payload) = &spdm_message.payload {
            assert_eq!(
                payload.measurement_summary_hash_type,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone
            );
            assert_eq!(payload.psk_hint.data_size, MAX_SPDM_PSK_HINT_SIZE as u16);
            assert_eq!(
                payload.psk_context.data_size,
                MAX_SPDM_PSK_CONTEXT_SIZE as u16
            );
            assert_eq!(payload.opaque.data_size, MAX_SPDM_OPAQUE_SIZE as u16);
            for i in 0..MAX_SPDM_PSK_HINT_SIZE {
                assert_eq!(payload.psk_hint.data[i], 100);
            }
            for i in 0..MAX_SPDM_PSK_CONTEXT_SIZE {
                assert_eq!(payload.psk_context.data[i], 100);
            }
            for i in 0..MAX_SPDM_OPAQUE_SIZE {
                assert_eq!(payload.opaque.data[i], 100);
            }
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponsePskExchangeRsp,
            },
            payload: SpdmMessagePayload::SpdmPskExchangeResponse(SpdmPskExchangeResponsePayload {
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
            }),
        };
        create_spdm_context!(context);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.runtime_info.need_measurement_summary_hash = true;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponsePskExchangeRsp
        );
        if let SpdmMessagePayload::SpdmPskExchangeResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.heartbeat_period, 0xaau8);
            assert_eq!(payload.rsp_session_id, 0xaa55u16);

            assert_eq!(
                payload.measurement_summary_hash.data_size,
                SHA512_DIGEST_SIZE as u16
            );
            assert_eq!(
                payload.psk_context.data_size,
                MAX_SPDM_PSK_CONTEXT_SIZE as u16
            );
            assert_eq!(payload.opaque.data_size, MAX_SPDM_OPAQUE_SIZE as u16);
            assert_eq!(payload.verify_data.data_size, SHA512_DIGEST_SIZE as u16);

            for i in 0..SHA512_DIGEST_SIZE {
                assert_eq!(payload.measurement_summary_hash.data[i], 100);
            }
            for i in 0..MAX_SPDM_PSK_CONTEXT_SIZE {
                assert_eq!(payload.psk_context.data[i], 100);
            }
            for i in 0..MAX_SPDM_OPAQUE_SIZE {
                assert_eq!(payload.opaque.data[i], 100);
            }
            for i in 0..SHA512_DIGEST_SIZE {
                assert_eq!(payload.verify_data.data[i], 100u8);
            }
        }
    }
    #[test]
    fn test_case15_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestPskFinish,
            },
            payload: SpdmMessagePayload::SpdmPskFinishRequest(SpdmPskFinishRequestPayload {
                verify_data: SpdmDigestStruct {
                    data_size: SPDM_MAX_HASH_SIZE as u16,
                    data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };
        create_spdm_context!(context);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestPskFinish
        );
        if let SpdmMessagePayload::SpdmPskFinishRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.verify_data.data_size, SHA512_DIGEST_SIZE as u16);
            for i in 0..SHA512_DIGEST_SIZE {
                assert_eq!(payload.verify_data.data[i], 100u8);
            }
        }
    }
    #[test]
    fn test_case17_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateRequest(SpdmKeyUpdateRequestPayload {
                key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateAllKeys,
                tag: 100u8,
            }),
        };
        create_spdm_context!(context);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmKeyUpdateRequest(payload) = &spdm_message.payload {
            assert_eq!(
                payload.key_update_operation,
                SpdmKeyUpdateOperation::SpdmUpdateAllKeys
            );
            assert_eq!(payload.tag, 100);
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseKeyUpdateAck,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateResponse(SpdmKeyUpdateResponsePayload {
                key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateAllKeys,
                tag: 100u8,
            }),
        };
        create_spdm_context!(context);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseKeyUpdateAck
        );
        if let SpdmMessagePayload::SpdmKeyUpdateResponse(payload) = &spdm_message.payload {
            assert_eq!(
                payload.key_update_operation,
                SpdmKeyUpdateOperation::SpdmUpdateAllKeys
            );
            assert_eq!(payload.tag, 100);
        }
    }
    #[test]
    fn test_case18_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestEndSession,
            },
            payload: SpdmMessagePayload::SpdmEndSessionRequest(SpdmEndSessionRequestPayload {
                end_session_request_attributes:
                    SpdmEndSessionRequestAttributes::PRESERVE_NEGOTIATED_STATE,
            }),
        };
        create_spdm_context!(context);
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestEndSession
        );
        if let SpdmMessagePayload::SpdmEndSessionRequest(payload) = &spdm_message.payload {
            assert_eq!(
                payload.end_session_request_attributes,
                SpdmEndSessionRequestAttributes::PRESERVE_NEGOTIATED_STATE
            );
        }
    }
    #[test]
    fn test_case19_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseError,
            },
            payload: SpdmMessagePayload::SpdmErrorResponse(SpdmErrorResponsePayload {
                error_code: SpdmErrorCode::SpdmErrorResponseNotReady,
                error_data: 100,
                extended_data: SpdmErrorResponseExtData::SpdmErrorExtDataNotReady(
                    SpdmErrorResponseNotReadyExtData {
                        rdt_exponent: 100,
                        request_code: 100,
                        token: 100,
                        rdtm: 100,
                    },
                ),
            }),
        };
        create_spdm_context!(context);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseError
        );
        if let SpdmMessagePayload::SpdmErrorResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.error_code, SpdmErrorCode::SpdmErrorResponseNotReady);
            assert_eq!(payload.error_data, 100);
            if let SpdmErrorResponseExtData::SpdmErrorExtDataNotReady(extended_data) =
                &payload.extended_data
            {
                assert_eq!(extended_data.rdt_exponent, 100);
                assert_eq!(extended_data.request_code, 100);
                assert_eq!(extended_data.token, 100);
                assert_eq!(extended_data.rdtm, 100);
            }
        }
    }
    #[test]
    fn test_case20_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetVersion,
            },
            payload: SpdmMessagePayload::SpdmGetVersionRequest(SpdmGetVersionRequestPayload {}),
        };

        create_spdm_context!(context);
        new_spdm_message(value, context);
    }
    #[test]
    fn test_case21_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetDigests,
            },
            payload: SpdmMessagePayload::SpdmGetDigestsRequest(SpdmGetDigestsRequestPayload {}),
        };

        create_spdm_context!(context);
        new_spdm_message(value, context);
    }
    #[test]
    fn test_case22_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetCertificate,
            },
            payload: SpdmMessagePayload::SpdmGetCertificateRequest(
                SpdmGetCertificateRequestPayload {
                    slot_id: 100,
                    offset: 100,
                    length: 100,
                },
            ),
        };

        create_spdm_context!(context);
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestGetCertificate
        );
        if let SpdmMessagePayload::SpdmGetCertificateRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_id, 100);
            assert_eq!(payload.offset, 100);
            assert_eq!(payload.length, 100);
        }
    }
    #[test]
    fn test_case23_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponsePskFinishRsp,
            },
            payload: SpdmMessagePayload::SpdmPskFinishResponse(SpdmPskFinishResponsePayload {}),
        };
        create_spdm_context!(context);
        new_spdm_message(value, context);
    }
    #[test]
    fn test_case24_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestHeartbeat,
            },
            payload: SpdmMessagePayload::SpdmHeartbeatRequest(SpdmHeartbeatRequestPayload {}),
        };
        create_spdm_context!(context);
        new_spdm_message(value, context);
    }
    #[test]
    fn test_case25_spdm_message() {
        let _value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseEndSessionAck,
            },
            payload: SpdmMessagePayload::SpdmEndSessionResponse(SpdmEndSessionResponsePayload {}),
        };
        create_spdm_context!(context);
    }
    #[test]
    fn test_case26_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::Unknown(0),
            },
            payload: SpdmMessagePayload::SpdmEndSessionResponse(SpdmEndSessionResponsePayload {}),
        };
        create_spdm_context!(context);
        let u8_slice = &mut [0u8; 1000];
        let mut writer = Writer::init(u8_slice);
        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        let spdm_message = SpdmMessage::spdm_read(&mut context, &mut reader);
        assert_eq!(spdm_message.is_none(), true);
    }

    #[test]
    fn test_case27_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmDigestsResponse(SpdmDigestsResponsePayload {
                slot_mask: 0b11111111,
                digests: gen_array_clone(
                    SpdmDigestStruct {
                        data_size: SPDM_MAX_HASH_SIZE as u16,
                        data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
                    },
                    SPDM_MAX_SLOT_NUMBER,
                ),
            }),
        };
        create_spdm_context!(context);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseDigests
        );
        if let SpdmMessagePayload::SpdmDigestsResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_mask, 0b11111111);
            assert_eq!(payload.digests[1].data_size, SHA512_DIGEST_SIZE as u16);
            assert_eq!(payload.digests[1].data[1], 100u8);
        }
    }
    #[test]
    fn test_case28_spdm_message() {
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseHeartbeatAck,
            },
            payload: SpdmMessagePayload::SpdmHeartbeatResponse(SpdmHeartbeatResponsePayload {}),
        };
        create_spdm_context!(context);
        new_spdm_message(value, context);
    }
}

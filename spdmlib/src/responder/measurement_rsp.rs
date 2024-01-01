// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::opaque::{SpdmOpaqueStruct, MAX_SPDM_OPAQUE_SIZE};
#[cfg(feature = "hashed-transcript-data")]
use crate::common::ManagedBuffer12Sign;
#[cfg(not(feature = "hashed-transcript-data"))]
use crate::common::ManagedBufferL1L2;
use crate::common::SpdmCodec;
use crate::common::SpdmConnectionState;
use crate::common::SpdmMeasurementContentChanged;
use crate::crypto;
use crate::error::SpdmResult;
use crate::error::SPDM_STATUS_BUFFER_FULL;
use crate::error::SPDM_STATUS_CRYPTO_ERROR;
use crate::error::SPDM_STATUS_INVALID_MSG_FIELD;
#[cfg(not(feature = "hashed-transcript-data"))]
use crate::error::SPDM_STATUS_INVALID_PARAMETER;
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use crate::error::SPDM_STATUS_INVALID_STATE_PEER;
use crate::error::SPDM_STATUS_NOT_READY_PEER;
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;
use crate::secret;

impl ResponderContext {
    pub fn handle_spdm_measurement<'a>(
        &mut self,
        session_id: Option<u32>,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let (status, rsp_slice) = self.write_spdm_measurement_response(session_id, bytes, writer);

        if let Err(e) = status {
            if e != SPDM_STATUS_NOT_READY_PEER {
                self.common.reset_message_m(session_id);
            }
        }

        (Ok(()), rsp_slice)
    }

    pub fn write_spdm_measurement_response<'a>(
        &mut self,
        session_id: Option<u32>,
        bytes: &[u8],
        writer: &'a mut Writer<'_>,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        if self.common.runtime_info.get_connection_state().get_u8()
            < SpdmConnectionState::SpdmConnectionNegotiated.get_u8()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_PEER),
                Some(writer.used_slice()),
            );
        }
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestGetMeasurements,
            session_id,
        );

        let get_measurements =
            SpdmGetMeasurementsRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_measurements) = &get_measurements {
            debug!("!!! get_measurements : {:02x?}\n", get_measurements);
        } else {
            error!("!!! get_measurements : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }
        let get_measurements = get_measurements.unwrap();
        let slot_id = get_measurements.slot_id as usize;

        let signature_size = self.common.negotiate_info.base_asym_sel.get_size();

        if get_measurements
            .measurement_attributes
            .contains(SpdmMeasurementAttributes::SIGNATURE_REQUESTED)
        {
            self.common.runtime_info.need_measurement_signature = true;

            if slot_id >= SPDM_MAX_SLOT_NUMBER {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
            if self.common.provision_info.my_cert_chain[slot_id].is_none() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                    Some(writer.used_slice()),
                );
            }
        } else {
            self.common.runtime_info.need_measurement_signature = false;

            if slot_id != 0 {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
        }

        let measurement_hash_sel = self.common.negotiate_info.measurement_hash_sel;
        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let measurement_specification_sel =
            self.common.negotiate_info.measurement_specification_sel;
        let runtime_content_change_support = self.common.config_info.runtime_content_change_support;
        let content_changed = self.common.runtime_info.content_changed;
        let base_asym_sel = self.common.negotiate_info.base_asym_sel;

        if self
            .common
            .append_message_m(session_id, &bytes[..reader.used()])
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        let number_of_measurement = secret::measurement::measurement_collection(
            spdm_version_sel,
            measurement_specification_sel,
            measurement_hash_sel,
            SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber.get_u8() as usize,
        )
        .unwrap()
        .number_of_blocks;

        let measurement_record = if get_measurements.measurement_operation
            == SpdmMeasurementOperation::SpdmMeasurementRequestAll
        {
            secret::measurement::measurement_collection(
                spdm_version_sel,
                measurement_specification_sel,
                measurement_hash_sel,
                SpdmMeasurementOperation::SpdmMeasurementRequestAll.get_u8() as usize,
            )
            .unwrap()
        } else if let SpdmMeasurementOperation::Unknown(index) =
            get_measurements.measurement_operation
        {
            if index > number_of_measurement {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
            secret::measurement::measurement_collection(
                spdm_version_sel,
                measurement_specification_sel,
                measurement_hash_sel,
                index as usize,
            )
            .unwrap()
        } else {
            SpdmMeasurementRecordStructure::default()
        };

        let content_changed =
            if runtime_content_change_support && (spdm_version_sel >= SpdmVersion::SpdmVersion12) {
                content_changed
            } else {
                SpdmMeasurementContentChanged::NOT_SUPPORTED
            };

        let mut nonce = [0u8; SPDM_NONCE_SIZE];
        let res = crypto::rand::get_random(&mut nonce);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (Err(SPDM_STATUS_CRYPTO_ERROR), Some(writer.used_slice()));
        }

        info!("send spdm measurement\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseMeasurements,
            },
            payload: SpdmMessagePayload::SpdmMeasurementsResponse(
                SpdmMeasurementsResponsePayload {
                    number_of_measurement,
                    slot_id: get_measurements.slot_id,
                    content_changed,
                    measurement_record,
                    nonce: SpdmNonceStruct { data: nonce },
                    opaque: SpdmOpaqueStruct {
                        data_size: 0,
                        data: [0u8; MAX_SPDM_OPAQUE_SIZE],
                    },
                    signature: SpdmSignatureStruct {
                        data_size: signature_size,
                        data: [0x60u8; SPDM_MAX_ASYM_KEY_SIZE],
                    },
                    measurement_operation: get_measurements.measurement_operation,
                },
            ),
        };

        let res = response.spdm_encode(&mut self.common, writer);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }
        let used = writer.used();

        // generat signature
        if get_measurements
            .measurement_attributes
            .contains(SpdmMeasurementAttributes::SIGNATURE_REQUESTED)
        {
            let base_asym_size = base_asym_sel.get_size() as usize;
            let temp_used = used - base_asym_size;

            if self
                .common
                .append_message_m(session_id, &writer.used_slice()[..temp_used])
                .is_err()
            {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                    Some(writer.used_slice()),
                );
            }

            let signature = self.generate_measurement_signature(session_id);
            if signature.is_err() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                    Some(writer.used_slice()),
                );
            }
            let signature = signature.unwrap();
            // patch the message before send
            writer.mut_used_slice()[(used - base_asym_size)..used]
                .copy_from_slice(signature.as_ref());

            self.common.reset_message_m(session_id);
        } else if self
            .common
            .append_message_m(session_id, writer.used_slice())
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        (Ok(()), Some(writer.used_slice()))
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub fn generate_measurement_signature(
        &self,
        session_id: Option<u32>,
    ) -> SpdmResult<SpdmSignatureStruct> {
        let message_l1l2_hash = match session_id {
            Some(session_id) => crypto::hash::hash_ctx_finalize(
                self.common
                    .get_immutable_session_via_id(session_id)
                    .unwrap()
                    .runtime_info
                    .digest_context_l1l2
                    .as_ref()
                    .cloned()
                    .unwrap(),
            )
            .ok_or(SPDM_STATUS_CRYPTO_ERROR)?,
            None => crypto::hash::hash_ctx_finalize(
                self.common
                    .runtime_info
                    .digest_context_l1l2
                    .as_ref()
                    .cloned()
                    .unwrap(),
            )
            .ok_or(SPDM_STATUS_CRYPTO_ERROR)?,
        };
        debug!("message_l1l2_hash - {:02x?}", message_l1l2_hash.as_ref());

        let mut message_sign = ManagedBuffer12Sign::default();

        if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            message_sign.reset_message();
            message_sign
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_sign
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_6)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_sign
                .append_message(&SPDM_MEASUREMENTS_SIGN_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_sign
                .append_message(message_l1l2_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        } else {
            error!("hashed-transcript-data is unsupported in SPDM 1.0/1.1 signing!\n");
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        crate::secret::asym_sign::sign(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            message_sign.as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn generate_measurement_signature(
        &self,
        session_id: Option<u32>,
    ) -> SpdmResult<SpdmSignatureStruct> {
        let mut message_l1l2 = ManagedBufferL1L2::default();
        if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            let message_a = self.common.runtime_info.message_a.clone();
            message_l1l2
                .append_message(message_a.as_ref())
                .map_or_else(|| Err(SPDM_STATUS_BUFFER_FULL), |_| Ok(()))?;
        }

        match session_id {
            None => {
                message_l1l2
                    .append_message(self.common.runtime_info.message_m.as_ref())
                    .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            }
            Some(session_id) => {
                let session = if let Some(s) = self.common.get_immutable_session_via_id(session_id)
                {
                    s
                } else {
                    return Err(SPDM_STATUS_INVALID_PARAMETER);
                };
                message_l1l2
                    .append_message(session.runtime_info.message_m.as_ref())
                    .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            }
        }
        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        let message_l1l2_hash = crypto::hash::hash_all(
            self.common.negotiate_info.base_hash_sel,
            message_l1l2.as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;

        debug!("message_l1l2_hash - {:02x?}", message_l1l2_hash.as_ref());

        if self.common.negotiate_info.spdm_version_sel >= SpdmVersion::SpdmVersion12 {
            message_l1l2.reset_message();
            message_l1l2
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_l1l2
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_6)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_l1l2
                .append_message(&SPDM_MEASUREMENTS_SIGN_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_l1l2
                .append_message(message_l1l2_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        }

        crate::secret::asym_sign::sign(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            message_l1l2.as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)
    }
}

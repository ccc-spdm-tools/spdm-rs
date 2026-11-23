// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

// The AEAD limit data (AEADlimitOE) in the Secured Message opaque data, DSP0277 1.3.

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use spdmlib::common::opaque::*;
use spdmlib::common::SpdmContext;
use spdmlib::error::{
    SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_UNSUPPORTED_CAP,
};
use spdmlib::protocol::*;
use spdmlib::responder::ResponderContext;
use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;

fn new_context(version: SpdmVersion, aead_limit_exponent: u8) -> SpdmContext {
    let (mut config_info, provision_info) = create_info();
    config_info.aead_limit_exponent = aead_limit_exponent;
    let mut context = ResponderContext::new(
        Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            SharedBuffer::new(),
        )))),
        Arc::new(Mutex::new(PciDoeTransportEncap {})),
        config_info,
        provision_info,
    )
    .common;
    context.negotiate_info.spdm_version_sel = version;
    context.negotiate_info.other_params_support = SpdmAlgoOtherParams::OPAQUE_DATA_FMT1;
    context
}

fn secured_message_version(version: u8) -> SecuredMessageVersion {
    SecuredMessageVersion::try_from(version).unwrap()
}

// The opaque data of a KEY_EXCHANGE or PSK_EXCHANGE request: the supported versions.
fn supported_version_opaque(context: &mut SpdmContext) -> SpdmOpaqueStruct {
    let mut versions_list = [SecuredMessageVersion::default(); MAX_SECURE_SPDM_VERSION_COUNT];
    versions_list[0] = secured_message_version(DMTF_SECURE_SPDM_VERSION_12);
    versions_list[1] = secured_message_version(DMTF_SECURE_SPDM_VERSION_13);
    SpdmOpaqueStruct::from_sm_supported_ver_list_opaque(
        context,
        &SMSupportedVerListOpaque {
            secured_message_version_list: SecuredMessageVersionList {
                version_count: 2,
                versions_list,
            },
        },
    )
    .unwrap()
}

// The opaque data of a KEY_EXCHANGE or PSK_EXCHANGE response: the selected version.
fn version_selection_opaque(context: &mut SpdmContext) -> SpdmOpaqueStruct {
    SpdmOpaqueStruct::from_sm_version_sel_opaque(
        context,
        &SMVersionSelOpaque {
            secured_message_version: secured_message_version(DMTF_SECURE_SPDM_VERSION_13),
        },
    )
    .unwrap()
}

// Where the header counts the elements: OpaqueDataFmt1 from SPDM 1.2, the general one before.
fn total_elements_index(version: SpdmVersion) -> usize {
    if version >= SpdmVersion::SpdmVersion12 {
        0
    } else {
        5
    }
}

#[test]
fn test_append_and_get_aead_limit() {
    for version in [SpdmVersion::SpdmVersion11, SpdmVersion::SpdmVersion12] {
        let mut context = new_context(version, 0);
        let index = total_elements_index(version);

        // After the supported version list, as in a request.
        let mut opaque = supported_version_opaque(&mut context);
        assert_eq!(opaque.data[index], 1);
        assert_eq!(opaque.get_aead_limit_exponent(&context), Ok(None));
        let size = opaque.data_size;
        opaque.append_aead_limit(&context, 20).unwrap();
        assert_eq!(opaque.data[index], 2);
        assert_eq!(opaque.data_size, size + 8);
        assert_eq!(opaque.data_size % 4, 0);
        assert_eq!(opaque.get_aead_limit_exponent(&context), Ok(Some(20)));
        // The element that was there is still found.
        let versions = opaque
            .rsp_get_dmtf_supported_secure_spdm_version_list(&mut context)
            .unwrap();
        assert_eq!(versions.version_count, 2);

        // After the version selection, as in a response.
        let mut opaque = version_selection_opaque(&mut context);
        assert_eq!(opaque.get_aead_limit_exponent(&context), Ok(None));
        opaque.append_aead_limit(&context, 0).unwrap();
        assert_eq!(opaque.get_aead_limit_exponent(&context), Ok(Some(0)));
        assert_eq!(
            opaque.req_get_dmtf_secure_spdm_version_selection(&mut context),
            Some(secured_message_version(DMTF_SECURE_SPDM_VERSION_13))
        );

        let mut opaque = version_selection_opaque(&mut context);
        opaque.append_aead_limit(&context, 64).unwrap();
        assert_eq!(opaque.get_aead_limit_exponent(&context), Ok(Some(64)));
    }
}

#[test]
fn test_no_opaque_data_has_no_aead_limit() {
    let context = new_context(SpdmVersion::SpdmVersion12, 0);
    assert_eq!(
        SpdmOpaqueStruct::default().get_aead_limit_exponent(&context),
        Ok(None)
    );
}

#[test]
fn test_append_aead_limit_rejects_an_exponent_over_64() {
    let mut context = new_context(SpdmVersion::SpdmVersion12, 0);
    let mut opaque = version_selection_opaque(&mut context);
    let before = opaque;
    assert!(opaque.append_aead_limit(&context, 65).is_err());
    assert_eq!(opaque.data_size, before.data_size);
    assert_eq!(opaque.data, before.data);
}

#[test]
fn test_append_aead_limit_needs_opaque_data_format_1() {
    let mut context = new_context(SpdmVersion::SpdmVersion12, 0);
    let mut opaque = version_selection_opaque(&mut context);
    context.negotiate_info.other_params_support = SpdmAlgoOtherParams::empty();
    assert_eq!(
        opaque.append_aead_limit(&context, 20),
        Err(SPDM_STATUS_UNSUPPORTED_CAP)
    );
}

#[test]
fn test_append_aead_limit_needs_room() {
    let context = new_context(SpdmVersion::SpdmVersion12, 0);
    // One element that fills the opaque data up to its last 4 bytes, so that the AEAD limit
    // element does not fit.
    let mut opaque = SpdmOpaqueStruct::default();
    opaque.data[0] = 1;
    opaque.data[4] = DMTF_ID;
    opaque.data[5] = DMTF_VENDOR_LEN;
    let element_data_len = (MAX_SPDM_OPAQUE_SIZE - 4 - 4 - 4) as u16;
    opaque.data[6..8].copy_from_slice(&element_data_len.to_le_bytes());
    opaque.data_size = (MAX_SPDM_OPAQUE_SIZE - 4) as u16;
    let before = opaque;
    assert_eq!(
        opaque.append_aead_limit(&context, 20),
        Err(SPDM_STATUS_BUFFER_FULL)
    );
    assert_eq!(opaque.data_size, before.data_size);
    assert_eq!(opaque.data, before.data);
}

#[test]
fn test_get_aead_limit_exponent_rejects_a_malformed_element() {
    let mut context = new_context(SpdmVersion::SpdmVersion12, 0);
    let mut valid = version_selection_opaque(&mut context);
    valid.append_aead_limit(&context, 20).unwrap();
    // The AEAD limit element is after the 4 byte header and the 8 byte version selection:
    // ID, VendorLen, OpaqueElementDataLen (2), SMDataVersion, SMDataID, AeadLimitExponent.
    let element = 12;
    assert_eq!(valid.data[element + 5], AEAD_LIMIT_SM_DATA_ID);
    assert_eq!(valid.get_aead_limit_exponent(&context), Ok(Some(20)));

    // An exponent over 64.
    let mut opaque = valid;
    opaque.data[element + 6] = 65;
    assert_eq!(
        opaque.get_aead_limit_exponent(&context),
        Err(SPDM_STATUS_INVALID_MSG_FIELD)
    );

    // SMData that is not one byte.
    let mut opaque = valid;
    opaque.data[element + 2] = 4;
    assert_eq!(
        opaque.get_aead_limit_exponent(&context),
        Err(SPDM_STATUS_INVALID_MSG_FIELD)
    );
    let mut opaque = valid;
    opaque.data[element + 2] = 2;
    assert_eq!(
        opaque.get_aead_limit_exponent(&context),
        Err(SPDM_STATUS_INVALID_MSG_FIELD)
    );

    // An element that runs past the end of the data.
    let mut opaque = valid;
    opaque.data_size -= 4;
    assert_eq!(
        opaque.get_aead_limit_exponent(&context),
        Err(SPDM_STATUS_INVALID_MSG_FIELD)
    );

    // More elements than there are.
    let mut opaque = valid;
    opaque.data[0] = 3;
    opaque.data[element + 5] = 0xFF;
    assert_eq!(
        opaque.get_aead_limit_exponent(&context),
        Err(SPDM_STATUS_INVALID_MSG_FIELD)
    );

    // An element that is not from DMTF is not an AEAD limit.
    let mut opaque = valid;
    opaque.data[element] = 1;
    assert_eq!(opaque.get_aead_limit_exponent(&context), Ok(None));
}

#[test]
fn test_append_aead_limit_after_an_unpadded_last_element() {
    for version in [SpdmVersion::SpdmVersion11, SpdmVersion::SpdmVersion12] {
        let mut context = new_context(version, 0);
        let index = total_elements_index(version);

        // The last element has 1, 2 or 3 bytes of padding missing, or none (4 bytes of data).
        for data_len in 1..=4usize {
            let mut opaque = version_selection_opaque(&mut context);
            let start = opaque.data_size as usize;

            // A vendor defined element after it, without its padding.
            let vendor = [&[1u8, 0, data_len as u8, 0][..], &[9u8; 4][..data_len]].concat();
            opaque.data[start..start + vendor.len()].copy_from_slice(&vendor);
            opaque.data[index] = 2;
            opaque.data_size = (start + vendor.len()) as u16;
            // Bytes that are not zero where the padding and the new element go.
            let size = opaque.data_size as usize;
            opaque.data[size..size + 12].fill(0xFF);

            opaque.append_aead_limit(&context, 20).unwrap();

            // The new element is at the aligned end, after the padding.
            let aligned_end = start + ((vendor.len() + 3) & !3);
            assert_eq!(opaque.data_size as usize, aligned_end + 8);
            assert_eq!(opaque.data[index], 3);
            assert!(opaque.data[start + vendor.len()..aligned_end]
                .iter()
                .all(|byte| *byte == 0));
            assert_eq!(
                opaque.data[aligned_end..aligned_end + 8],
                [
                    DMTF_ID,
                    DMTF_VENDOR_LEN,
                    3,
                    0,
                    SM_DATA_VERSION,
                    AEAD_LIMIT_SM_DATA_ID,
                    20,
                    0
                ]
            );
            assert_eq!(opaque.get_aead_limit_exponent(&context), Ok(Some(20)));
        }
    }
}

#[test]
fn test_get_aead_limit_exponent_skips_other_elements() {
    let context = new_context(SpdmVersion::SpdmVersion12, 0);
    let mut opaque = SpdmOpaqueStruct::default();
    let data = [
        // OpaqueDataFmt1 header, with 2 elements.
        2,
        0,
        0,
        0, //
        // A vendor defined element, with a 2 byte VendorID and 3 bytes of data, then padding.
        1,
        2,
        9,
        9,
        3,
        0,
        7,
        7,
        7,
        0,
        0,
        0, //
        // The AEAD limit element.
        DMTF_ID,
        DMTF_VENDOR_LEN,
        3,
        0,
        SM_DATA_VERSION,
        AEAD_LIMIT_SM_DATA_ID,
        33,
        0,
    ];
    opaque.data[..data.len()].copy_from_slice(&data);
    opaque.data_size = data.len() as u16;
    assert_eq!(opaque.get_aead_limit_exponent(&context), Ok(Some(33)));

    // Another element of DMTF data before it, which is not an AEAD limit.
    let mut other = SpdmOpaqueStruct::default();
    let data = [
        2,
        0,
        0,
        0, //
        DMTF_ID,
        DMTF_VENDOR_LEN,
        3,
        0,
        SM_DATA_VERSION,
        SMDataId::VersionSelectionSmDataId.into(),
        0x13,
        0,
        DMTF_ID,
        DMTF_VENDOR_LEN,
        3,
        0,
        SM_DATA_VERSION,
        AEAD_LIMIT_SM_DATA_ID,
        7,
        0,
    ];
    other.data[..data.len()].copy_from_slice(&data);
    other.data_size = data.len() as u16;
    assert_eq!(other.get_aead_limit_exponent(&context), Ok(Some(7)));
}

#[test]
fn test_the_default_aead_limit_is_not_advertised() {
    for exponent in [0, 64, 65, 255] {
        let mut context = new_context(SpdmVersion::SpdmVersion12, exponent);
        assert_eq!(context.local_aead_limit_exponent(), 64);
        let mut opaque = supported_version_opaque(&mut context);
        let before = opaque;
        context.advertise_aead_limit(&mut opaque).unwrap();
        assert_eq!(opaque.data_size, before.data_size);
        assert_eq!(opaque.data, before.data);
    }
}

#[test]
fn test_a_smaller_aead_limit_is_advertised() {
    for exponent in [1, 20, 63] {
        let mut context = new_context(SpdmVersion::SpdmVersion12, exponent);
        assert_eq!(context.local_aead_limit_exponent(), exponent);
        let mut opaque = supported_version_opaque(&mut context);
        context.advertise_aead_limit(&mut opaque).unwrap();
        assert_eq!(opaque.get_aead_limit_exponent(&context), Ok(Some(exponent)));
    }
}

#[test]
fn test_session_aead_limit_exponent_is_the_smaller_one() {
    let context = new_context(SpdmVersion::SpdmVersion12, 20);
    assert_eq!(context.session_aead_limit_exponent(Some(8)), 8);
    assert_eq!(context.session_aead_limit_exponent(Some(30)), 20);
    assert_eq!(context.session_aead_limit_exponent(Some(20)), 20);
    // A peer without AEAD limit data has the default.
    assert_eq!(context.session_aead_limit_exponent(None), 20);

    let context = new_context(SpdmVersion::SpdmVersion12, 0);
    assert_eq!(context.session_aead_limit_exponent(Some(8)), 8);
    assert_eq!(context.session_aead_limit_exponent(None), 64);
}

#[test]
fn test_supports_aead_limit() {
    let mut context = new_context(SpdmVersion::SpdmVersion12, 0);
    assert!(context.supports_aead_limit());

    context.config_info.secure_spdm_version = [
        Some(secured_message_version(DMTF_SECURE_SPDM_VERSION_10)),
        Some(secured_message_version(DMTF_SECURE_SPDM_VERSION_12)),
        None,
        None,
    ];
    assert!(!context.supports_aead_limit());

    context.config_info.secure_spdm_version = [None; MAX_SECURE_SPDM_VERSION_COUNT];
    assert!(!context.supports_aead_limit());
    assert!(secured_message_version_has_aead_limit(
        &secured_message_version(DMTF_SECURE_SPDM_VERSION_13)
    ));
    assert!(!secured_message_version_has_aead_limit(
        &secured_message_version(DMTF_SECURE_SPDM_VERSION_12)
    ));
}

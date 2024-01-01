// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::error::{SpdmResult, SPDM_STATUS_VERIF_FAIL};
use crate::protocol::SpdmBaseAsymAlgo;

// Key Usage: Digital Signature Bit;
const RFC_5280_KEY_USAGE_DIGITAL_SIGNATURE_BIT: u8 = 0x80;
// reference: https://www.itu.int/rec/T-REC-X.690/en
// TAG
const ASN1_TAG_CLASS_UNIVERSAL_MASK: u8 = 0x0;
const ASN1_TAG_CLASS_CONTEXT_SPECIFIC_MASK: u8 = 0x80;

const ASN1_FORM_CONSTRUCTED_MASK: u8 = 0x20;

const ASN1_TAG_NUMBER_INTEGER: u8 = 0x2;
const ASN1_TAG_BIT_STRING: u8 = 0x3;
const ASN1_TAG_NUMBER_OBJECT_IDENTIFIER: u8 = 0x6;
const ASN1_TAG_NUMBER_SEQUENCE: u8 = 0x10;

const ASN1_TAG_SEQUENCE: u8 =
    ASN1_TAG_CLASS_UNIVERSAL_MASK | ASN1_FORM_CONSTRUCTED_MASK | ASN1_TAG_NUMBER_SEQUENCE;
const ASN1_TAG_EXPLICIT_EXTENSION: u8 = 0xA3;
const ASN1_TAG_EXTN_VALUE: u8 = 0x04;
const ASN1_LENGTH_MULTI_OCTET_MASK: u8 = 0x80;

const X509V3_VERSION: u8 = 2;
const OID_RSA_SHA256RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0bu8];
const OID_RSA_SHA384RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0cu8];
const OID_RSA_SHA512RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0du8];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02u8];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03u8];
const OID_DMTF_SPDM_DEVICE_INFO: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x01];
const OID_DMTF_SPDM_HARDWARE_IDENTITY: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x02];
const OID_DMTF_SPDM_EKU_RESPONDER_AUTH: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x03];
const OID_DMTF_SPDM_EKU_REQUESTER_AUTH: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x04];
const OID_DMTF_MUTABLE_CERTIFICATE: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x05];
const OID_DMTF_SPDM_EXTENSION: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x06];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
const OID_SUBJECT_ALTERNATIVE_NAME: &[u8] = &[0x55, 0x1D, 0x11];
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];

// reference: https://www.rfc-editor.org/rfc/rfc5280.txt
// IN DER encoded certificate chain slice
// OUT Ok certificate count
// OUT Error Mulformed certificate found
// checked:
// 1. version should be x509v3.
// 2. the algorithm is match for leaf certificate
// 3. no more or less bytes found
pub fn check_cert_chain_format(
    cert_chain: &[u8],
    base_asym_algo: SpdmBaseAsymAlgo,
) -> SpdmResult<usize> {
    let mut cc_walker = 0usize;
    let mut cert_count = 0usize;
    let cert_chain_size = cert_chain.len();

    while cc_walker < cert_chain_size {
        cc_walker = cc_walker + check_cert_format(&cert_chain[cc_walker..], base_asym_algo)?;
        cert_count += 1;
    }

    if cc_walker == cert_chain_size {
        Ok(cert_count)
    } else {
        Err(SPDM_STATUS_VERIF_FAIL)
    }
}

// IN DER encoded certificate slice
// OUT Ok cert size
// OUT Error Mulformed certificate found
fn check_cert_format(cert: &[u8], base_asym_algo: SpdmBaseAsymAlgo) -> SpdmResult<usize> {
    let mut c_walker = 0usize;
    let len = cert.len();

    check_tag_is_sequence(cert)?;
    c_walker += 1;

    let (body_size, bytes_consumed) = check_length(&cert[c_walker..])?;
    c_walker += bytes_consumed;

    if len == c_walker + body_size {
        c_walker += check_tbs_certificate(&cert[c_walker..], base_asym_algo, true)?;
        c_walker += check_signature_algorithm(&cert[c_walker..], base_asym_algo, true)?;
    } else {
        c_walker += check_tbs_certificate(&cert[c_walker..], base_asym_algo, false)?;
        c_walker += check_signature_algorithm(&cert[c_walker..], base_asym_algo, false)?;
    }

    c_walker += check_signature_value(&cert[c_walker..], base_asym_algo)?;

    if c_walker == 1 + bytes_consumed + body_size {
        Ok(c_walker)
    } else {
        Err(SPDM_STATUS_VERIF_FAIL)
    }
}

fn check_tbs_certificate(
    data: &[u8],
    base_asym_algo: SpdmBaseAsymAlgo,
    is_leaf_cert: bool,
) -> SpdmResult<usize> {
    let mut t_walker = 0usize;
    let len = data.len();

    check_tag_is_sequence(data)?;
    t_walker += 1;

    let (tbs_length, bytes_consumed) = check_length(&data[t_walker..])?;
    t_walker += bytes_consumed;

    let length_before_tbs = t_walker;

    if len < t_walker + tbs_length {
        return Err(SPDM_STATUS_VERIF_FAIL);
    }

    // version         [0]  EXPLICIT Version DEFAULT v1,
    let bytes_consumed = check_version(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // serialNumber         CertificateSerialNumber,
    let bytes_consumed = check_and_skip_common_tag(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // signature            AlgorithmIdentifier,
    check_tag_is_sequence(&data[t_walker..])?;
    t_walker += 1;
    let (signature_id_length, bytes_consumed) = check_length(&data[t_walker..])?;
    t_walker += bytes_consumed;

    if is_leaf_cert {
        check_object_identifier(&data[t_walker..], get_oid_by_base_asym_algo(base_asym_algo))?;
    } else {
        check_object_identifier(&data[t_walker..], None)?;
    }
    t_walker += signature_id_length;
    // issuer               Name,
    let bytes_consumed = check_name(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // validity             Validity,
    let bytes_consumed = check_validity(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // subject              Name,
    let bytes_consumed = check_name(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // subjectPublicKeyInfo SubjectPublicKeyInfo,
    let bytes_consumed = check_public_key_info(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    // subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    // extensions      [3]  EXPLICIT Extensions OPTIONAL

    // key_usage             EXTENSIONS,
    let (find_key_usage, key_usage_value) = get_key_usage_value(&data[t_walker..])?;
    // The digitalSignature bit SHOULD asserted when subject public key is used for verifying digital signatures
    // in an entity authentication service, a data origin authentication service, and/or an integrity service.
    let check_extensions_success = !(find_key_usage
        && (RFC_5280_KEY_USAGE_DIGITAL_SIGNATURE_BIT & key_usage_value
            != RFC_5280_KEY_USAGE_DIGITAL_SIGNATURE_BIT));
    // when key usage digitalSignature bit unset, it SHOULD return false.

    //extensions            EXTENSIONS,
    let (bytes_consumed, extension_data) = check_and_get_extensions(&data[t_walker..])?;
    let check_extn_spdm_success = check_extensions_spdm_oid(extension_data, is_leaf_cert)?;
    t_walker += bytes_consumed;

    if (t_walker == length_before_tbs + tbs_length)
        && check_extensions_success
        && check_extn_spdm_success
    {
        Ok(length_before_tbs + tbs_length)
    } else {
        Err(SPDM_STATUS_VERIF_FAIL)
    }
}

fn check_signature_algorithm(
    data: &[u8],
    base_asym_algo: SpdmBaseAsymAlgo,
    is_leaf_cert: bool,
) -> SpdmResult<usize> {
    let mut s_walker = 0usize;
    // signature            AlgorithmIdentifier,
    check_tag_is_sequence(&data[s_walker..])?;
    s_walker += 1;
    let (signature_id_length, bytes_consumed) = check_length(&data[s_walker..])?;
    s_walker += bytes_consumed;

    if is_leaf_cert {
        check_object_identifier(&data[s_walker..], get_oid_by_base_asym_algo(base_asym_algo))?;
    } else {
        check_object_identifier(&data[s_walker..], None)?;
    }

    Ok(s_walker + signature_id_length)
}

fn check_signature_value(data: &[u8], _base_asym_algo: SpdmBaseAsymAlgo) -> SpdmResult<usize> {
    check_and_skip_common_tag(data)
}

fn check_tag_is_sequence(data: &[u8]) -> SpdmResult {
    if data.is_empty() {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else if data[0] == ASN1_TAG_SEQUENCE {
        Ok(())
    } else {
        Err(SPDM_STATUS_VERIF_FAIL)
    }
}

// IN bytes slice
// OUT Ok (length, bytes consumed)
// OUT Error Mulformed certificate found
fn check_length(data: &[u8]) -> SpdmResult<(usize, usize)> {
    let len = data.len();
    if len < 1 {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else if data[0] & ASN1_LENGTH_MULTI_OCTET_MASK == 0 {
        Ok((data[0] as usize, 1))
    } else {
        let length_count = data[0] - ASN1_LENGTH_MULTI_OCTET_MASK;
        if len < (length_count as usize + 1) || length_count == 0 || length_count > 8 {
            Err(SPDM_STATUS_VERIF_FAIL)
        } else {
            let mut length = [0u8; 8];
            for (i, b) in data[1..length_count as usize + 1].iter().rev().enumerate() {
                length[i] = *b;
            }
            Ok((usize::from_le_bytes(length), length_count as usize + 1))
        }
    }
}

fn check_version(data: &[u8]) -> SpdmResult<usize> {
    let len = data.len();
    if len < 5
        || data[0] != (ASN1_TAG_CLASS_CONTEXT_SPECIFIC_MASK | ASN1_FORM_CONSTRUCTED_MASK)
        || data[1] != 3
        || data[2] != ASN1_TAG_NUMBER_INTEGER
        || data[3] != 1
    {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else {
        let version = data[4];
        if version == X509V3_VERSION {
            Ok(5)
        } else {
            Err(SPDM_STATUS_VERIF_FAIL)
        }
    }
}

fn check_object_identifier(data: &[u8], oid: Option<&'static [u8]>) -> SpdmResult<usize> {
    let len = data.len();
    if len < 2 || data[0] != ASN1_TAG_NUMBER_OBJECT_IDENTIFIER {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else {
        let oid_length = data[1];
        if len < oid_length as usize + 2 || oid_length >= 0x80 {
            Err(SPDM_STATUS_VERIF_FAIL)
        } else if let Some(oid) = oid {
            if object_identifiers_are_same(&data[2..2 + oid_length as usize], oid) {
                Ok(oid_length as usize + 2)
            } else {
                Err(SPDM_STATUS_VERIF_FAIL)
            }
        } else {
            Ok(oid_length as usize + 2)
        }
    }
}

fn check_name(data: &[u8]) -> SpdmResult<usize> {
    check_and_skip_common_sequence(data)
}

fn check_validity(data: &[u8]) -> SpdmResult<usize> {
    check_and_skip_common_sequence(data)
}

fn check_public_key_info(data: &[u8]) -> SpdmResult<usize> {
    check_and_skip_common_sequence(data)
}

fn check_and_get_extensions(data: &[u8]) -> SpdmResult<(usize, &[u8])> {
    let len = data.len();
    if len < 1 || data[0] != ASN1_TAG_EXPLICIT_EXTENSION {
        Ok((len, &data[0..]))
    } else {
        let (payload_length, bytes_consumed) = check_length(&data[1..])?;
        if len < 1 + bytes_consumed + payload_length {
            Err(SPDM_STATUS_VERIF_FAIL)
        } else {
            Ok((
                1 + bytes_consumed + payload_length,
                &data[1 + bytes_consumed..1 + bytes_consumed + payload_length],
            ))
        }
    }
}

fn get_key_usage_value(data: &[u8]) -> SpdmResult<(bool, u8)> {
    let mut find_key_usage = false;
    let len = data.len();
    let key_usage_oid_len = OID_KEY_USAGE.len();
    let (data_length, bytes_consumed) = check_length(&data[1..])?;
    if len < 1 + data_length + bytes_consumed {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else {
        let mut index = 1 + bytes_consumed;
        while index < data_length {
            let (payload_length, bytes_consumed) = check_length(&data[index + 1..])?;
            if data[index] == ASN1_TAG_SEQUENCE {
                index += 1 + payload_length;
                continue;
            } else if data[index] == ASN1_TAG_NUMBER_OBJECT_IDENTIFIER
                && payload_length == key_usage_oid_len
                && object_identifiers_are_same(
                    &data[index + 1 + bytes_consumed..index + 1 + bytes_consumed + payload_length],
                    OID_KEY_USAGE,
                )
            {
                index += 1 + bytes_consumed + payload_length;
                if data[index] == ASN1_TAG_EXTN_VALUE {
                    let (_, extnvalue_consumed) = check_length(&data[index + 1..])?;
                    index += 1 + extnvalue_consumed;
                    if data[index] == ASN1_TAG_BIT_STRING {
                        let (string_length, string_consumed) = check_length(&data[index + 1..])?;
                        index += string_consumed + string_length;
                        find_key_usage = true;
                    } else {
                        find_key_usage = false;
                    }
                    break;
                } else {
                    index += 1 + bytes_consumed + payload_length;
                    continue;
                }
            } else {
                index += 1 + bytes_consumed + payload_length;
                continue;
            }
        }
        if find_key_usage {
            Ok((true, data[index]))
        } else {
            Ok((false, 0x00))
        }
    }
}

fn check_extensions_spdm_oid(extensions: &[u8], is_leaf_cert: bool) -> SpdmResult<bool> {
    let mut responder_auth_oid_find_success = false;
    let mut requester_auth_oid_find_success = false;
    let len = extensions.len();
    if len < 1 || extensions[0] != ASN1_TAG_SEQUENCE {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else {
        let (payload_length, sequences_bytes_consumed) = check_length(&extensions[1..])?;
        let extn_sequences = &extensions[1 + sequences_bytes_consumed..];
        let sequences_len = extn_sequences.len();
        if sequences_len < payload_length {
            Err(SPDM_STATUS_VERIF_FAIL)
        } else {
            let mut index = 0;
            while index < payload_length {
                let (extnid, extn_sequence_len) = check_and_get_extn_id(&extn_sequences[index..])?;
                // find the first level extension identifiy from extensions sequence
                if object_identifiers_are_same(extnid, OID_SUBJECT_ALTERNATIVE_NAME) {
                    if find_target_object_identifiers(
                        &extn_sequences[index..index + extn_sequence_len],
                        OID_DMTF_SPDM_DEVICE_INFO,
                    )? {
                        info!("find id-DMTF-device-info OID\n");
                    }
                    index += extn_sequence_len;
                    continue;
                } else if object_identifiers_are_same(extnid, OID_EXT_KEY_USAGE) {
                    if find_target_object_identifiers(
                        &extn_sequences[index..index + extn_sequence_len],
                        OID_DMTF_SPDM_EKU_RESPONDER_AUTH,
                    )? {
                        responder_auth_oid_find_success = true;
                        info!("find id-DMTF-eku-responder-auth OID\n");
                    } else if find_target_object_identifiers(
                        &extn_sequences[index..index + extn_sequence_len],
                        OID_DMTF_SPDM_EKU_REQUESTER_AUTH,
                    )? {
                        requester_auth_oid_find_success = true;
                        info!("find id-DMTF-eku-requester-auth OID\n");
                    }
                    index += extn_sequence_len;
                    continue;
                } else if object_identifiers_are_same(extnid, OID_DMTF_SPDM_EXTENSION) {
                    if find_target_object_identifiers(
                        &extn_sequences[index..index + extn_sequence_len],
                        OID_DMTF_MUTABLE_CERTIFICATE,
                    )? {
                        info!("find id-DMTF-mutable-certificate OID\n");
                    } else if find_target_object_identifiers(
                        &extn_sequences[index..index + extn_sequence_len],
                        OID_DMTF_SPDM_HARDWARE_IDENTITY,
                    )? {
                        info!("find id-DMTF-hardware-identity OID\n");
                    }
                    index += extn_sequence_len;
                    continue;
                } else {
                    index += extn_sequence_len;
                    continue;
                }
            }
            // if not the leaf certificate, reuester/responder auth OIDs SHOULD not be presented.
            Ok(!(!is_leaf_cert
                && (responder_auth_oid_find_success || requester_auth_oid_find_success)))
        }
    }
}

// IN  (sequences slice, target oid)
// OUT true when find target oid
// OUT false when not find target oid
fn find_target_object_identifiers(data: &[u8], target_oid: &[u8]) -> SpdmResult<bool> {
    let mut target_oid_find_success = false;
    let len = data.len();
    let target_oid_len = target_oid.len();
    if len < target_oid_len {
        target_oid_find_success = false;
    } else {
        let mut index = 0;
        while index < len - target_oid_len {
            let (payload_length, bytes_consumed) = check_length(&data[index + 1..])?;
            if data[index] == ASN1_TAG_NUMBER_OBJECT_IDENTIFIER {
                if object_identifiers_are_same(
                    &data[index + 1 + bytes_consumed..index + 1 + bytes_consumed + payload_length],
                    target_oid,
                ) && payload_length == target_oid_len
                {
                    target_oid_find_success = true;
                    break;
                } else {
                    index += 1 + bytes_consumed + payload_length;
                    continue;
                }
            } else if data[index] == ASN1_TAG_SEQUENCE || data[index] == ASN1_TAG_EXTN_VALUE {
                index += 1 + bytes_consumed;
                continue;
            } else {
                index += 1 + bytes_consumed + payload_length;
                continue;
            }
        }
    }
    Ok(target_oid_find_success)
}

// IN extension sequence slice
// OUT Ok (extnID, extn sequence length)
// OUT Error not found extnID, verify fail
fn check_and_get_extn_id(extn_sequences: &[u8]) -> SpdmResult<(&[u8], usize)> {
    let len = extn_sequences.len();
    if len < 1 || extn_sequences[0] != ASN1_TAG_SEQUENCE {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else {
        let (extn_payload_length, extn_bytes_consumed) = check_length(&extn_sequences[1..])?;
        if len < 1 + extn_bytes_consumed + extn_payload_length {
            Err(SPDM_STATUS_VERIF_FAIL)
        } else {
            // extnID is the first item in the extension sequence and the tag is Object identifier
            let extn_id = &extn_sequences[1 + extn_bytes_consumed..];
            if extn_id[0] != ASN1_TAG_NUMBER_OBJECT_IDENTIFIER {
                Err(SPDM_STATUS_VERIF_FAIL)
            } else {
                let (extn_id_length, extn_id_bytes_consumed) = check_length(&extn_id[1..])?;
                Ok((
                    &extn_id
                        [1 + extn_id_bytes_consumed..1 + extn_id_bytes_consumed + extn_id_length],
                    1 + extn_bytes_consumed + extn_payload_length,
                ))
            }
        }
    }
}

fn check_and_skip_common_sequence(data: &[u8]) -> SpdmResult<usize> {
    let len = data.len();
    if len < 1 || data[0] != ASN1_TAG_SEQUENCE {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else {
        let (payload_length, bytes_consumed) = check_length(&data[1..])?;
        if len < 1 + bytes_consumed + payload_length {
            Err(SPDM_STATUS_VERIF_FAIL)
        } else {
            Ok(1 + bytes_consumed + payload_length)
        }
    }
}

fn check_and_skip_common_tag(data: &[u8]) -> SpdmResult<usize> {
    let len = data.len();
    if len < 1 {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else {
        let (payload_length, bytes_consumed) = check_length(&data[1..])?;
        if len < 1 + bytes_consumed + payload_length {
            Err(SPDM_STATUS_VERIF_FAIL)
        } else {
            Ok(1 + bytes_consumed + payload_length)
        }
    }
}

fn check_and_get_common_tag(data: &[u8]) -> SpdmResult<(usize, &[u8])> {
    let len = data.len();
    if len < 1 {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else {
        let (payload_length, bytes_consumed) = check_length(&data[1..])?;
        if len < 1 + bytes_consumed + payload_length {
            Err(SPDM_STATUS_VERIF_FAIL)
        } else {
            Ok((
                1 + bytes_consumed + payload_length,
                &data[1 + bytes_consumed..1 + bytes_consumed + payload_length],
            ))
        }
    }
}

fn get_oid_by_base_asym_algo(base_asym_algo: SpdmBaseAsymAlgo) -> Option<&'static [u8]> {
    match base_asym_algo {
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048 => Some(OID_RSA_SHA256RSA),
        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048 => Some(OID_RSA_SHA256RSA),
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072 => Some(OID_RSA_SHA384RSA),
        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072 => Some(OID_RSA_SHA384RSA),
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256 => Some(OID_ECDSA_SHA256),
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096 => Some(OID_RSA_SHA512RSA),
        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096 => Some(OID_RSA_SHA512RSA),
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384 => Some(OID_ECDSA_SHA384),
        _ => None,
    }
}

fn object_identifiers_are_same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        false
    } else {
        for (ai, bi) in a.iter().zip(b.iter()) {
            match ai.cmp(bi) {
                core::cmp::Ordering::Equal => continue,
                _ => return false,
            }
        }
        true
    }
}

// test root cert by checking issuer name == subject name
pub fn is_root_certificate(cert: &[u8]) -> SpdmResult {
    let mut c_walker = 0usize;

    check_tag_is_sequence(cert)?;
    c_walker += 1;

    let (_, bytes_consumed) = check_length(&cert[c_walker..])?;
    c_walker += bytes_consumed;

    // tbs
    let data = &cert[c_walker..];
    let mut t_walker = 0usize;
    let len = data.len();

    check_tag_is_sequence(data)?;
    t_walker += 1;

    let (tbs_length, bytes_consumed) = check_length(&data[t_walker..])?;
    t_walker += bytes_consumed;

    if len < t_walker + tbs_length {
        return Err(SPDM_STATUS_VERIF_FAIL);
    }

    // version         [0]  EXPLICIT Version DEFAULT v1,
    let bytes_consumed = check_version(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // serialNumber         CertificateSerialNumber,
    let bytes_consumed = check_and_skip_common_tag(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // signature            AlgorithmIdentifier,
    check_tag_is_sequence(&data[t_walker..])?;
    t_walker += 1;
    let (signature_id_length, bytes_consumed) = check_length(&data[t_walker..])?;
    t_walker += bytes_consumed;

    check_object_identifier(&data[t_walker..], None)?;

    t_walker += signature_id_length;
    // issuer               Name,
    let (bytes_consumed, issuer) = check_and_get_common_tag(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // validity             Validity,
    let bytes_consumed = check_validity(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // subject              Name,
    let (_, subject) = check_and_get_common_tag(&data[t_walker..])?;

    if subject == issuer {
        Ok(())
    } else {
        Err(SPDM_STATUS_VERIF_FAIL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case0_object_identifiers_are_same() {
        let lt = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0bu8];
        let lt_wrong1 = [0x2b, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0bu8];
        let lt_wrong2 = [0x2b, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0xb0u8];
        let lt_empty: [u8; 0] = [];
        assert!(object_identifiers_are_same(&lt, OID_RSA_SHA256RSA));
        assert!(!object_identifiers_are_same(&lt, OID_RSA_SHA384RSA));
        assert!(!object_identifiers_are_same(&lt_wrong1, OID_RSA_SHA256RSA));
        assert!(!object_identifiers_are_same(&lt_wrong2, OID_RSA_SHA256RSA));
        assert!(!object_identifiers_are_same(&lt_empty, OID_RSA_SHA384RSA));
    }

    #[test]
    fn test_case0_get_oid_by_base_asym_algo() {
        assert_eq!(
            get_oid_by_base_asym_algo(SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048),
            Some(OID_RSA_SHA256RSA)
        );
        assert_eq!(
            get_oid_by_base_asym_algo(SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256),
            Some(OID_ECDSA_SHA256)
        );
    }

    #[test]
    fn test_case0_check_and_skip_common_tag() {
        let sq1 = [
            0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31, 0x00, 0xD7, 0x9C, 0x7F, 0x26, 0x91, 0x34,
            0xA5, 0x2B, 0x79, 0xEA, 0x66, 0x15, 0x00, 0x88, 0x0A, 0x4D, 0xE7, 0xAD, 0x71, 0xC6,
            0x2E, 0xE4, 0x7E, 0x37, 0xE1, 0x86, 0xEB, 0xE8, 0x55, 0xB0, 0x2F, 0xC5, 0xF3, 0xA9,
            0xE0, 0x90, 0xF9, 0x0B, 0x82, 0xC5, 0xDF, 0x4A, 0x35, 0x9A, 0x0D, 0x35, 0x38, 0x4B,
            0x02, 0x30, 0x40, 0xA7, 0xFE, 0x70, 0x39, 0x7B, 0x4B, 0xD7, 0xC2, 0x28, 0x72, 0x93,
            0x93, 0x0C, 0x62, 0x12, 0x14, 0xF0, 0x70, 0x74, 0x0F, 0xFC, 0xB1, 0x21, 0x60, 0x40,
            0x6D, 0x13, 0xA3, 0x59, 0x0E, 0x27, 0x06, 0xC1, 0x73, 0x4E, 0xCA, 0x40, 0x4C, 0x2D,
            0xF5, 0x96, 0x48, 0x66, 0x05, 0xB1, 0xA6, 0x08,
        ];
        let sq2 = [0xA0, 0x03, 0x02, 0x01, 0x02];
        let sq3 = [0x01, 0x01, 0xFF];
        let sq4 = [0x01, 0x01, 0xFF, 0xAA];
        let sq1_wrong = [0x01, 0x02, 0xFF];
        assert_eq!(check_and_skip_common_tag(&sq1), Ok(106));
        assert_eq!(check_and_skip_common_tag(&sq2), Ok(5));
        assert_eq!(check_and_skip_common_tag(&sq3), Ok(3));
        assert_eq!(check_and_skip_common_tag(&sq4), Ok(3));
        assert_eq!(
            check_and_skip_common_tag(&sq1_wrong),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_check_object_identifier() {
        let oid1 = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
        let oid2 = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
        let oid3 = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        ];
        let oid1_wrong = [
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
        ];
        let oid2_wrong = [0x06, 0x08, 0x2A, 0x86];
        let oid3_wrong: [u8; 0] = [];
        assert_eq!(
            check_object_identifier(&oid1, Some(OID_ECDSA_SHA384)),
            Ok(10)
        );
        assert_eq!(
            check_object_identifier(&oid2, Some(OID_ECDSA_SHA256)),
            Ok(10)
        );
        assert_eq!(
            check_object_identifier(&oid3, Some(OID_RSA_SHA256RSA)),
            Ok(11)
        );
        assert_eq!(
            check_object_identifier(&oid1_wrong, Some(OID_ECDSA_SHA384)),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_object_identifier(&oid2_wrong, Some(OID_ECDSA_SHA384)),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_object_identifier(&oid3_wrong, Some(OID_ECDSA_SHA384)),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_check_version() {
        let v1 = [0xA0, 0x03, 0x02, 0x01, 0x02];
        let v1_wrong = [0xA0, 0x03, 0x02, 0x01, 0x01];
        let v2_wrong = [0x30, 0x03, 0x02, 0x01, 0x02];
        let v3_wrong = [0xA0, 0x03, 0x02, 0x01];
        assert_eq!(check_version(&v1), Ok(5));
        assert_eq!(check_version(&v1_wrong), Err(SPDM_STATUS_VERIF_FAIL));
        assert_eq!(check_version(&v2_wrong), Err(SPDM_STATUS_VERIF_FAIL));
        assert_eq!(check_version(&v3_wrong), Err(SPDM_STATUS_VERIF_FAIL));
    }

    #[test]
    fn test_case0_check_length() {
        let l1 = [0x03];
        let l2 = [0x81, 0x12];
        let l3 = [0x82, 0x01, 0xD7];
        let l1_wrong = [0x80];
        let l2_wrong = [0x81];
        let l3_wrong = [0x82, 0x01];
        assert_eq!(check_length(&l1), Ok((3, 1)));
        assert_eq!(check_length(&l2), Ok((0x12, 2)));
        assert_eq!(check_length(&l3), Ok((0x1D7, 3)));
        assert_eq!(check_length(&l1_wrong), Err(SPDM_STATUS_VERIF_FAIL));
        assert_eq!(check_length(&l2_wrong), Err(SPDM_STATUS_VERIF_FAIL));
        assert_eq!(check_length(&l3_wrong), Err(SPDM_STATUS_VERIF_FAIL));
    }

    #[test]
    fn test_case0_check_tag_is_sequence() {
        let l1 = [0x30];
        let l1_wrong = [0x80];
        let l2_wrong = [0x81];
        let l3_wrong = [0x82, 0x01];
        assert_eq!(check_tag_is_sequence(&l1), Ok(()));
        assert_eq!(
            check_tag_is_sequence(&l1_wrong),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_tag_is_sequence(&l2_wrong),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_tag_is_sequence(&l3_wrong),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_check_signature_algorithm() {
        let s1 = [
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
        ];
        let s1_wrong = [
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03,
        ];
        let s2_wrong = [0x06, 0x08, 0x2A, 0x86];
        let s3_wrong: [u8; 0] = [];
        assert_eq!(
            check_signature_algorithm(&s1, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384, true),
            Ok(12)
        );
        assert_eq!(
            check_signature_algorithm(&s1, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384, false),
            Ok(12)
        );
        assert_eq!(
            check_signature_algorithm(&s1, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256, false),
            Ok(12)
        );
        assert_eq!(
            check_signature_algorithm(&s1, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256, true),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_signature_algorithm(
                &s1_wrong,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                false
            ),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_signature_algorithm(
                &s2_wrong,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                false
            ),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_signature_algorithm(
                &s3_wrong,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                false
            ),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_check_tbs_certificate() {
        let t1 = std::fs::read("../test_key/ecp384/ca.cert.der").expect("unable to read ca cert!");
        let t2 =
            std::fs::read("../test_key/ecp384/inter.cert.der").expect("unable to read inter cert!");
        let t3 = std::fs::read("../test_key/ecp384/end_responder.cert.der")
            .expect("unable to read leaf cert!");

        let t1_wrong = [0x30, 0x82, 0x01, 0xA8, 0xA0];

        assert_eq!(
            check_tbs_certificate(
                &t1[4..],
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                false
            ),
            Ok(350)
        );
        assert_eq!(
            check_tbs_certificate(
                &t2[4..],
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                false
            ),
            Ok(357)
        );
        assert_eq!(
            check_tbs_certificate(
                &t3[4..],
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                false
            ),
            Ok(460)
        );
        assert_eq!(
            check_tbs_certificate(
                &t3[4..],
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                false
            ),
            Ok(460)
        );
        assert_eq!(
            check_tbs_certificate(
                &t3[4..],
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                true
            ),
            Ok(460)
        );
        assert_eq!(
            check_tbs_certificate(
                &t3[4..],
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                true
            ),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_tbs_certificate(
                &t1_wrong,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                false
            ),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_tbs_certificate(
                &t1_wrong,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                true
            ),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case1_check_tbs_certificate() {
        let t1 = std::fs::read("../test_key/rsa2048/end_requester_with_spdm_rsp_eku.cert.der")
            .expect("unable to read leaf cert!");
        let t2 = std::fs::read("../test_key/rsa2048/end_responder_with_spdm_req_eku.cert.der")
            .expect("unable to read leaf cert!");

        assert_eq!(
            check_tbs_certificate(&t1[4..], SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048, true),
            Ok(562)
        );
        assert_eq!(
            check_tbs_certificate(&t1[4..], SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048, false),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_tbs_certificate(&t2[4..], SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048, true),
            Ok(562)
        );
        assert_eq!(
            check_tbs_certificate(&t2[4..], SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048, false),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_check_cert_format() {
        let c1 = std::fs::read("../test_key/ecp384/ca.cert.der").expect("unable to read ca cert!");
        let c2 =
            std::fs::read("../test_key/ecp384/inter.cert.der").expect("unable to read inter cert!");
        let c3 = std::fs::read("../test_key/ecp384/end_responder.cert.der")
            .expect("unable to read leaf cert!");

        let c1_wrong = [0x30u8, 0x82, 0x01, 0xA8, 0xA0];

        assert_eq!(
            check_cert_format(&c1, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384),
            Ok(472)
        );
        assert_eq!(
            check_cert_format(&c2, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384),
            Ok(480)
        );
        assert_eq!(
            check_cert_format(&c3, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384),
            Ok(583)
        );
        assert_eq!(
            check_cert_format(&c3, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_cert_format(&c1_wrong, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_check_cert_chain_format() {
        let ct1 = std::fs::read("../test_key/ecp256/bundle_responder.certchain.der")
            .expect("unable to read ca cert!");
        let ct2 = std::fs::read("../test_key/ecp384/bundle_responder.certchain.der")
            .expect("unable to read ca cert!");
        let ct3 = std::fs::read("../test_key/rsa2048/bundle_responder.certchain.der")
            .expect("unable to read ca cert!");
        let ct4 = std::fs::read("../test_key/rsa3072/bundle_responder.certchain.der")
            .expect("unable to read ca cert!");
        let ct5 = std::fs::read("../test_key/rsa4096/bundle_responder.certchain.der")
            .expect("unable to read ca cert!");

        let ct1_wrong = [0x30, 0x82, 0x01, 0xA8, 0xA0];

        assert_eq!(
            check_cert_chain_format(&ct1, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256),
            Ok(3)
        );
        assert_eq!(
            check_cert_chain_format(&ct2, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384),
            Ok(3)
        );
        assert_eq!(
            check_cert_chain_format(&ct3, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048),
            Ok(3)
        );
        assert_eq!(
            check_cert_chain_format(&ct4, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072),
            Ok(3)
        );
        assert_eq!(
            check_cert_chain_format(&ct5, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096),
            Ok(3)
        );
        assert_eq!(
            check_cert_chain_format(&ct3, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_cert_chain_format(&ct1_wrong, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_is_root_certificate() {
        let ca1 = std::fs::read("../test_key/ecp256/ca.cert.der").expect("unable to read ca cert!");
        let ca2 =
            std::fs::read("../test_key/ecp256/ca1.cert.der").expect("unable to read ca1 cert!");
        let inter1 =
            std::fs::read("../test_key/ecp256/inter.cert.der").expect("unable to read inter cert!");
        let end1 = std::fs::read("../test_key/ecp256/end_requester1.cert.der")
            .expect("unable to read end cert!");
        let end2 = std::fs::read("../test_key/ecp256/end_responder1.cert.der")
            .expect("unable to read end cert!");

        let ct1_wrong = [0x30, 0x82, 0x01, 0xA8, 0xA0];

        assert!(is_root_certificate(&ca1).is_ok());
        assert!(is_root_certificate(&ca2).is_ok());

        assert!(is_root_certificate(&inter1).is_err());
        assert!(is_root_certificate(&end1).is_err());
        assert!(is_root_certificate(&end2).is_err());
        assert!(is_root_certificate(&ct1_wrong).is_err());
    }

    #[test]
    fn test_case0_get_key_usage_value() {
        let key_usage1 = &[
            0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x05, 0xE0,
        ];
        let key_usage2_wrong = &[
            0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x04, 0x03, 0x02, 0x05, 0xE0,
        ];
        let key_usage3_wrong = &[0x30, 0x0B];
        let key_usage4_wrong = &[
            0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x05,
        ];
        assert_eq!(get_key_usage_value(key_usage1), Ok((true, 0xE0)));
        assert_eq!(get_key_usage_value(key_usage2_wrong), Ok((false, 0x00)));
        assert_eq!(
            get_key_usage_value(key_usage3_wrong),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            get_key_usage_value(key_usage4_wrong),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_check_extensions_spdm_oid() {
        let e1 = std::fs::read("../test_key/ecp384/end_responder.cert.der")
            .expect("unable to read leaf cert!");
        let e2 = std::fs::read("../test_key/rsa2048/end_requester_with_spdm_rsp_eku.cert.der")
            .expect("unable to read leaf cert!");
        let e3 = std::fs::read("../test_key/rsa2048/end_responder_with_spdm_req_eku.cert.der")
            .expect("unable to read leaf cert!");
        assert_eq!(check_extensions_spdm_oid(&e1[280..], false), Ok(true));
        assert_eq!(check_extensions_spdm_oid(&e1[280..], true), Ok(true));
        assert_eq!(check_extensions_spdm_oid(&e2[450..], true), Ok(true));
        assert_eq!(check_extensions_spdm_oid(&e2[450..], false), Ok(false));
        assert_eq!(check_extensions_spdm_oid(&e3[450..], true), Ok(true));
        assert_eq!(check_extensions_spdm_oid(&e3[450..], false), Ok(false));
    }

    #[test]
    fn test_case0_check_and_get_extn_id() {
        let extension_s1 = &[
            0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00,
        ];
        let extension_s2 = &[
            0x30, 0x2A, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x01, 0x01, 0xFF, 0x04, 0x20, 0x30, 0x1E,
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06,
            0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07,
            0x03, 0x09,
        ];
        let extension_s3_wrong = &[
            0x30, 0x0D, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00,
        ];
        let extension_sa4_wrong = &[
            0x30, 0x0C, 0x05, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00,
        ];
        let oid1: &[u8] = &[0x55, 0x1D, 0x13];
        let oid2: &[u8] = &[0x55, 0x1D, 0x25];
        assert_eq!(check_and_get_extn_id(extension_s1), Ok((oid1, 14)));
        assert_eq!(check_and_get_extn_id(extension_s2), Ok((oid2, 44)));
        assert_eq!(
            check_and_get_extn_id(extension_s3_wrong),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_and_get_extn_id(extension_sa4_wrong),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_find_target_object_identifiers() {
        let extension_s1 = &[
            0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00,
        ];
        let extension_s2 = &[
            0x04, 0x2C, 0x30, 0x2A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2B, 0x06,
            0x01, 0x05, 0x05, 0x07, 0x03, 0x09, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83,
            0x1C, 0x82, 0x12, 0x04,
        ];
        let extension_s3_wrong = &[
            0x30, 0x0D, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00,
        ];
        let extension_sa4_wrong = &[
            0x30, 0x0C, 0x05, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00,
        ];
        assert_eq!(
            find_target_object_identifiers(extension_s1, &[0x55, 0x1D, 0x13]),
            Ok(true)
        );
        assert_eq!(
            find_target_object_identifiers(
                extension_s2,
                &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x04]
            ),
            Ok(true)
        );
        assert_eq!(
            find_target_object_identifiers(extension_s3_wrong, &[0x55, 0x1D, 0x14]),
            Ok(false)
        );
        assert_eq!(
            find_target_object_identifiers(extension_sa4_wrong, &[0x55, 0x1D, 0x13]),
            Ok(false)
        );
    }
}

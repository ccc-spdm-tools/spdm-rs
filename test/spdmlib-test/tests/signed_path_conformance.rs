// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(all(feature = "mut-auth", feature = "hashed-transcript-data"))]

use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use spdmlib::crypto;
use spdmlib::error::SPDM_STATUS_INVALID_CERT;
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::responder::ResponderContext;
use spdmlib_test::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use spdmlib_test::common::transport::PciDoeTransportEncap;
use spdmlib_test::common::util::create_info;
use spin::Mutex;
use std::sync::{Arc, Once};

// ── Minimal DER builder for ephemerally signed P-256 X.509 v3 test chains ──

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + content.len());
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
    out.extend_from_slice(content);
    out
}

fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for p in parts {
        body.extend_from_slice(p);
    }
    der_tlv(0x30, &body)
}

fn der_set(parts: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for p in parts {
        body.extend_from_slice(p);
    }
    der_tlv(0x31, &body)
}

fn der_oid(raw_body: &[u8]) -> Vec<u8> {
    der_tlv(0x06, raw_body)
}

fn der_int_u8(v: u8) -> Vec<u8> {
    der_tlv(0x02, &[v])
}

fn der_bool(v: bool) -> Vec<u8> {
    der_tlv(0x01, &[if v { 0xff } else { 0x00 }])
}

fn der_bit_string(unused_bits: u8, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + bytes.len());
    body.push(unused_bits);
    body.extend_from_slice(bytes);
    der_tlv(0x03, &body)
}

fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    der_tlv(0x04, bytes)
}

fn der_name_cn(cn: &str) -> Vec<u8> {
    // 2.5.4.3 = id-at-commonName
    let cn_oid = der_oid(&[0x55, 0x04, 0x03]);
    let cn_val = der_tlv(0x0c, cn.as_bytes());
    let atv = der_seq(&[&cn_oid, &cn_val]);
    let rdn = der_set(&[&atv]);
    der_seq(&[&rdn])
}

fn der_ecdsa_sha256_alg() -> Vec<u8> {
    // 1.2.840.10045.4.3.2
    let oid = der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
    der_seq(&[&oid])
}

fn der_p256_spki(pub_bytes: &[u8]) -> Vec<u8> {
    // id-ecPublicKey (1.2.840.10045.2.1), secp256r1 (1.2.840.10045.3.1.7)
    let ec_oid = der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
    let p256_oid = der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
    let alg = der_seq(&[&ec_oid, &p256_oid]);
    let pk = der_bit_string(0, pub_bytes);
    der_seq(&[&alg, &pk])
}

fn der_ext(oid_body: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let oid = der_oid(oid_body);
    let oct = der_octet_string(value);
    if critical {
        let crit = der_bool(true);
        der_seq(&[&oid, &crit, &oct])
    } else {
        der_seq(&[&oid, &oct])
    }
}

// Extension OID bodies
const OID_BC: &[u8] = &[0x55, 0x1d, 0x13]; // 2.5.29.19
const OID_KU: &[u8] = &[0x55, 0x1d, 0x0f]; // 2.5.29.15
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11]; // 2.5.29.17
const OID_NC: &[u8] = &[0x55, 0x1d, 0x1e]; // 2.5.29.30
const OID_EKU: &[u8] = &[0x55, 0x1d, 0x25]; // 2.5.29.37

// SPDM EKU OID bodies
const OID_SPDM_RSP_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1c, 0x82, 0x12, 0x03];
const OID_SPDM_REQ_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1c, 0x82, 0x12, 0x04];

fn ext_bc(critical: bool, ca: bool, path_len: Option<u8>) -> Vec<u8> {
    let mut body = Vec::new();
    if ca {
        body.extend_from_slice(&der_bool(true));
    }
    if let Some(pl) = path_len {
        body.extend_from_slice(&der_int_u8(pl));
    }
    let val = der_tlv(0x30, &body);
    der_ext(OID_BC, critical, &val)
}

fn ext_ku(critical: bool, bits: u8) -> Vec<u8> {
    let unused = bits.trailing_zeros().min(7) as u8;
    let val = der_bit_string(unused, &[bits]);
    der_ext(OID_KU, critical, &val)
}

fn ext_eku(critical: bool, oid_bodies: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for oid in oid_bodies {
        body.extend_from_slice(&der_oid(oid));
    }
    let val = der_tlv(0x30, &body);
    der_ext(OID_EKU, critical, &val)
}

fn ext_san_uri(uri: &str) -> Vec<u8> {
    // [6] IMPLICIT IA5String (uniformResourceIdentifier)
    let gn = der_tlv(0x86, uri.as_bytes());
    let val = der_seq(&[&gn]);
    der_ext(OID_SAN, false, &val)
}

fn ext_san_dns(dns: &str) -> Vec<u8> {
    // [2] IMPLICIT IA5String (dNSName)
    let gn = der_tlv(0x82, dns.as_bytes());
    let val = der_seq(&[&gn]);
    der_ext(OID_SAN, false, &val)
}

fn ext_name_constraints(permitted_gn: Option<&[u8]>, excluded_gn: Option<&[u8]>) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(gn) = permitted_gn {
        let subtree = der_seq(&[gn]);
        body.extend_from_slice(&der_tlv(0xa0, &subtree));
    }
    if let Some(gn) = excluded_gn {
        let subtree = der_seq(&[gn]);
        body.extend_from_slice(&der_tlv(0xa1, &subtree));
    }
    let val = der_tlv(0x30, &body);
    der_ext(OID_NC, true, &val)
}

fn gen_p256_key() -> EcdsaKeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap()
}

fn sign_cert(
    serial: u8,
    issuer_cn: &str,
    subject_cn: &str,
    subject_key: &EcdsaKeyPair,
    issuer_key: &EcdsaKeyPair,
    extensions: &[Vec<u8>],
) -> Vec<u8> {
    let version = der_tlv(0xa0, &der_int_u8(2)); // v3
    let serial_der = der_int_u8(serial);
    let sig_alg = der_ecdsa_sha256_alg();
    let issuer = der_name_cn(issuer_cn);
    let not_before = der_tlv(0x17, b"260101000000Z");
    let not_after = der_tlv(0x17, b"360101000000Z");
    let validity = der_seq(&[&not_before, &not_after]);
    let subject = der_name_cn(subject_cn);
    let spki = der_p256_spki(subject_key.public_key().as_ref());

    let mut tbs_fields: Vec<Vec<u8>> = vec![
        version, serial_der, sig_alg, issuer, validity, subject, spki,
    ];
    if !extensions.is_empty() {
        let mut ext_body = Vec::new();
        for ext in extensions {
            ext_body.extend_from_slice(ext);
        }
        let exts_seq = der_tlv(0x30, &ext_body);
        tbs_fields.push(der_tlv(0xa3, &exts_seq));
    }
    let refs: Vec<&[u8]> = tbs_fields.iter().map(|v| v.as_slice()).collect();
    let tbs = der_seq(&refs);

    let rng = SystemRandom::new();
    let sig = issuer_key.sign(&rng, &tbs).unwrap();
    let sig_bits = der_bit_string(0, sig.as_ref());
    let outer_sig_alg = der_ecdsa_sha256_alg();
    der_seq(&[&tbs, &outer_sig_alg, &sig_bits])
}

// KeyUsage bit masks (MSB-first in X.509 BIT STRING)
const KU_DIGITAL_SIGNATURE: u8 = 0x80; // bit 0
const KU_KEY_ENCIPHERMENT: u8 = 0x20; // bit 2
const KU_KEY_CERT_SIGN: u8 = 0x04; // bit 5

fn contexts_with_root(root_der: &[u8]) -> (RequesterContext, ResponderContext) {
    static CRYPTO_INIT: Once = Once::new();
    CRYPTO_INIT.call_once(|| {
        let ca = include_bytes!("../../../test_key/ecp256/ca.cert.der");
        assert!(crypto::hash::hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_256, ca).is_some());
        assert!(crypto::cert_operation::verify_cert_chain(
            ca,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
            SpdmPqcAsymAlgo::empty(),
            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
        )
        .is_ok());
    });
    let (req_config, mut req_provision) = create_info();
    let (rsp_config, mut rsp_provision) = create_info();
    req_provision.peer_root_cert_data.fill(None);
    rsp_provision.peer_root_cert_data.fill(None);
    let mut root_data = SpdmCertChainData {
        data_size: root_der.len() as u32,
        ..Default::default()
    };
    root_data.data[..root_der.len()].copy_from_slice(root_der);
    req_provision.peer_root_cert_data[0] = Some(root_data.clone());
    rsp_provision.peer_root_cert_data[0] = Some(root_data);

    let io = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
        SharedBuffer::new(),
    ))));
    let transport = Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let mut requester =
        RequesterContext::new(io.clone(), transport.clone(), req_config, req_provision);
    let mut responder = ResponderContext::new(io, transport, rsp_config, rsp_provision);
    for common in [&mut requester.common, &mut responder.common] {
        common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion13;
        common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
        common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
    }
    (requester, responder)
}

fn chain_buffer(certs: &[&[u8]]) -> SpdmCertChainBuffer {
    let root_hash = crypto::hash::hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_256, certs[0]).unwrap();
    let hash_len = root_hash.data_size as usize;
    let body: Vec<u8> = certs.iter().copied().flatten().copied().collect();
    let total_len = 4 + hash_len + body.len();
    let mut buf = SpdmCertChainBuffer {
        data_size: total_len as u32,
        ..Default::default()
    };
    buf.data[..4].copy_from_slice(&(total_len as u32).to_le_bytes());
    buf.data[4..4 + hash_len].copy_from_slice(root_hash.as_ref());
    buf.data[4 + hash_len..total_len].copy_from_slice(&body);
    buf
}

fn verify_both(
    root: &[u8],
    certs: &[&[u8]],
) -> (
    Result<(), spdmlib::error::SpdmStatus>,
    Result<(), spdmlib::error::SpdmStatus>,
) {
    let (mut req, mut rsp) = contexts_with_root(root);
    let buf = chain_buffer(certs);
    req.common.peer_info.peer_cert_chain_temp = Some(buf.clone());
    rsp.common.peer_info.peer_cert_chain_temp = Some(buf);
    (
        req.verify_spdm_certificate_chain(),
        rsp.verify_spdm_certificate_chain(),
    )
}

// ── C07: Validly linked signed intermediate missing keyCertSign ──

#[test]
fn signed_intermediate_missing_key_cert_sign_rejected_in_both_directions() {
    let root_key = gen_p256_key();
    let inter_key = gen_p256_key();
    let leaf_key = gen_p256_key();

    let root = sign_cert(
        1,
        "Test Root CA",
        "Test Root CA",
        &root_key,
        &root_key,
        &[ext_bc(true, true, None), ext_ku(true, KU_KEY_CERT_SIGN)],
    );
    let leaf = sign_cert(
        3,
        "Test Inter CA",
        "Test Leaf",
        &leaf_key,
        &inter_key,
        &[
            ext_bc(true, false, None),
            ext_ku(true, KU_DIGITAL_SIGNATURE),
        ],
    );

    // Control: intermediate asserts keyCertSign -> accepted in both directions.
    let good_inter = sign_cert(
        2,
        "Test Root CA",
        "Test Inter CA",
        &inter_key,
        &root_key,
        &[ext_bc(true, true, None), ext_ku(true, KU_KEY_CERT_SIGN)],
    );
    assert_eq!(
        verify_both(&root, &[&root, &good_inter, &leaf]),
        (Ok(()), Ok(()))
    );

    // Negative: validly linked intermediate omits keyCertSign (both critical & non-critical BC).
    for bc_critical in [true, false] {
        let bad_inter = sign_cert(
            2,
            "Test Root CA",
            "Test Inter CA",
            &inter_key,
            &root_key,
            &[
                ext_bc(bc_critical, true, None),
                ext_ku(true, KU_DIGITAL_SIGNATURE),
            ],
        );
        assert_eq!(
            verify_both(&root, &[&root, &bad_inter, &leaf]),
            (Err(SPDM_STATUS_INVALID_CERT), Err(SPDM_STATUS_INVALID_CERT))
        );
    }
}

// ── C09: Signed URI and DNS Name Constraints through both acceptance flows ──

#[test]
fn signed_uri_and_dns_name_constraints_enforced_in_both_directions() {
    let root_key = gen_p256_key();
    let inter_key = gen_p256_key();
    let leaf_key = gen_p256_key();

    // Permitted URI constraint: .example.com
    let uri_base = der_tlv(0x86, b".example.com");
    let root_uri = sign_cert(
        1,
        "URI NC Root",
        "URI NC Root",
        &root_key,
        &root_key,
        &[
            ext_bc(true, true, None),
            ext_ku(true, KU_KEY_CERT_SIGN),
            ext_name_constraints(Some(&uri_base), None),
        ],
    );
    let inter_uri = sign_cert(
        2,
        "URI NC Root",
        "URI NC Inter",
        &inter_key,
        &root_key,
        &[ext_bc(true, true, None), ext_ku(true, KU_KEY_CERT_SIGN)],
    );
    let good_uri_leaf = sign_cert(
        3,
        "URI NC Inter",
        "URI Leaf",
        &leaf_key,
        &inter_key,
        &[
            ext_bc(true, false, None),
            ext_ku(true, KU_DIGITAL_SIGNATURE),
            ext_san_uri("https://device.example.com/spdm"),
        ],
    );
    let bad_uri_leaf = sign_cert(
        4,
        "URI NC Inter",
        "URI Leaf",
        &leaf_key,
        &inter_key,
        &[
            ext_bc(true, false, None),
            ext_ku(true, KU_DIGITAL_SIGNATURE),
            ext_san_uri("https://attacker.invalid/spdm"),
        ],
    );

    assert_eq!(
        verify_both(&root_uri, &[&root_uri, &inter_uri, &good_uri_leaf]),
        (Ok(()), Ok(()))
    );
    assert_eq!(
        verify_both(&root_uri, &[&root_uri, &inter_uri, &bad_uri_leaf]),
        (Err(SPDM_STATUS_INVALID_CERT), Err(SPDM_STATUS_INVALID_CERT))
    );

    // Corrupting the signature on the accepting URI-NC leaf must still fail.
    let mut corrupt_leaf = good_uri_leaf;
    *corrupt_leaf.last_mut().unwrap() ^= 1;
    assert_eq!(
        verify_both(&root_uri, &[&root_uri, &inter_uri, &corrupt_leaf]),
        (Err(SPDM_STATUS_INVALID_CERT), Err(SPDM_STATUS_INVALID_CERT))
    );

    // Excluded URI constraint: .forbidden.example + Permitted DNS: example.com
    let excl_uri = der_tlv(0x86, b".forbidden.example");
    let perm_dns = der_tlv(0x82, b"example.com");
    let root_excl = sign_cert(
        5,
        "Mixed NC Root",
        "Mixed NC Root",
        &root_key,
        &root_key,
        &[
            ext_bc(true, true, None),
            ext_ku(true, KU_KEY_CERT_SIGN),
            ext_name_constraints(Some(&perm_dns), Some(&excl_uri)),
        ],
    );
    let inter_excl = sign_cert(
        6,
        "Mixed NC Root",
        "Mixed NC Inter",
        &inter_key,
        &root_key,
        &[ext_bc(true, true, None), ext_ku(true, KU_KEY_CERT_SIGN)],
    );
    let good_dns_leaf = sign_cert(
        7,
        "Mixed NC Inter",
        "DNS Leaf",
        &leaf_key,
        &inter_key,
        &[
            ext_bc(true, false, None),
            ext_ku(true, KU_DIGITAL_SIGNATURE),
            ext_san_dns("node.example.com"),
        ],
    );
    let excluded_uri_leaf = sign_cert(
        8,
        "Mixed NC Inter",
        "Excluded URI Leaf",
        &leaf_key,
        &inter_key,
        &[
            ext_bc(true, false, None),
            ext_ku(true, KU_DIGITAL_SIGNATURE),
            ext_san_uri("https://svc.forbidden.example/x"),
        ],
    );
    assert_eq!(
        verify_both(&root_excl, &[&root_excl, &inter_excl, &good_dns_leaf]),
        (Ok(()), Ok(()))
    );
    assert_eq!(
        verify_both(&root_excl, &[&root_excl, &inter_excl, &excluded_uri_leaf]),
        (Err(SPDM_STATUS_INVALID_CERT), Err(SPDM_STATUS_INVALID_CERT))
    );
}

// ── C05 / C06 / C08: Signed leaf KU/BC & malformed recognized extensions ──

#[test]
fn signed_leaf_constraints_and_malformed_recognized_extensions_rejected() {
    let root_key = gen_p256_key();
    let inter_key = gen_p256_key();
    let leaf_key = gen_p256_key();

    let root = sign_cert(
        1,
        "Ext Root",
        "Ext Root",
        &root_key,
        &root_key,
        &[ext_bc(true, true, None), ext_ku(true, KU_KEY_CERT_SIGN)],
    );
    let inter = sign_cert(
        2,
        "Ext Root",
        "Ext Inter",
        &inter_key,
        &root_key,
        &[ext_bc(true, true, None), ext_ku(true, KU_KEY_CERT_SIGN)],
    );

    // Leaf asserting keyCertSign alongside digitalSignature must be rejected.
    let leaf_key_cert_sign = sign_cert(
        3,
        "Ext Inter",
        "Leaf KCS",
        &leaf_key,
        &inter_key,
        &[
            ext_bc(true, false, None),
            ext_ku(true, KU_DIGITAL_SIGNATURE | KU_KEY_CERT_SIGN),
        ],
    );
    assert_eq!(
        verify_both(&root, &[&root, &inter, &leaf_key_cert_sign]),
        (Err(SPDM_STATUS_INVALID_CERT), Err(SPDM_STATUS_INVALID_CERT))
    );

    // Leaf missing digitalSignature in KeyUsage must be rejected.
    let leaf_no_ds = sign_cert(
        4,
        "Ext Inter",
        "Leaf NoDS",
        &leaf_key,
        &inter_key,
        &[ext_bc(true, false, None), ext_ku(true, KU_KEY_ENCIPHERMENT)],
    );
    assert_eq!(
        verify_both(&root, &[&root, &inter, &leaf_no_ds]),
        (Err(SPDM_STATUS_INVALID_CERT), Err(SPDM_STATUS_INVALID_CERT))
    );

    // Leaf with non-critical BC cA=FALSE and pathLenConstraint=0 must be rejected.
    let leaf_pathlen = sign_cert(
        5,
        "Ext Inter",
        "Leaf PathLen",
        &leaf_key,
        &inter_key,
        &[
            ext_bc(false, false, Some(0)),
            ext_ku(true, KU_DIGITAL_SIGNATURE),
        ],
    );
    assert_eq!(
        verify_both(&root, &[&root, &inter, &leaf_pathlen]),
        (Err(SPDM_STATUS_INVALID_CERT), Err(SPDM_STATUS_INVALID_CERT))
    );

    // Malformed non-critical BasicConstraints, KeyUsage, and empty/malformed EKU at leaf.
    let malformed_exts = [
        der_ext(OID_BC, false, &[0x05, 0x00]),
        der_ext(OID_KU, false, &[0x05, 0x00]),
        der_ext(OID_EKU, false, &[0x30, 0x00]),
        der_ext(OID_EKU, false, &[0x30, 0x01, 0xff]),
    ];
    for (idx, bad_ext) in malformed_exts.iter().enumerate() {
        let bad_leaf = sign_cert(
            10 + idx as u8,
            "Ext Inter",
            "Bad Ext Leaf",
            &leaf_key,
            &inter_key,
            std::slice::from_ref(bad_ext),
        );
        assert_eq!(
            verify_both(&root, &[&root, &inter, &bad_leaf]),
            (Err(SPDM_STATUS_INVALID_CERT), Err(SPDM_STATUS_INVALID_CERT)),
            "malformed leaf extension #{} must be rejected",
            idx
        );
    }

    // Malformed non-critical EKU on intermediate must also be rejected.
    let bad_inter_eku = sign_cert(
        20,
        "Ext Root",
        "Ext Inter",
        &inter_key,
        &root_key,
        &[
            ext_bc(true, true, None),
            ext_ku(true, KU_KEY_CERT_SIGN),
            der_ext(OID_EKU, false, &[0x30, 0x00]),
        ],
    );
    let good_leaf = sign_cert(
        21,
        "Ext Inter",
        "Good Leaf",
        &leaf_key,
        &inter_key,
        &[
            ext_bc(true, false, None),
            ext_ku(true, KU_DIGITAL_SIGNATURE),
        ],
    );
    assert_eq!(
        verify_both(&root, &[&root, &bad_inter_eku, &good_leaf]),
        (Err(SPDM_STATUS_INVALID_CERT), Err(SPDM_STATUS_INVALID_CERT))
    );
}

// ── S01 / C02: Signed absent-EKU leaf, issuer-placed EKU, and chain ordering ──

#[test]
fn signed_eku_placement_and_chain_ordering_vectors() {
    let root_key = gen_p256_key();
    let inter_key = gen_p256_key();
    let leaf_key = gen_p256_key();

    let root = sign_cert(
        1,
        "EKU Root",
        "EKU Root",
        &root_key,
        &root_key,
        &[ext_bc(true, true, None), ext_ku(true, KU_KEY_CERT_SIGN)],
    );
    let inter = sign_cert(
        2,
        "EKU Root",
        "EKU Inter",
        &inter_key,
        &root_key,
        &[ext_bc(true, true, None), ext_ku(true, KU_KEY_CERT_SIGN)],
    );

    // 1. Signed leaf with NO EKU extension -> accepted for both roles.
    let no_eku_leaf = sign_cert(
        3,
        "EKU Inter",
        "No EKU Leaf",
        &leaf_key,
        &inter_key,
        &[
            ext_bc(true, false, None),
            ext_ku(true, KU_DIGITAL_SIGNATURE),
        ],
    );
    assert_eq!(
        verify_both(&root, &[&root, &inter, &no_eku_leaf]),
        (Ok(()), Ok(()))
    );

    // 2. Signed leaf with Responder-only vs Requester-only EKU.
    let rsp_only_leaf = sign_cert(
        4,
        "EKU Inter",
        "Rsp EKU Leaf",
        &leaf_key,
        &inter_key,
        &[
            ext_bc(true, false, None),
            ext_ku(true, KU_DIGITAL_SIGNATURE),
            ext_eku(false, &[OID_SPDM_RSP_AUTH]),
        ],
    );
    assert_eq!(
        verify_both(&root, &[&root, &inter, &rsp_only_leaf]),
        (Ok(()), Err(SPDM_STATUS_INVALID_CERT))
    );

    let req_only_leaf = sign_cert(
        5,
        "EKU Inter",
        "Req EKU Leaf",
        &leaf_key,
        &inter_key,
        &[
            ext_bc(true, false, None),
            ext_ku(true, KU_DIGITAL_SIGNATURE),
            ext_eku(false, &[OID_SPDM_REQ_AUTH]),
        ],
    );
    assert_eq!(
        verify_both(&root, &[&root, &inter, &req_only_leaf]),
        (Err(SPDM_STATUS_INVALID_CERT), Ok(()))
    );

    // 3. Issuer-placed EKU does not block a leaf with valid EKU.
    let inter_with_eku = sign_cert(
        6,
        "EKU Root",
        "EKU Inter",
        &inter_key,
        &root_key,
        &[
            ext_bc(true, true, None),
            ext_ku(true, KU_KEY_CERT_SIGN),
            ext_eku(false, &[OID_SPDM_REQ_AUTH]),
        ],
    );
    assert_eq!(
        verify_both(&root, &[&root, &inter_with_eku, &rsp_only_leaf]),
        (Ok(()), Err(SPDM_STATUS_INVALID_CERT))
    );

    // 4. Reordered chain [root, leaf, inter] and missing intermediate [root, leaf] rejected (C02).
    assert_eq!(
        verify_both(&root, &[&root, &no_eku_leaf, &inter]),
        (Err(SPDM_STATUS_INVALID_CERT), Err(SPDM_STATUS_INVALID_CERT))
    );
    assert_eq!(
        verify_both(&root, &[&root, &no_eku_leaf]),
        (Err(SPDM_STATUS_INVALID_CERT), Err(SPDM_STATUS_INVALID_CERT))
    );
}

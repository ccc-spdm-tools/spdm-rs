// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(all(feature = "mut-auth", feature = "hashed-transcript-data"))]

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

const P256_ROOT: &[u8] = include_bytes!("../../../test_key/ecp256/ca.cert.der");
const P256_INTER: &[u8] = include_bytes!("../../../test_key/ecp256/inter.cert.der");
const P256_LEAF: &[u8] = include_bytes!("../../../test_key/ecp256/end_responder.cert.der");
const P256_DEVICE_CA: &[u8] =
    include_bytes!("../../../test_key/ecp256/end_responder_alias_cert_partial_set.cert.der");
const P256_ALIAS_LEAF: &[u8] =
    include_bytes!("../../../test_key/ecp256/end_responder_alias.cert.der");
const P384_ROOT: &[u8] = include_bytes!("../../../test_key/ecp384/ca.cert.der");

fn init_crypto() {
    static CRYPTO_INIT: Once = Once::new();
    CRYPTO_INIT.call_once(|| {
        assert!(crypto::hash::hash_all(SpdmBaseHashAlgo::TPM_ALG_SHA_256, P256_ROOT).is_some());
        assert!(crypto::cert_operation::verify_cert_chain(
            P256_ROOT,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
            SpdmPqcAsymAlgo::empty(),
            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
        )
        .is_ok());
    });
}

fn root_data(cert: &[u8]) -> SpdmCertChainData {
    let mut data = SpdmCertChainData {
        data_size: cert.len() as u32,
        ..Default::default()
    };
    data.data[..cert.len()].copy_from_slice(cert);
    data
}

fn contexts_with_roots(roots: &[&[u8]]) -> (RequesterContext, ResponderContext) {
    init_crypto();
    let (req_config, mut req_provision) = create_info();
    let (rsp_config, mut rsp_provision) = create_info();
    req_provision.peer_root_cert_data.fill(None);
    rsp_provision.peer_root_cert_data.fill(None);
    for (idx, root) in roots.iter().enumerate() {
        req_provision.peer_root_cert_data[idx] = Some(root_data(root));
        rsp_provision.peer_root_cert_data[idx] = Some(root_data(root));
    }
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

fn build_chain_buffer(
    root_for_hash: &[u8],
    wire_certs: &[&[u8]],
    hash_algo: SpdmBaseHashAlgo,
) -> SpdmCertChainBuffer {
    let root_hash = crypto::hash::hash_all(hash_algo, root_for_hash).unwrap();
    let hash_len = root_hash.data_size as usize;
    let certs_bytes: Vec<u8> = wire_certs.iter().copied().flatten().copied().collect();
    let total_len = 4 + hash_len + certs_bytes.len();
    let mut buf = SpdmCertChainBuffer {
        data_size: total_len as u32,
        ..Default::default()
    };
    buf.data[..4].copy_from_slice(&(total_len as u32).to_le_bytes());
    buf.data[4..4 + hash_len].copy_from_slice(root_hash.as_ref());
    buf.data[4 + hash_len..total_len].copy_from_slice(&certs_bytes);
    buf
}

// ── C03: Omitted-root chains ──

#[test]
fn omitted_root_chain_accepted_when_provisioned_root_matches_in_both_directions() {
    let (mut requester, mut responder) = contexts_with_roots(&[P256_ROOT]);
    let omitted = build_chain_buffer(
        P256_ROOT,
        &[P256_INTER, P256_LEAF],
        SpdmBaseHashAlgo::TPM_ALG_SHA_256,
    );
    requester.common.peer_info.peer_cert_chain_temp = Some(omitted.clone());
    responder.common.peer_info.peer_cert_chain_temp = Some(omitted);

    assert_eq!(requester.verify_spdm_certificate_chain(), Ok(()));
    assert_eq!(responder.verify_spdm_certificate_chain(), Ok(()));
}

#[test]
fn omitted_root_chain_rejected_when_unprovisioned_or_wrong_root() {
    let omitted = build_chain_buffer(
        P256_ROOT,
        &[P256_INTER, P256_LEAF],
        SpdmBaseHashAlgo::TPM_ALG_SHA_256,
    );

    for roots in [&[][..], &[P384_ROOT][..]] {
        let (mut requester, mut responder) = contexts_with_roots(roots);
        requester.common.peer_info.peer_cert_chain_temp = Some(omitted.clone());
        responder.common.peer_info.peer_cert_chain_temp = Some(omitted.clone());

        assert_eq!(
            requester.verify_spdm_certificate_chain(),
            Err(SPDM_STATUS_INVALID_CERT)
        );
        assert_eq!(
            responder.verify_spdm_certificate_chain(),
            Err(SPDM_STATUS_INVALID_CERT)
        );
    }
}

#[test]
fn omitted_root_chain_verifies_first_cert_signature_and_linkage_against_provisioned_root() {
    let (mut requester, mut responder) = contexts_with_roots(&[P256_ROOT]);

    // Corrupting the intermediate's signature must fail against the provisioned root.
    let mut bad_inter = P256_INTER.to_vec();
    *bad_inter.last_mut().unwrap() ^= 1;
    let corrupt_omitted = build_chain_buffer(
        P256_ROOT,
        &[&bad_inter, P256_LEAF],
        SpdmBaseHashAlgo::TPM_ALG_SHA_256,
    );
    requester.common.peer_info.peer_cert_chain_temp = Some(corrupt_omitted.clone());
    responder.common.peer_info.peer_cert_chain_temp = Some(corrupt_omitted);
    assert_eq!(
        requester.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );
    assert_eq!(
        responder.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );

    // Omitting the intermediate as well leaves leaf unlinked to P256_ROOT.
    let missing_inter =
        build_chain_buffer(P256_ROOT, &[P256_LEAF], SpdmBaseHashAlgo::TPM_ALG_SHA_256);
    requester.common.peer_info.peer_cert_chain_temp = Some(missing_inter.clone());
    responder.common.peer_info.peer_cert_chain_temp = Some(missing_inter);
    assert_eq!(
        requester.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );
    assert_eq!(
        responder.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );

    // Hashing a non-root intermediate as RootHash must not bypass root verification.
    let fake_root_hash = build_chain_buffer(
        P256_INTER,
        &[P256_INTER, P256_LEAF],
        SpdmBaseHashAlgo::TPM_ALG_SHA_256,
    );
    requester.common.peer_info.peer_cert_chain_temp = Some(fake_root_hash.clone());
    responder.common.peer_info.peer_cert_chain_temp = Some(fake_root_hash);
    assert_eq!(
        requester.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );
    assert_eq!(
        responder.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );

    // A non-self-issued certificate provisioned as peer_root_cert_data must not be accepted as root.
    let (mut req_bad_anchor, mut rsp_bad_anchor) = contexts_with_roots(&[P256_INTER]);
    let bad_anchor_chain =
        build_chain_buffer(P256_INTER, &[P256_LEAF], SpdmBaseHashAlgo::TPM_ALG_SHA_256);
    req_bad_anchor.common.peer_info.peer_cert_chain_temp = Some(bad_anchor_chain.clone());
    rsp_bad_anchor.common.peer_info.peer_cert_chain_temp = Some(bad_anchor_chain);
    assert_eq!(
        req_bad_anchor.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );
    assert_eq!(
        rsp_bad_anchor.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );
}

// ── C03 / S04: Single-certificate & AliasCert model rules ──

#[test]
fn alias_model_accepts_full_and_omitted_root_chains_and_rejects_single_cert() {
    let (mut requester, mut responder) = contexts_with_roots(&[P256_ROOT]);
    requester.common.negotiate_info.rsp_capabilities_sel |=
        SpdmResponseCapabilityFlags::ALIAS_CERT_CAP;
    responder.common.negotiate_info.multi_key_conn_req = true;
    responder.common.peer_info.peer_cert_info[0] =
        Some(SpdmCertificateModelType::SpdmCertModelTypeAliasCert);

    let full_alias = build_chain_buffer(
        P256_ROOT,
        &[P256_ROOT, P256_INTER, P256_DEVICE_CA, P256_ALIAS_LEAF],
        SpdmBaseHashAlgo::TPM_ALG_SHA_256,
    );
    requester.common.peer_info.peer_cert_chain_temp = Some(full_alias.clone());
    responder.common.peer_info.peer_cert_chain_temp = Some(full_alias);
    assert_eq!(requester.verify_spdm_certificate_chain(), Ok(()));
    assert_eq!(responder.verify_spdm_certificate_chain(), Ok(()));

    let omitted_alias = build_chain_buffer(
        P256_ROOT,
        &[P256_INTER, P256_DEVICE_CA, P256_ALIAS_LEAF],
        SpdmBaseHashAlgo::TPM_ALG_SHA_256,
    );
    requester.common.peer_info.peer_cert_chain_temp = Some(omitted_alias.clone());
    responder.common.peer_info.peer_cert_chain_temp = Some(omitted_alias);
    assert_eq!(requester.verify_spdm_certificate_chain(), Ok(()));
    assert_eq!(responder.verify_spdm_certificate_chain(), Ok(()));

    // A single self-signed certificate cannot satisfy AliasCert model.
    let single_cert =
        build_chain_buffer(P256_ROOT, &[P256_ROOT], SpdmBaseHashAlgo::TPM_ALG_SHA_256);
    requester.common.peer_info.peer_cert_chain_temp = Some(single_cert.clone());
    responder.common.peer_info.peer_cert_chain_temp = Some(single_cert);
    assert_eq!(
        requester.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );
    assert_eq!(
        responder.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );
}

// ── S06: Certificate-chain framing and RootHash validation ──

#[test]
fn framing_and_root_hash_mismatches_are_rejected_in_both_directions() {
    let valid = build_chain_buffer(
        P256_ROOT,
        &[P256_ROOT, P256_INTER, P256_LEAF],
        SpdmBaseHashAlgo::TPM_ALG_SHA_256,
    );

    // 1. Flipped bit in RootHash (both provisioned and unprovisioned).
    let mut bad_hash = valid.clone();
    bad_hash.data[4] ^= 0x01;
    for roots in [&[][..], &[P256_ROOT][..]] {
        let (mut requester, mut responder) = contexts_with_roots(roots);
        requester.common.peer_info.peer_cert_chain_temp = Some(bad_hash.clone());
        responder.common.peer_info.peer_cert_chain_temp = Some(bad_hash.clone());
        assert_eq!(
            requester.verify_spdm_certificate_chain(),
            Err(SPDM_STATUS_INVALID_CERT)
        );
        assert_eq!(
            responder.verify_spdm_certificate_chain(),
            Err(SPDM_STATUS_INVALID_CERT)
        );
    }

    // 2. Wrong hash algorithm framing (SHA-256 framed chain verified under SHA-384).
    let (mut requester, mut responder) = contexts_with_roots(&[P256_ROOT]);
    for common in [&mut requester.common, &mut responder.common] {
        common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        common.peer_info.peer_cert_chain_temp = Some(valid.clone());
    }
    assert_eq!(
        requester.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );
    assert_eq!(
        responder.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );

    // 3. Header length mismatch (too small and too large).
    let (mut requester, mut responder) = contexts_with_roots(&[P256_ROOT]);
    for delta in [-1i32, 1i32] {
        let mut bad_len = valid.clone();
        let mutated = (bad_len.data_size as i32 + delta) as u32;
        bad_len.data[..4].copy_from_slice(&mutated.to_le_bytes());
        requester.common.peer_info.peer_cert_chain_temp = Some(bad_len.clone());
        responder.common.peer_info.peer_cert_chain_temp = Some(bad_len);
        assert_eq!(
            requester.verify_spdm_certificate_chain(),
            Err(SPDM_STATUS_INVALID_CERT)
        );
        assert_eq!(
            responder.verify_spdm_certificate_chain(),
            Err(SPDM_STATUS_INVALID_CERT)
        );
    }

    // 4. Trailing extra bytes after the final DER certificate.
    let mut extra_bytes = valid.clone();
    let new_len = extra_bytes.data_size + 2;
    extra_bytes.data[extra_bytes.data_size as usize] = 0x00;
    extra_bytes.data[extra_bytes.data_size as usize + 1] = 0xff;
    extra_bytes.data_size = new_len;
    extra_bytes.data[..4].copy_from_slice(&new_len.to_le_bytes());
    requester.common.peer_info.peer_cert_chain_temp = Some(extra_bytes.clone());
    responder.common.peer_info.peer_cert_chain_temp = Some(extra_bytes);
    assert_eq!(
        requester.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );
    assert_eq!(
        responder.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );

    // 5. Truncated certificate bytes (length matches truncated buffer).
    let mut truncated = valid.clone();
    truncated.data_size -= 10;
    truncated.data[..4].copy_from_slice(&truncated.data_size.to_le_bytes());
    requester.common.peer_info.peer_cert_chain_temp = Some(truncated.clone());
    responder.common.peer_info.peer_cert_chain_temp = Some(truncated);
    assert_eq!(
        requester.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );
    assert_eq!(
        responder.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );

    // 6. Pre-1.4 non-zero reserved bytes in header [2..4].
    let mut bad_reserved = valid;
    bad_reserved.data[2] = 0x01;
    requester.common.peer_info.peer_cert_chain_temp = Some(bad_reserved.clone());
    responder.common.peer_info.peer_cert_chain_temp = Some(bad_reserved);
    assert_eq!(
        requester.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );
    assert_eq!(
        responder.verify_spdm_certificate_chain(),
        Err(SPDM_STATUS_INVALID_CERT)
    );
}

// ── S08: Explicit root trust policy matrix ──

#[test]
fn root_trust_policy_provisioned_match_mismatch_and_unprovisioned_modes() {
    let valid_chain = build_chain_buffer(
        P256_ROOT,
        &[P256_ROOT, P256_INTER, P256_LEAF],
        SpdmBaseHashAlgo::TPM_ALG_SHA_256,
    );

    // Policy A: Provisioned trust anchor matches (tested in slot 0 and secondary slot 1).
    for roots in [&[P256_ROOT][..], &[P384_ROOT, P256_ROOT][..]] {
        let (mut requester, mut responder) = contexts_with_roots(roots);
        requester.common.peer_info.peer_cert_chain_temp = Some(valid_chain.clone());
        responder.common.peer_info.peer_cert_chain_temp = Some(valid_chain.clone());
        assert_eq!(requester.verify_spdm_certificate_chain(), Ok(()));
        assert_eq!(responder.verify_spdm_certificate_chain(), Ok(()));
    }

    // Policy B: Provisioned trust anchor does not match the chain's root -> rejected.
    {
        let (mut requester, mut responder) = contexts_with_roots(&[P384_ROOT]);
        requester.common.peer_info.peer_cert_chain_temp = Some(valid_chain.clone());
        responder.common.peer_info.peer_cert_chain_temp = Some(valid_chain.clone());
        assert_eq!(
            requester.verify_spdm_certificate_chain(),
            Err(SPDM_STATUS_INVALID_CERT)
        );
        assert_eq!(
            responder.verify_spdm_certificate_chain(),
            Err(SPDM_STATUS_INVALID_CERT)
        );
    }

    // Policy C: Unprovisioned deployment mode accepts a cryptographically valid
    // included-root chain, while still rejecting signature corruption.
    {
        let (mut requester, mut responder) = contexts_with_roots(&[]);
        requester.common.peer_info.peer_cert_chain_temp = Some(valid_chain.clone());
        responder.common.peer_info.peer_cert_chain_temp = Some(valid_chain.clone());
        assert_eq!(requester.verify_spdm_certificate_chain(), Ok(()));
        assert_eq!(responder.verify_spdm_certificate_chain(), Ok(()));

        let mut corrupt = valid_chain;
        corrupt.data[corrupt.data_size as usize - 1] ^= 1;
        requester.common.peer_info.peer_cert_chain_temp = Some(corrupt.clone());
        responder.common.peer_info.peer_cert_chain_temp = Some(corrupt);
        assert_eq!(
            requester.verify_spdm_certificate_chain(),
            Err(SPDM_STATUS_INVALID_CERT)
        );
        assert_eq!(
            responder.verify_spdm_certificate_chain(),
            Err(SPDM_STATUS_INVALID_CERT)
        );
    }
}

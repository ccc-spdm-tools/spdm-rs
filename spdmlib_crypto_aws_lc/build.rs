// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use std::env;

fn any_feature_enabled(features: &[&str]) -> bool {
    features
        .iter()
        .any(|feature| env::var_os(feature).is_some())
}

fn emit_cfg(name: &str, enabled: bool) {
    println!("cargo:rustc-check-cfg=cfg({name})");
    if enabled {
        println!("cargo:rustc-cfg={name}");
    }
}

fn main() {
    let has_hash = any_feature_enabled(&[
        "CARGO_FEATURE_SHA256",
        "CARGO_FEATURE_SHA384",
        "CARGO_FEATURE_SHA512",
    ]);
    let has_ecdsa = any_feature_enabled(&["CARGO_FEATURE_ECDSA_P256", "CARGO_FEATURE_ECDSA_P384"]);
    let has_rsa = any_feature_enabled(&["CARGO_FEATURE_RSA_PKCS1", "CARGO_FEATURE_RSA_PSS"]);

    emit_cfg("spdm_has_hash", has_hash);
    emit_cfg(
        "spdm_has_aead",
        any_feature_enabled(&[
            "CARGO_FEATURE_AES_128_GCM",
            "CARGO_FEATURE_AES_256_GCM",
            "CARGO_FEATURE_CHACHA20_POLY1305",
        ]),
    );
    emit_cfg(
        "spdm_has_classical_asym",
        has_hash && (has_ecdsa || has_rsa),
    );
    emit_cfg("spdm_has_ecdsa", has_hash && has_ecdsa);
    emit_cfg("spdm_has_rsa", has_hash && has_rsa);
    emit_cfg(
        "spdm_has_ecdh",
        any_feature_enabled(&["CARGO_FEATURE_ECDH_P256", "CARGO_FEATURE_ECDH_P384"]),
    );
    emit_cfg(
        "spdm_has_ml_kem",
        any_feature_enabled(&[
            "CARGO_FEATURE_ML_KEM_512",
            "CARGO_FEATURE_ML_KEM_768",
            "CARGO_FEATURE_ML_KEM_1024",
        ]),
    );
    emit_cfg(
        "spdm_has_ml_dsa",
        any_feature_enabled(&[
            "CARGO_FEATURE_ML_DSA_44",
            "CARGO_FEATURE_ML_DSA_65",
            "CARGO_FEATURE_ML_DSA_87",
        ]),
    );
}

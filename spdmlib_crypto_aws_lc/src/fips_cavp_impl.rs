// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use spdmlib::crypto::fips::cavs_vectors::ml_kem_1024_encap_decap;
use spdmlib::crypto::fips::cavs_vectors::{ml_dsa_87_key_gen, ml_dsa_87_sig_gen_ver};
use spdmlib::error::{SpdmResult, SPDM_STATUS_FIPS_SELF_TEST_FAIL};

fn sha384_matches(data: &[u8], expected: &[u8; 48]) -> bool {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, data).as_ref() == expected
}

pub(crate) fn ml_dsa_87_cavp() -> SpdmResult {
    const PUBLIC_KEY_SIZE: usize = 2592;
    const PRIVATE_KEY_SIZE: usize = 4896;
    const SIGNATURE_SIZE: usize = 4627;
    let [keygen_vector] = ml_dsa_87_key_gen::get_cavs_vectors();
    let [signature_vector] = ml_dsa_87_sig_gen_ver::get_cavs_vectors();

    let mut public_key = [0u8; PUBLIC_KEY_SIZE];
    let mut private_key = [0u8; PRIVATE_KEY_SIZE];
    let keygen_result = unsafe {
        ml_dsa_87_keypair_internal(
            public_key.as_mut_ptr(),
            private_key.as_mut_ptr(),
            keygen_vector.seed.as_ptr(),
        )
    };
    if keygen_result != 1
        || !sha384_matches(&public_key, keygen_vector.public_key_sha384)
        || !sha384_matches(&private_key, keygen_vector.private_key_sha384)
    {
        return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
    }

    let mut signature_public_key = [0u8; PUBLIC_KEY_SIZE];
    let mut signature = [0u8; SIGNATURE_SIZE];
    let mut signature_len = signature.len();
    let mut prefix = [0u8; 257];
    prefix[1] = signature_vector.context.len() as u8;
    prefix[2..2 + signature_vector.context.len()].copy_from_slice(signature_vector.context);
    let deterministic_randomizer = [0u8; 32];

    let pack_result = unsafe {
        ml_dsa_87_pack_pk_from_sk(
            signature_public_key.as_mut_ptr(),
            signature_vector.private_key.as_ptr(),
        )
    };
    let sign_result = unsafe {
        ml_dsa_87_sign_internal(
            signature_vector.private_key.as_ptr(),
            signature.as_mut_ptr(),
            &mut signature_len,
            signature_vector.message.as_ptr(),
            signature_vector.message.len(),
            prefix.as_ptr(),
            2 + signature_vector.context.len(),
            deterministic_randomizer.as_ptr(),
        )
    };
    let verify_result = unsafe {
        ml_dsa_87_verify(
            signature_public_key.as_ptr(),
            signature.as_ptr(),
            signature_len,
            signature_vector.message.as_ptr(),
            signature_vector.message.len(),
            signature_vector.context.as_ptr(),
            signature_vector.context.len(),
        )
    };
    let signature_matches = sha384_matches(&signature, signature_vector.signature_sha384);
    let invalid_verify_result = unsafe {
        ml_dsa_87_verify(
            signature_vector.invalid_public_key.as_ptr(),
            signature_vector.invalid_signature.as_ptr(),
            signature_vector.invalid_signature.len(),
            signature_vector.invalid_message.as_ptr(),
            signature_vector.invalid_message.len(),
            signature_vector.invalid_context.as_ptr(),
            signature_vector.invalid_context.len(),
        )
    };

    #[cfg(test)]
    {
        assert_eq!(pack_result, 1);
        assert_eq!(sign_result, 1);
        assert_eq!(verify_result, 1);
        assert_eq!(invalid_verify_result, 0);
        assert_eq!(signature_len, SIGNATURE_SIZE);
        assert!(sha384_matches(
            &signature_public_key,
            signature_vector.public_key_sha384,
        ));
        assert!(signature_matches);
    }

    if pack_result != 1
        || sign_result != 1
        || verify_result != 1
        || invalid_verify_result != 0
        || signature_len != SIGNATURE_SIZE
        || !sha384_matches(&signature_public_key, signature_vector.public_key_sha384)
        || !signature_matches
    {
        return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
    }

    Ok(())
}

pub(crate) fn ml_kem_1024_cavp() -> SpdmResult {
    const PUBLIC_KEY_SIZE: usize = 1568;
    const PRIVATE_KEY_SIZE: usize = 3168;
    const CIPHER_TEXT_SIZE: usize = 1568;
    let [vector] = ml_kem_1024_encap_decap::get_cavs_vectors();

    let mut public_key = [0u8; PUBLIC_KEY_SIZE];
    let mut private_key = [0u8; PRIVATE_KEY_SIZE];
    let mut cipher_text = [0u8; CIPHER_TEXT_SIZE];
    let mut shared_secret = [0u8; 32];
    let mut decapsulated_secret = [0u8; 32];
    let mut implicit_rejection_secret = [0u8; 32];
    let mut public_key_len = public_key.len();
    let mut private_key_len = private_key.len();
    let mut cipher_text_len = cipher_text.len();
    let mut shared_secret_len = shared_secret.len();
    let mut decapsulated_secret_len = decapsulated_secret.len();
    let mut implicit_rejection_secret_len = implicit_rejection_secret.len();

    let keygen_result = unsafe {
        ml_kem_1024_keypair_deterministic(
            public_key.as_mut_ptr(),
            &mut public_key_len,
            private_key.as_mut_ptr(),
            &mut private_key_len,
            vector.keygen_seed.as_ptr(),
        )
    };
    let encap_result = unsafe {
        ml_kem_1024_encapsulate_deterministic(
            cipher_text.as_mut_ptr(),
            &mut cipher_text_len,
            shared_secret.as_mut_ptr(),
            &mut shared_secret_len,
            vector.encap_public_key.as_ptr(),
            vector.encap_seed.as_ptr(),
        )
    };
    let decap_result = unsafe {
        ml_kem_1024_decapsulate(
            decapsulated_secret.as_mut_ptr(),
            &mut decapsulated_secret_len,
            cipher_text.as_ptr(),
            vector.decap_private_key.as_ptr(),
        )
    };
    let implicit_rejection_result = unsafe {
        ml_kem_1024_decapsulate(
            implicit_rejection_secret.as_mut_ptr(),
            &mut implicit_rejection_secret_len,
            vector.modified_cipher_text.as_ptr(),
            vector.implicit_rejection_private_key.as_ptr(),
        )
    };
    let invalid_private_key_result = unsafe {
        ml_kem_1024_check_sk(
            vector.invalid_private_key.as_ptr(),
            vector.invalid_private_key.len(),
        )
    };
    let invalid_public_key_result = unsafe {
        ml_kem_1024_check_pk(
            vector.invalid_public_key.as_ptr(),
            vector.invalid_public_key.len(),
        )
    };

    #[cfg(test)]
    {
        assert_eq!(keygen_result, 0);
        assert_eq!(encap_result, 0);
        assert_eq!(decap_result, 0);
        assert_eq!(implicit_rejection_result, 0);
        assert_ne!(invalid_private_key_result, 0);
        assert_ne!(invalid_public_key_result, 0);
        assert_eq!(public_key_len, PUBLIC_KEY_SIZE);
        assert_eq!(private_key_len, PRIVATE_KEY_SIZE);
        assert_eq!(cipher_text_len, CIPHER_TEXT_SIZE);
        assert_eq!(shared_secret_len, vector.shared_secret.len());
        assert_eq!(decapsulated_secret_len, vector.shared_secret.len());
        assert_eq!(
            implicit_rejection_secret_len,
            vector.implicit_rejection_secret.len()
        );
        assert!(sha384_matches(&public_key, vector.public_key_sha384));
        assert!(sha384_matches(&private_key, vector.private_key_sha384));
        assert!(sha384_matches(&cipher_text, vector.cipher_text_sha384));
        assert_eq!(&shared_secret, vector.shared_secret);
        assert_eq!(&decapsulated_secret, vector.shared_secret);
        assert_eq!(&implicit_rejection_secret, vector.implicit_rejection_secret);
    }

    if keygen_result != 0
        || encap_result != 0
        || decap_result != 0
        || implicit_rejection_result != 0
        || invalid_private_key_result == 0
        || invalid_public_key_result == 0
        || public_key_len != PUBLIC_KEY_SIZE
        || private_key_len != PRIVATE_KEY_SIZE
        || cipher_text_len != CIPHER_TEXT_SIZE
        || shared_secret_len != vector.shared_secret.len()
        || decapsulated_secret_len != vector.shared_secret.len()
        || implicit_rejection_secret_len != vector.implicit_rejection_secret.len()
        || !sha384_matches(&public_key, vector.public_key_sha384)
        || !sha384_matches(&private_key, vector.private_key_sha384)
        || !sha384_matches(&cipher_text, vector.cipher_text_sha384)
        || &shared_secret != vector.shared_secret
        || &decapsulated_secret != vector.shared_secret
        || &implicit_rejection_secret != vector.implicit_rejection_secret
    {
        return Err(SPDM_STATUS_FIPS_SELF_TEST_FAIL);
    }

    Ok(())
}

extern "C" {
    #[link_name = "aws_lc_0_43_0_ml_dsa_87_keypair_internal"]
    fn ml_dsa_87_keypair_internal(
        public_key: *mut u8,
        private_key: *mut u8,
        seed: *const u8,
    ) -> core::ffi::c_int;

    #[link_name = "aws_lc_0_43_0_ml_dsa_87_pack_pk_from_sk"]
    fn ml_dsa_87_pack_pk_from_sk(public_key: *mut u8, private_key: *const u8) -> core::ffi::c_int;

    #[link_name = "aws_lc_0_43_0_ml_dsa_87_sign_internal"]
    fn ml_dsa_87_sign_internal(
        private_key: *const u8,
        signature: *mut u8,
        signature_len: *mut usize,
        message: *const u8,
        message_len: usize,
        prefix: *const u8,
        prefix_len: usize,
        randomizer: *const u8,
    ) -> core::ffi::c_int;

    #[link_name = "aws_lc_0_43_0_ml_dsa_87_verify"]
    fn ml_dsa_87_verify(
        public_key: *const u8,
        signature: *const u8,
        signature_len: usize,
        message: *const u8,
        message_len: usize,
        context: *const u8,
        context_len: usize,
    ) -> core::ffi::c_int;
}

extern "C" {
    #[link_name = "aws_lc_0_43_0_ml_kem_1024_keypair_deterministic"]
    fn ml_kem_1024_keypair_deterministic(
        public_key: *mut u8,
        public_key_len: *mut usize,
        private_key: *mut u8,
        private_key_len: *mut usize,
        seed: *const u8,
    ) -> core::ffi::c_int;

    #[link_name = "aws_lc_0_43_0_ml_kem_1024_encapsulate_deterministic"]
    fn ml_kem_1024_encapsulate_deterministic(
        cipher_text: *mut u8,
        cipher_text_len: *mut usize,
        shared_secret: *mut u8,
        shared_secret_len: *mut usize,
        public_key: *const u8,
        seed: *const u8,
    ) -> core::ffi::c_int;

    #[link_name = "aws_lc_0_43_0_ml_kem_1024_decapsulate"]
    fn ml_kem_1024_decapsulate(
        shared_secret: *mut u8,
        shared_secret_len: *mut usize,
        cipher_text: *const u8,
        private_key: *const u8,
    ) -> core::ffi::c_int;

    #[link_name = "aws_lc_0_43_0_ml_kem_1024_check_pk"]
    fn ml_kem_1024_check_pk(public_key: *const u8, public_key_len: usize) -> core::ffi::c_int;

    #[link_name = "aws_lc_0_43_0_ml_kem_1024_check_sk"]
    fn ml_kem_1024_check_sk(private_key: *const u8, private_key_len: usize) -> core::ffi::c_int;
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ml_dsa_87_cavp() {
        assert!(super::ml_dsa_87_cavp().is_ok());
    }

    #[test]
    fn test_ml_kem_1024_cavp() {
        assert!(super::ml_kem_1024_cavp().is_ok());
    }
}

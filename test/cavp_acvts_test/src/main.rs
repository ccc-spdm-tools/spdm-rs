// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use serde_json::Value;
use spdmlib::protocol::SpdmDer;
use std::collections::BTreeMap;
use std::io::{self, Read};

fn init_handlers() {
    register_handlers(
        ("SHA2-256".to_string(), "1.0".to_string()),
        handle_algorithm_sha2_256,
    );
    register_handlers(
        ("SHA2-384".to_string(), "1.0".to_string()),
        handle_algorithm_sha2_384,
    );
    register_handlers(
        ("HMAC-SHA2-256".to_string(), "1.0".to_string()),
        handle_algorithm_hmac_sha2_256,
    );
    register_handlers(
        ("HMAC-SHA2-384".to_string(), "1.0".to_string()),
        handle_algorithm_hmac_sha2_384,
    );
    register_handlers(
        ("ECDSA".to_string(), "FIPS186-5".to_string()),
        handle_algorithm_ecdsa,
    );
    register_handlers(
        ("ACVP-AES-GCM".to_string(), "1.0".to_string()),
        handle_algorithm_aead,
    );
    register_handlers(
        ("KAS-ECC-SSC".to_string(), "Sp800-56Ar3".to_string()),
        handle_algorithm_ecdhe,
    );
    register_handlers(
        ("RSA".to_string(), "FIPS186-4".to_string()),
        handle_algorithm_rsa,
    );
}

fn main() -> io::Result<()> {
    // Init algorithms handlers
    init_handlers();

    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    buffer = buffer.trim().to_string();

    let output = handle_input_json(buffer)?;
    println!("{}", output);
    Ok(())
}

fn handle_input_json(input_json: String) -> io::Result<String> {
    // Parse the input JSON
    let input: Value = serde_json::from_str(&input_json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut output: Vec<Value> = Vec::new();
    // Process the parsed JSON
    let input = input.as_array().unwrap();
    for value in input {
        if !value.is_object() {
            continue;
        }
        let acv_version = value["acvVersion"].as_str();
        if acv_version.is_some() {
            output.push(serde_json::json!({
                "acvVersion": acv_version.unwrap()
            }));
            continue;
        }
        let vs_id = value["vsId"].as_u64().unwrap();
        let algorithm = value["algorithm"].as_str().unwrap();
        let revision = value["revision"].as_str().unwrap();
        let is_sample = value["isSample"].as_bool().unwrap();
        let test_groups = value["testGroups"].as_array().unwrap();

        let mut output_ret = serde_json::json!({
            "vsId": vs_id,
            "algorithm": algorithm,
            "revision": revision,
            "isSample": is_sample,
            "testGroups": []
        });
        let output_ret_test_groups = output_ret["testGroups"].as_array_mut().unwrap();
        let handler = get_handler(algorithm, revision);
        let mut results = handler(test_groups);
        output_ret_test_groups.append(&mut results);
        output.push(output_ret);
    }

    let formatted_json = serde_json::to_string_pretty(&output).unwrap();
    Ok(formatted_json)
}

type AlgorithmHandler = fn(&Vec<Value>) -> Vec<Value>;

use lazy_static::lazy_static;
use std::sync::Mutex;
lazy_static! {
    static ref ALGORITHM_HANDLERS: Mutex<BTreeMap<(String, String), AlgorithmHandler>> =
        Mutex::new(BTreeMap::new());
}

fn register_handlers(key: (String, String), handler: AlgorithmHandler) {
    let mut handlers = ALGORITHM_HANDLERS.lock().unwrap();
    handlers.insert(key, handler);
}

fn get_handler(algorithm: &str, revision: &str) -> AlgorithmHandler {
    let handlers = ALGORITHM_HANDLERS.lock().unwrap();
    handlers
        .get(&(algorithm.to_string(), revision.to_string()))
        .cloned()
        .unwrap()
}

fn handle_algorithm_sha2_256(test_groups: &Vec<Value>) -> Vec<Value> {
    algorithm_sha2(test_groups, "SHA2-256")
}

fn handle_algorithm_sha2_384(test_groups: &Vec<Value>) -> Vec<Value> {
    algorithm_sha2(test_groups, "SHA2-384")
}

fn algorithm_sha2(test_groups: &Vec<Value>, algo_str: &str) -> Vec<Value> {
    use spdmlib::crypto::hash;
    use spdmlib::protocol::SpdmBaseHashAlgo;

    let algo = match algo_str {
        "SHA2-384" => SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        "SHA2-256" => SpdmBaseHashAlgo::TPM_ALG_SHA_256,
        _ => panic!("not support algo"),
    };

    let mut results = Vec::new();
    for test_group in test_groups {
        if !test_group.is_object() {
            continue;
        }
        let tg_id = test_group["tgId"].as_u64().unwrap();
        let test_type = test_group["testType"].as_str().unwrap();

        let tests = test_group["tests"].as_array().unwrap();
        let mut results_test = Vec::new();

        match test_type {
            "AFT" => {
                for tc in tests {
                    if !tc.is_object() {
                        continue;
                    }
                    let tc_id = tc["tcId"].as_u64().unwrap();
                    let msg = tc["msg"].as_str().unwrap();
                    let msg = from_hex(msg).unwrap();
                    let len: u64 = tc["len"].as_u64().unwrap() / 8;
                    assert_eq!(msg.as_slice().len(), len as usize, "{}", tc_id);
                    let md = hash::hash_all(algo, msg.as_slice()).unwrap();

                    results_test.push(serde_json::json!({
                        "tcId": tc_id,
                        "md": to_hex(md.as_ref())
                    }));
                }
            }
            "MCT" => {
                for tc in tests {
                    let tc_id = tc["tcId"].as_u64().unwrap();
                    let msg = tc["msg"].as_str().unwrap();
                    let msg = from_hex(msg).unwrap();
                    let len = tc["len"].as_u64().unwrap() / 8;
                    assert_eq!(msg.as_slice().len(), len as usize);

                    let mut value = serde_json::json!({
                        "tcId": tc_id,
                        "resultsArray": [],
                    });

                    let mut seed = msg.clone();

                    let result_array = value["resultsArray"].as_array_mut().unwrap();
                    // https://pages.nist.gov/ACVP/draft-celi-acvp-sha.txt MCT
                    for _ in 0..100usize {
                        let mut md = vec![Vec::new(); 1003];
                        md[0] = seed.clone();
                        md[1] = seed.clone();
                        md[2] = seed.clone();
                        for i in 3..1003usize {
                            let mut m = Vec::new();
                            m.extend(md[i - 3].clone());
                            m.extend(md[i - 2].clone());
                            m.extend(md[i - 1].clone());

                            let ret = hash::hash_all(algo, m.as_slice()).unwrap();
                            md[i] = ret.as_ref().to_vec();
                        }
                        seed = md[1002].clone();
                        result_array.push(serde_json::json!({
                            "md": to_hex(seed.as_slice())
                        }));
                    }
                    results_test.push(value);
                }
            }
            "LDT" => {
                for tc in tests {
                    let tc_id = tc["tcId"].as_u64().unwrap();

                    let content_length = tc["largeMsg"]["contentLength"].as_u64().unwrap();
                    let full_length = tc["largeMsg"]["fullLength"].as_u64().unwrap();
                    let content = tc["largeMsg"]["content"].as_str().unwrap();
                    let expansion_technique =
                        tc["largeMsg"]["expansionTechnique"].as_str().unwrap();
                    assert_eq!(expansion_technique, "repeating");
                    let repeat = {
                        let repeat = full_length / content_length;
                        repeat as usize
                    };
                    let msg = from_hex(content).unwrap();
                    let len = content_length / 8;
                    assert_eq!(msg.as_slice().len(), len as usize);

                    let mut ctx = hash::hash_ctx_init(algo).unwrap();
                    for _ in 0..repeat {
                        hash::hash_ctx_update(&mut ctx, msg.as_slice()).unwrap();
                    }
                    let md = hash::hash_ctx_finalize(ctx).unwrap();

                    results_test.push(serde_json::json!({
                        "tcId": tc_id,
                        "md": to_hex(md.as_ref())
                    }));
                }
            }
            _ => {
                panic!("not support test type {}", test_type);
            }
        }

        results.push(serde_json::json!({
            "tgId": tg_id,
            "tests": results_test
        }));
    }
    results
}

fn handle_algorithm_hmac_sha2_256(test_groups: &Vec<Value>) -> Vec<Value> {
    algorithm_hmac_sha2(test_groups, "HMAC-SHA2-256")
}

fn handle_algorithm_hmac_sha2_384(test_groups: &Vec<Value>) -> Vec<Value> {
    algorithm_hmac_sha2(test_groups, "HMAC-SHA2-384")
}

fn algorithm_hmac_sha2(test_groups: &Vec<Value>, algo_str: &str) -> Vec<Value> {
    use spdmlib::crypto::hmac;
    use spdmlib::protocol::SpdmBaseHashAlgo;

    let algo = match algo_str {
        "HMAC-SHA2-384" => SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        "HMAC-SHA2-256" => SpdmBaseHashAlgo::TPM_ALG_SHA_256,
        _ => panic!("not support algo"),
    };

    let mut results = Vec::new();
    for group in test_groups {
        if !group.is_object() {
            continue;
        }
        let tg_id = group["tgId"].as_u64().unwrap();
        let test_type = group["testType"].as_str().unwrap();
        assert_eq!(test_type, "AFT");
        let _key_len = group["keyLen"].as_u64().unwrap();
        let _msg_len = group["msgLen"].as_u64().unwrap();
        let mac_len = group["macLen"].as_u64().unwrap();
        let tests = group["tests"].as_array().unwrap();
        let mut results_test = Vec::new();
        for tc in tests {
            if !tc.is_object() {
                continue;
            }
            let tc_id = tc["tcId"].as_u64().unwrap();
            let key = tc["key"].as_str().unwrap();
            let msg = tc["msg"].as_str().unwrap();
            let key = from_hex(key).unwrap();
            let data = from_hex(msg).unwrap();
            let res = hmac::hmac(algo, key.as_slice(), data.as_slice()).unwrap();
            let mac = &res.as_ref()[0..((mac_len / 8) as usize)];

            results_test.push(serde_json::json!({
                "tcId": tc_id,
                "mac": to_hex(mac),
            }));
        }
        results.push(serde_json::json!({
            "tgId": tg_id,
            "tests": results_test
        }));
    }
    results
}

fn ecdsa_verify(
    tc_id: u64,
    curve: &str,
    hash_alg: &str,
    message: &str,
    qx: &str,
    qy: &str,
    r: &str,
    s: &str,
) -> Value {
    use spdmlib::crypto::asym_verify;
    use spdmlib::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmSignatureStruct};

    let hash_algo = match hash_alg {
        "SHA2-256" => SpdmBaseHashAlgo::TPM_ALG_SHA_256,
        "SHA2-384" => SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        _ => panic!("not support algo"),
    };

    let asym_algo = match curve {
        "P-256" => SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
        "P-384" => SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        _ => panic!("not support algo"),
    };

    let mut ecp256_template = include_bytes!("./ecdsa_256.cert.der").to_vec();
    let mut ecp384_template = include_bytes!("./ecdsa_384.cert.der").to_vec();
    let qx = from_hex(qx).unwrap();
    let qy = from_hex(qy).unwrap();
    let certificate = match curve {
        "P-256" => {
            let length = 32;
            let offset: usize = 180 + 4;
            ecp256_template[offset..offset + length].copy_from_slice(qx.as_slice());
            ecp256_template[offset + length..offset + 2 * length].copy_from_slice(qy.as_slice());
            ecp256_template.clone()
        }
        "P-384" => {
            let length = 48;
            let offset: usize = 177 + 4;
            ecp384_template[offset..offset + length].copy_from_slice(qx.as_slice());
            ecp384_template[offset + length..offset + 2 * length].copy_from_slice(qy.as_slice());
            ecp384_template.clone()
        }
        _ => panic!("not support algo"),
    };

    let data = from_hex(message).unwrap();
    let mut signature = SpdmSignatureStruct::default();
    let r = from_hex(r).unwrap().to_vec();
    let s = from_hex(s).unwrap().to_vec();
    signature.data_size = (r.len() + s.len()) as u16;
    signature.data[0..r.len()].copy_from_slice(r.as_slice());
    signature.data[r.len()..r.len() + s.len()].copy_from_slice(s.as_slice());

    let ret = asym_verify::verify(
        hash_algo,
        asym_algo,
        SpdmDer::SpdmDerCertChain(certificate.as_slice()),
        data.as_slice(),
        &signature,
    );

    serde_json::json!({
        "tcId": tc_id,
        "testPassed": ret.is_ok(),
    })
}

fn handle_algorithm_ecdsa(test_groups: &Vec<Value>) -> Vec<Value> {
    let mut results = Vec::new();
    for group in test_groups {
        if !group.is_object() {
            continue;
        }
        let tg_id = group["tgId"].as_u64().unwrap();
        let test_type = group["testType"].as_str().unwrap();
        assert_eq!(test_type, "AFT");
        let curve = group["curve"].as_str().unwrap();
        let hash_alg = group["hashAlg"].as_str().unwrap();
        let tests = group["tests"].as_array().unwrap();
        let mut test_results = Vec::new();
        for tc in tests {
            if !tc.is_object() {
                continue;
            }
            let tc_id = tc["tcId"].as_u64().unwrap();
            let message = tc["message"].as_str().unwrap();
            let qx = tc["qx"].as_str().unwrap();
            let qy = tc["qy"].as_str().unwrap();
            let r = tc["r"].as_str().unwrap();
            let s = tc["s"].as_str().unwrap();

            let result = ecdsa_verify(tc_id, curve, hash_alg, message, qx, qy, r, s);

            test_results.push(result);
        }
        results.push(serde_json::json!({
            "tgId": tg_id,
            "tests": test_results
        }));
    }
    results
}

fn handle_algorithm_aead(test_groups: &Vec<Value>) -> Vec<Value> {
    use spdmlib::crypto::aead;
    use spdmlib::crypto::rand;
    use spdmlib::protocol::{SpdmAeadAlgo, SpdmAeadIvStruct, SpdmAeadKeyStruct};

    let mut results = Vec::new();
    for group in test_groups {
        if !group.is_object() {
            continue;
        }
        let tg_id = group["tgId"].as_u64().unwrap();
        let test_type = group["testType"].as_str().unwrap();
        let direction = group["direction"].as_str().unwrap();
        let key_len = group["keyLen"].as_u64().unwrap();
        let iv_len = group["ivLen"].as_u64().unwrap();
        let _iv_gen_mode = group["ivGenMode"].as_str().unwrap();
        let _payload_len = group["payloadLen"].as_u64().unwrap();
        let _aad_len = group["aadLen"].as_u64().unwrap();
        let tag_len = group["tagLen"].as_u64().unwrap();

        assert_eq!(test_type, "AFT");
        assert_eq!(key_len, 256);
        assert_eq!(iv_len, 12 * 8);
        assert_eq!(tag_len, 16 * 8);

        let tests = group["tests"].as_array().unwrap();
        let mut test_results = Value::Array(Vec::new());
        for test in tests {
            let tc_id = test["tcId"].as_u64().unwrap();
            match direction {
                "encrypt" => {
                    let pt = from_hex(test["pt"].as_str().unwrap()).unwrap();
                    let key = from_hex(test["key"].as_str().unwrap()).unwrap();
                    let aad = from_hex(test["aad"].as_str().unwrap()).unwrap();

                    let mut iv = vec![0u8; (iv_len / 8) as usize];
                    let mut tag = vec![0u8; (tag_len / 8) as usize];
                    let mut ct = vec![0u8; pt.len()];
                    rand::get_random(iv.as_mut_slice()).unwrap();

                    let key = SpdmAeadKeyStruct::from(key.as_slice());
                    let iv = SpdmAeadIvStruct::from(iv.as_slice());
                    let ret = aead::encrypt(
                        SpdmAeadAlgo::AES_256_GCM,
                        &key,
                        &iv,
                        aad.as_slice(),
                        pt.as_slice(),
                        tag.as_mut_slice(),
                        ct.as_mut_slice(),
                    );
                    assert!(ret.is_ok());

                    test_results
                        .as_array_mut()
                        .unwrap()
                        .push(serde_json::json!({
                            "tcId": tc_id,
                            "iv": to_hex(iv.as_ref()),
                            "ct": to_hex(ct.as_slice()),
                            "tag": to_hex(tag.as_slice()),
                        }));
                }
                "decrypt" => {
                    let key = from_hex(test["key"].as_str().unwrap()).unwrap();
                    let aad = from_hex(test["aad"].as_str().unwrap()).unwrap();
                    let iv = from_hex(test["iv"].as_str().unwrap()).unwrap();
                    let ct = from_hex(test["ct"].as_str().unwrap()).unwrap();
                    let tag = from_hex(test["tag"].as_str().unwrap()).unwrap();

                    let key = SpdmAeadKeyStruct::from(key.as_slice());
                    let iv = SpdmAeadIvStruct::from(iv.as_slice());

                    let mut pt = vec![0u8; ct.len()];

                    let ret = aead::decrypt(
                        SpdmAeadAlgo::AES_256_GCM,
                        &key,
                        &iv,
                        aad.as_slice(),
                        ct.as_slice(),
                        tag.as_slice(),
                        pt.as_mut_slice(),
                    );

                    let test_passed = ret.is_ok();

                    if test_passed {
                        test_results
                            .as_array_mut()
                            .unwrap()
                            .push(serde_json::json!({
                                "tcId": tc_id,
                                "pt": to_hex(pt.as_slice()),
                                "iv": to_hex(iv.as_ref()),
                            }));
                    } else {
                        test_results
                            .as_array_mut()
                            .unwrap()
                            .push(serde_json::json!({
                                "tcId": tc_id,
                                "testPassed": false,
                            }));
                    }
                }
                _ => panic!("not supported direction {}", direction),
            }
        }
        results.push(serde_json::json!({
            "tgId": tg_id,
            "tests": test_results
        }));
    }
    results
}

fn handle_algorithm_ecdhe(test_groups: &Vec<Value>) -> Vec<Value> {
    use ring::agreement::{EphemeralPrivateKey, ECDH_P256, ECDH_P384};
    use spdmlib::crypto::dhe;
    use spdmlib::crypto::hash;
    use spdmlib::protocol::SpdmBaseHashAlgo;
    use spdmlib::protocol::{SpdmDheAlgo, SpdmDheExchangeStruct};

    let mut group_results = Vec::new();
    for group in test_groups {
        let tg_id = group["tgId"].as_u64().unwrap();
        let test_type = group["testType"].as_str().unwrap();
        let domain_parameter_generation_mode =
            group["domainParameterGenerationMode"].as_str().unwrap();
        let hash_function_z = group["hashFunctionZ"].as_str().unwrap();

        let hash_algo = match hash_function_z {
            "SHA2-384" => SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            "SHA2-256" => SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            _ => panic!("not support algo"),
        };

        let dhe_algo = match domain_parameter_generation_mode {
            "P-256" => SpdmDheAlgo::SECP_256_R1,
            "P-384" => SpdmDheAlgo::SECP_384_R1,
            _ => panic!(
                "dhe_algo not supported, {}",
                domain_parameter_generation_mode
            ),
        };
        let tg_result: Value = match test_type {
            "VAL" => {
                let mut results = Value::Array(Vec::new());
                let tests = group["tests"].as_array().unwrap();

                let curve = match domain_parameter_generation_mode {
                    "P-256" => &ECDH_P256,
                    "P-384" => &ECDH_P384,
                    _ => panic!(
                        "dhe_algo not supported, {}",
                        domain_parameter_generation_mode
                    ),
                };

                for test in tests {
                    let ephemeral_private_iut =
                        from_hex(test["ephemeralPrivateIut"].as_str().unwrap()).unwrap();
                    let ephemeral_public_iut_x_expected =
                        from_hex(test["ephemeralPublicIutX"].as_str().unwrap()).unwrap();
                    let ephemeral_public_iut_y_expected =
                        from_hex(test["ephemeralPublicIutY"].as_str().unwrap()).unwrap();
                    let ephemeral_public_server_x =
                        from_hex(test["ephemeralPublicServerX"].as_str().unwrap()).unwrap();
                    let ephemeral_public_server_y =
                        from_hex(test["ephemeralPublicServerY"].as_str().unwrap()).unwrap();

                    let private = EphemeralPrivateKey::from_bytes_for_test(
                        curve,
                        ephemeral_private_iut.as_slice(),
                    )
                    .unwrap();

                    let ephemeral_public_iut_actual =
                        private.compute_public_key().unwrap().as_ref()[1..].to_vec();
                    let len = ephemeral_public_iut_actual.len() / 2;
                    let mut passed = true;
                    if ephemeral_public_iut_x_expected.as_slice()
                        != &ephemeral_public_iut_actual.as_slice()[0..len]
                    {
                        passed = false;
                    }
                    if ephemeral_public_iut_y_expected.as_slice()
                        != &ephemeral_public_iut_actual.as_slice()[len..len * 2]
                    {
                        passed = false;
                    }

                    let algo = match domain_parameter_generation_mode {
                        "P-256" => &ring::agreement::ECDH_P256,
                        "P-384" => &ring::agreement::ECDH_P384,
                        _ => panic!(
                            "dhe_algo not supported, {}",
                            domain_parameter_generation_mode
                        ),
                    };

                    let mut unparsed_public_key = Vec::new();
                    unparsed_public_key.push(0x4u8);
                    unparsed_public_key.extend_from_slice(&ephemeral_public_server_x);
                    unparsed_public_key.extend_from_slice(&ephemeral_public_server_y);
                    let unparsed_pub_key =
                        ring::agreement::UnparsedPublicKey::new(algo, unparsed_public_key);

                    let ret =
                        ring::agreement::agree_ephemeral(private, &unparsed_pub_key, |peer_key| {
                            let hash_z = hash::hash_all(hash_algo, peer_key).unwrap();
                            let hash_z_actual = to_hex(hash_z.as_ref());
                            let hash_z_expected = test["hashZ"].as_str().unwrap();
                            if hash_z_expected != hash_z_actual.as_str() {
                                passed = false;
                            }
                        })
                        .is_ok();
                    if ret == false {
                        passed = false;
                    }

                    results.as_array_mut().unwrap().push(serde_json::json!({
                        "tcId": test["tcId"].as_u64().unwrap(),
                        "testPassed": passed,
                    }));
                }
                results
            }
            "AFT" => {
                let mut results = Value::Array(Vec::new());
                let tests = group["tests"].as_array().unwrap();
                for test in tests {
                    let ephemeral_public_server_x =
                        test["ephemeralPublicServerX"].as_str().unwrap();
                    let ephemeral_public_server_y =
                        test["ephemeralPublicServerY"].as_str().unwrap();

                    let pub_x = from_hex(ephemeral_public_server_x).unwrap();
                    let pub_y = from_hex(ephemeral_public_server_y).unwrap();

                    let mut public_key = SpdmDheExchangeStruct::default();
                    public_key.data_size = (pub_x.len() + pub_y.len()) as u16;
                    public_key.data[0..pub_x.len()].copy_from_slice(pub_x.as_slice());
                    public_key.data[pub_x.len()..pub_x.len() + pub_y.len()]
                        .copy_from_slice(pub_y.as_slice());
                    let (ephemeral_public_iut, private) = dhe::generate_key_pair(dhe_algo).unwrap();
                    let peer_key = private.compute_final_key(&public_key).unwrap();
                    let len = ephemeral_public_iut.as_ref().len();
                    let ephemeral_public_iut_x = &ephemeral_public_iut.as_ref()[0..len / 2];
                    let ephemeral_public_iut_y = &ephemeral_public_iut.as_ref()[len / 2..len];

                    let hash_z = hash::hash_all(hash_algo, peer_key.as_ref()).unwrap();
                    results.as_array_mut().unwrap().push(serde_json::json!({
                        "tcId": test["tcId"].as_u64().unwrap(),
                        "hashZ": to_hex(hash_z.as_ref()),
                        "ephemeralPublicIutX": to_hex(ephemeral_public_iut_x),
                        "ephemeralPublicIutY": to_hex(ephemeral_public_iut_y),
                    }));
                }
                results
            }
            _ => {
                panic!("not supported test_type {}", test_type);
            }
        };
        group_results.push(serde_json::json!({
            "tgId": tg_id,
            "tests": tg_result,
        }));
    }
    group_results
}

fn handle_algorithm_rsa(test_groups: &Vec<Value>) -> Vec<Value> {
    use ring::signature::RsaPublicKeyComponents;

    let mut group_results = Vec::new();
    for group in test_groups {
        let tg_id = group["tgId"].as_u64().unwrap();
        let sig_type = group["sigType"].as_str().unwrap();
        let hash_algo = group["hashAlg"].as_str().unwrap();
        let _salt_len = group["saltLen"].as_u64().unwrap();
        let n = group["n"].as_str().unwrap();
        let e = group["e"].as_str().unwrap();
        let test_type = group["testType"].as_str().unwrap();

        assert_eq!(test_type, "GDT");

        let public_key = RsaPublicKeyComponents {
            n: from_hex(n).unwrap(),
            e: from_hex(e).unwrap(),
        };

        let params = match (sig_type, hash_algo) {
            ("pkcs1v1.5", "SHA2-384") => &ring::signature::RSA_PKCS1_3072_8192_SHA384,
            ("pkcs1v1.5", "SHA2-256") => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            _ => panic!("not supported"),
        };

        let tests = group["tests"].as_array().unwrap();
        let mut results = Value::Array(Vec::new());
        for test in tests {
            let tc_id = test["tcId"].as_u64().unwrap();
            let message = from_hex(test["message"].as_str().unwrap()).unwrap();
            let signature = from_hex(test["signature"].as_str().unwrap()).unwrap();

            let ret = public_key.verify(params, message.as_slice(), signature.as_slice());

            results.as_array_mut().unwrap().push(serde_json::json!({
                "tcId": tc_id,
                "testPassed": ret.is_ok()
            }));
        }

        group_results.push(serde_json::json!({
            "tgId": tg_id,
            "tests": results,
        }));
    }
    group_results
}

fn from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 != 0 {
        return Err(String::from(
            "Hex string does not have an even number of digits",
        ));
    }

    let mut result = Vec::with_capacity(hex_str.len() / 2);
    for digits in hex_str.as_bytes().chunks(2) {
        let hi = from_hex_digit(digits[0])?;
        let lo = from_hex_digit(digits[1])?;
        result.push((hi * 0x10) | lo);
    }
    Ok(result)
}

fn from_hex_digit(d: u8) -> Result<u8, String> {
    use core::ops::RangeInclusive;
    const DECIMAL: (u8, RangeInclusive<u8>) = (0, b'0'..=b'9');
    const HEX_LOWER: (u8, RangeInclusive<u8>) = (10, b'a'..=b'f');
    const HEX_UPPER: (u8, RangeInclusive<u8>) = (10, b'A'..=b'F');
    for (offset, range) in &[DECIMAL, HEX_LOWER, HEX_UPPER] {
        if range.contains(&d) {
            return Ok(d - range.start() + offset);
        }
    }
    Err(std::format!("Invalid hex digit '{}'", d as char))
}

fn to_hex(data: &[u8]) -> String {
    let mut hex_str = String::with_capacity(data.len() * 2);
    for byte in data {
        hex_str.push_str(&format!("{:02X}", byte));
    }
    hex_str
}

## CAVP ACVTS Test

### Overview

The Cryptographic Algorithm Validation Program [CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/) Automated Cryptographic Validation Testing System (ACVTS) test is a framework for validating the correct implementation of cryptographic algorithms according to NIST standards. 

This test suite allows the spdm-rs project to verify that its cryptographic implementations meet the requirements specified by NIST's validation programs.

### Features

Process test JSON inputs from ACVTS and return JSON result.

### How to use

```
pushd test/cavp_acvts_test
bash pre-build.sh
cat vectors/vector-set_SHA2-256.json | cargo run -p cavp_acvts_test
popd
```

### How to add new

```
# implement a new algorithms
fn handle_algorithm_new_algorithms(test_groups: &Vec<Value>, algo_str: &str) -> Vec<Value> {
    todo!("new");
}
# register the new algorithms
register_handlers(
    ("NEW_ALGO".to_string(), "VERSION".to_string()),
    handle_algorithm_new_algorithms,
);
```

### Reference

[Cryptographic Algorithm Validation Program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/)

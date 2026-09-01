// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;
use serde::Deserialize;

use crate::chain::CertificateChain;
use crate::{Certificate, Result};

#[derive(Debug, Deserialize)]
pub(super) struct LimboFixture {
    pub source: LimboSource,
    testcases: Vec<LimboTestcase>,
}

#[derive(Debug, Deserialize)]
pub(super) struct LimboSource {
    pub repository: String,
    pub revision: String,
    pub license: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct LimboTestcase {
    pub id: String,
    trusted_certs: Vec<String>,
    untrusted_intermediates: Vec<String>,
    peer_certificate: String,
    expected_result: LimboExpectedResult,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum LimboExpectedResult {
    Success,
    Failure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LimboRunSummary {
    pub total: usize,
    pub expected_successes: usize,
    pub expected_failures: usize,
}

pub(super) struct LimboRunner {
    fixture: LimboFixture,
}

impl LimboRunner {
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json).map(|fixture| Self { fixture })
    }

    pub fn source(&self) -> &LimboSource {
        &self.fixture.source
    }

    pub fn assert_conformance<E, F>(&self, mut validate: F) -> LimboRunSummary
    where
        E: Debug,
        F: FnMut(&LimboTestcase) -> core::result::Result<(), E>,
    {
        let mut summary = LimboRunSummary {
            total: 0,
            expected_successes: 0,
            expected_failures: 0,
        };

        for testcase in &self.fixture.testcases {
            let result = validate(testcase);
            let expected_success = testcase.expected_result == LimboExpectedResult::Success;

            summary.total += 1;
            if expected_success {
                summary.expected_successes += 1;
            } else {
                summary.expected_failures += 1;
            }

            assert_eq!(
                result.is_ok(),
                expected_success,
                "x509-limbo mismatch for {}: {result:?}",
                testcase.id
            );
        }

        summary
    }
}

impl LimboTestcase {
    pub fn leaf_first_chain(&self) -> Result<CertificateChain> {
        let mut certificates =
            Vec::with_capacity(1 + self.untrusted_intermediates.len() + self.trusted_certs.len());
        certificates.push(Certificate::from_pem(&self.peer_certificate)?);
        for pem in self.untrusted_intermediates.iter().rev() {
            certificates.push(Certificate::from_pem(pem)?);
        }
        for pem in &self.trusted_certs {
            certificates.push(Certificate::from_pem(pem)?);
        }

        Ok(CertificateChain::new(certificates))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIXED_RESULTS: &str = r#"
                {
                    "source": {
                        "repository": "https://example.com/x509-limbo",
                        "revision": "test-revision",
                        "license": "Apache-2.0"
                    },
                    "testcases": [
                        {
                            "id": "success",
                            "trusted_certs": [],
                            "untrusted_intermediates": [],
                            "peer_certificate": "",
                            "expected_result": "SUCCESS"
                        },
                        {
                            "id": "failure",
                            "trusted_certs": [],
                            "untrusted_intermediates": [],
                            "peer_certificate": "",
                            "expected_result": "FAILURE"
                        }
                    ]
                }
        "#;

    #[test]
    fn reports_mixed_result_summary() {
        let runner = LimboRunner::from_json(MIXED_RESULTS).expect("valid fixture");

        let summary = runner.assert_conformance(|testcase| match testcase.id.as_str() {
            "success" => Ok(()),
            "failure" => Err("expected validation failure"),
            id => panic!("unexpected testcase: {id}"),
        });

        assert_eq!(
            summary,
            LimboRunSummary {
                total: 2,
                expected_successes: 1,
                expected_failures: 1,
            }
        );
    }

    #[test]
    fn rejects_unknown_expected_result() {
        let invalid = MIXED_RESULTS.replace("SUCCESS", "UNKNOWN");

        assert!(LimboRunner::from_json(&invalid).is_err());
    }
}

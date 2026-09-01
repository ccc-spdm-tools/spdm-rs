# Copyright (c) 2026 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0 or MIT

import json
import tempfile
import unittest
from pathlib import Path

import update_x509_limbo as importer


class UpdateX509LimboTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = {
            "version": 1,
            "source": {
                "repository": "https://example.com/x509-limbo",
                "revision": "0123456789abcdef",
                "license": "Apache-2.0",
            },
            "suites": [
                {
                    "name": "example",
                    "output": "example.json",
                    "testcases": [
                        {"id": "case::supported", "status": "supported"},
                        {
                            "id": "case::unsupported",
                            "status": "unsupported",
                            "reason": "not implemented",
                        },
                    ],
                }
            ],
        }
        self.upstream = {
            "version": 1,
            "testcases": [
                {
                    "id": "case::supported",
                    "description": "preserved verbatim",
                    "expected_result": "SUCCESS",
                },
                {"id": "case::unsupported", "expected_result": "FAILURE"},
            ],
        }

    def test_generates_only_supported_cases_and_preserves_fields(self) -> None:
        generated = importer.generate_suites(self.manifest, self.upstream, set())
        fixture = json.loads(generated["example.json"])

        self.assertEqual(fixture["source"], self.manifest["source"])
        self.assertEqual(fixture["testcases"], [self.upstream["testcases"][0]])

    def test_rejects_missing_upstream_case(self) -> None:
        self.upstream["testcases"].pop()

        with self.assertRaisesRegex(
            importer.ImporterError, "upstream testcase is missing"
        ):
            importer.generate_suites(self.manifest, self.upstream, set())

    def test_requires_reason_for_unsupported_case(self) -> None:
        del self.manifest["suites"][0]["testcases"][1]["reason"]

        with self.assertRaisesRegex(importer.ImporterError, "requires a reason"):
            importer.validate_manifest(self.manifest)

    def test_rejects_mismatched_supplied_revision(self) -> None:
        with self.assertRaisesRegex(importer.ImporterError, "revision mismatch"):
            importer.verify_revision(
                Path("limbo.json"), "0123456789abcdef", "different-revision"
            )

    def test_check_mode_reports_fixture_drift_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "capabilities.json"
            output = Path(directory) / "example.json"
            output.write_text("old fixture\n", encoding="utf-8")

            changed = importer.update_outputs(
                manifest_path, {"example.json": "new fixture\n"}, check=True
            )

            self.assertEqual(changed, [output])
            self.assertEqual(output.read_text(encoding="utf-8"), "old fixture\n")


if __name__ == "__main__":
    unittest.main()

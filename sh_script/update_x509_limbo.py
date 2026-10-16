#!/usr/bin/env python3
# Copyright (c) 2026 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0 or MIT

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

VALID_STATUSES = {"supported", "unsupported", "not-applicable"}
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = (
    REPO_ROOT
    / "spdmlib"
    / "src"
    / "crypto"
    / "spdm_x509"
    / "etc"
    / "x509_limbo_capabilities.json"
)


class ImporterError(Exception):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ImporterError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise ImporterError(f"{path}: expected a JSON object")
    return value


def validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("version") != 1:
        raise ImporterError("capability manifest version must be 1")

    source = manifest.get("source")
    if not isinstance(source, dict):
        raise ImporterError("capability manifest source must be an object")
    for field in ("repository", "revision", "license"):
        if not isinstance(source.get(field), str) or not source[field]:
            raise ImporterError(f"capability manifest source.{field} must be set")

    suites = manifest.get("suites")
    if not isinstance(suites, list) or not suites:
        raise ImporterError("capability manifest suites must be a non-empty array")

    suite_names: set[str] = set()
    outputs: set[str] = set()
    testcase_ids: set[str] = set()
    for suite in suites:
        if not isinstance(suite, dict):
            raise ImporterError("each suite must be an object")
        name = suite.get("name")
        output = suite.get("output")
        if not isinstance(name, str) or not name:
            raise ImporterError("each suite must have a name")
        if name in suite_names:
            raise ImporterError(f"duplicate suite name: {name}")
        suite_names.add(name)
        if not isinstance(output, str) or not output:
            raise ImporterError(f"{name}: suite output must be set")
        if Path(output).is_absolute() or ".." in Path(output).parts:
            raise ImporterError(
                f"{name}: suite output must stay within the manifest directory"
            )
        if output in outputs:
            raise ImporterError(f"duplicate suite output: {output}")
        outputs.add(output)

        testcases = suite.get("testcases")
        if not isinstance(testcases, list) or not testcases:
            raise ImporterError(f"{name}: testcases must be a non-empty array")
        for capability in testcases:
            if not isinstance(capability, dict):
                raise ImporterError(
                    f"{name}: each testcase capability must be an object"
                )
            testcase_id = capability.get("id")
            status = capability.get("status")
            if not isinstance(testcase_id, str) or not testcase_id:
                raise ImporterError(f"{name}: each testcase must have an id")
            if testcase_id in testcase_ids:
                raise ImporterError(f"duplicate testcase capability: {testcase_id}")
            testcase_ids.add(testcase_id)
            if status not in VALID_STATUSES:
                raise ImporterError(f"{testcase_id}: unknown status: {status}")
            if status != "supported" and not capability.get("reason"):
                raise ImporterError(f"{testcase_id}: {status} status requires a reason")


def verify_revision(limbo_path: Path, expected: str, supplied: str | None) -> None:
    if supplied is not None:
        actual = supplied
    else:
        try:
            actual = subprocess.run(
                ["git", "-C", str(limbo_path.parent), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as error:
            raise ImporterError(
                "cannot determine the x509-limbo revision; pass --source-revision"
            ) from error
    if actual != expected:
        raise ImporterError(
            f"x509-limbo revision mismatch: expected {expected}, found {actual}"
        )


def index_upstream(upstream: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if upstream.get("version") != 1:
        raise ImporterError("upstream limbo.json version must be 1")
    testcases = upstream.get("testcases")
    if not isinstance(testcases, list):
        raise ImporterError("upstream limbo.json testcases must be an array")

    by_id: dict[str, dict[str, Any]] = {}
    for testcase in testcases:
        if not isinstance(testcase, dict) or not isinstance(testcase.get("id"), str):
            raise ImporterError("every upstream testcase must be an object with an id")
        testcase_id = testcase["id"]
        if testcase_id in by_id:
            raise ImporterError(f"duplicate upstream testcase: {testcase_id}")
        by_id[testcase_id] = testcase
    return by_id


def generate_suites(
    manifest: dict[str, Any], upstream: dict[str, Any], selected_suites: set[str]
) -> dict[str, str]:
    validate_manifest(manifest)
    by_id = index_upstream(upstream)
    known_suites = {suite["name"] for suite in manifest["suites"]}
    unknown_suites = selected_suites - known_suites
    if unknown_suites:
        raise ImporterError(f"unknown suite(s): {', '.join(sorted(unknown_suites))}")

    generated: dict[str, str] = {}
    for suite in manifest["suites"]:
        if selected_suites and suite["name"] not in selected_suites:
            continue

        selected: list[dict[str, Any]] = []
        for capability in suite["testcases"]:
            testcase_id = capability["id"]
            if testcase_id not in by_id:
                raise ImporterError(f"upstream testcase is missing: {testcase_id}")
            if capability["status"] == "supported":
                selected.append(by_id[testcase_id])
        if not selected:
            raise ImporterError(f"{suite['name']}: suite has no supported testcases")

        fixture = {"source": manifest["source"], "testcases": selected}
        generated[suite["output"]] = (
            json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
        )
    return generated


def update_outputs(
    manifest_path: Path, generated: dict[str, str], check: bool
) -> list[Path]:
    changed: list[Path] = []
    for relative_output, content in generated.items():
        output = manifest_path.parent / relative_output
        current = output.read_text(encoding="utf-8") if output.exists() else None
        if current == content:
            continue
        changed.append(output)
        if not check:
            output.write_text(content, encoding="utf-8")
    return changed


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate curated spdm_x509 fixtures from a pinned x509-limbo suite"
    )
    parser.add_argument("limbo", type=Path, help="path to upstream limbo.json")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--suite", action="append", default=[])
    parser.add_argument(
        "--source-revision",
        help="revision for a standalone limbo.json outside its Git checkout",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if generated fixtures are not current",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        manifest = load_json(args.manifest)
        validate_manifest(manifest)
        verify_revision(
            args.limbo, manifest["source"]["revision"], args.source_revision
        )
        upstream = load_json(args.limbo)
        generated = generate_suites(manifest, upstream, set(args.suite))
        changed = update_outputs(args.manifest, generated, args.check)
    except (ImporterError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if args.check and changed:
        for output in changed:
            print(f"out of date: {output}", file=sys.stderr)
        return 1
    for output in changed:
        print(f"updated: {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

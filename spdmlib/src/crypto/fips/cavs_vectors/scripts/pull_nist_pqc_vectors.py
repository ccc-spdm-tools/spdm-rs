# Copyright (c) 2026 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0 or MIT

import argparse
import hashlib
from pathlib import Path
from urllib.request import urlopen


NIST_ACVP_SERVER_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
BASE_URL = (
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
    f"{NIST_ACVP_SERVER_COMMIT}/gen-val/json-files"
)
ARTIFACTS = {
    "ml-dsa-keygen.json": (
        "ML-DSA-keyGen-FIPS204/internalProjection.json",
        "e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf",
    ),
    "ml-dsa-siggen.json": (
        "ML-DSA-sigGen-FIPS204/internalProjection.json",
        "72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22",
    ),
    "ml-dsa-sigver.json": (
        "ML-DSA-sigVer-FIPS204/internalProjection.json",
        "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437",
    ),
    "ml-kem-keygen.json": (
        "ML-KEM-keyGen-FIPS203/internalProjection.json",
        "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b",
    ),
    "ml-kem-encap-decap.json": (
        "ML-KEM-encapDecap-FIPS203-tr1/internalProjection.json",
        "5e88fbd351dc2915b2ab399f5dffd269e1cdbdd0186103ab0e90b374cf592187",
    ),
}


def main():
    parser = argparse.ArgumentParser(description="Download pinned NIST PQC ACVP samples")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    for filename, (relative_url, expected_sha256) in ARTIFACTS.items():
        with urlopen(f"{BASE_URL}/{relative_url}") as response:
            contents = response.read()
        actual_sha256 = hashlib.sha256(contents).hexdigest()
        if actual_sha256 != expected_sha256:
            raise ValueError(
                f"{filename}: SHA-256 {actual_sha256}; expected {expected_sha256}"
            )
        destination = args.output / filename
        destination.write_bytes(contents)
        print(f"Downloaded {destination}")


if __name__ == "__main__":
    main()
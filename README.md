[![CI](https://github.com/ccc-spdm-tools/spdm-rs/actions/workflows/main.yml/badge.svg)](https://github.com/ccc-spdm-tools/spdm-rs/actions/workflows/main.yml)
[![Deny](https://github.com/ccc-spdm-tools/spdm-rs/actions/workflows/deny.yml/badge.svg)](https://github.com/ccc-spdm-tools/spdm-rs/actions/workflows/deny.yml)
[![Format](https://github.com/ccc-spdm-tools/spdm-rs/actions/workflows/format.yml/badge.svg)](https://github.com/ccc-spdm-tools/spdm-rs/actions/workflows/format.yml)
[![Fuzzing](https://github.com/ccc-spdm-tools/spdm-rs/actions/workflows/fuzz.yml/badge.svg)](https://github.com/ccc-spdm-tools/spdm-rs/actions/workflows/fuzz.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8901/badge)](https://www.bestpractices.dev/projects/8901)

# spdm-rs

This project provides a Rust language implementation of [SPDM](https://www.dmtf.org/standards/spdm),
[IDE_KM](https://pcisig.com/integrity-and-data-encryption-ide-ecn-%E2%80%93-revision)
and [TDISP](https://pcisig.com/tee-device-interface-security-protocol-tdisp).
These protocols are used to facilitate direct device assignment for Trusted Execution
Environment I/O (TEE-I/O) in Confidential Computing. 

There are a number of use cases that benefit from including devices and accelerators in the trust
boundary of a Confidential Virtual Machine (CVM). In machine learning, for example, these
protocols can be used to build a trusted connection between a GPU’s TEE and a CVM to accelerate
performance.


## Features

### Specification

#### DMTF

DMTF [DSP0274](https://www.dmtf.org/dsp/DSP0274) Security Protocol and Data Model (SPDM) Specification (version [1.4.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.4.0.pdf))

DMTF [DSP0277](https://www.dmtf.org/dsp/DSP0277) Secured Messages using SPDM Specification (version [1.2.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.2.0.pdf))

#### PCI-SIG

PCIe Base Specification Version [6.0.1](https://members.pcisig.com/wg/PCI-SIG/document/18363), [6.1](https://members.pcisig.com/wg/PCI-SIG/document/19849), [6.2](https://members.pcisig.com/wg/PCI-SIG/document/20590).

PCIe [DOE 1.0 ECN](https://members.pcisig.com/wg/PCI-SIG/document/14143) for PCIe 4.0, 5.0 (integrated in 6.0), [DOE 1.1 ECN](https://members.pcisig.com/wg/PCI-SIG/document/18483) for PCIe 5.0, 6.0 (integrated in 6.1).

PCIe [CMA 1.0 ECN](https://members.pcisig.com/wg/PCI-SIG/document/14236) for PCIe 4.0, 5.0 (integrated in 6.0), [CMA 1.1 ECN](https://members.pcisig.com/wg/PCI-SIG/document/20110) for PCIe 6.1 (integrated in 6.2).

PCIe [IDE ECN](https://members.pcisig.com/wg/PCI-SIG/document/16599) for PCIe 5.0 (integrated in 6.0).

PCIe [TDISP ECN](https://members.pcisig.com/wg/PCI-SIG/document/18268) for PCIe 5.0, 6.0 (integrated in 6.1).

### SPDM Implemented Requests and Responses

SPDM 1.0: GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, GET_DIGESTS, GET_CERTIFICATE, CHALLENGE, GET_MEASUREMENTS, and VENDOR_DEFINED messages.

SPDM 1.1: KEY_EXCHANGE, FINISH, PSK_EXCHANGE, PSK_FINISH, END_SESSION, HEARTBEAT, KEY_UPDATE, and ENCAPSULATED messages.

SPDM 1.2: CHUNK messages.

SPDM 1.3: No new messages.

SPDM 1.4: No new messages.

### SPDM Vendor Defined Message

IDE_KM 1.0 in PCIe 6.0.

TDISP 1.0 in PCIe 6.1.

### SPDM Capability Support

Requester: ENCRYPT_CAP, MAC_CAP, KEY_EX_CAP, PSK_CAP, HBEAT_CAP, KEY_UPD_CAP, HANDSHAKE_IN_THE_CLEAR_CAP, CHUNK_CAP, LARGE_RESP_CAP.

Responder: CERT_CAP, CHAL_CAP, MEAS_CAP_NO_SIG, MEAS_CAP_SIG, MEAS_FRESH_CAP, ENCRYPT_CAP, MAC_CAP, KEY_EX_CAP, PSK_CAP_WITHOUT_CONTEXT, PSK_CAP_WITH_CONTEXT, HBEAT_CAP, KEY_UPD_CAP, HANDSHAKE_IN_THE_CLEAR_CAP, CHUNK_CAP, ALIAS_CERT_CAP, LARGE_RESP_CAP.

### SPDM Cryptographic Algorithm Support

It depends on crypto wrapper. Current support algorithms:
* Hash: SHA2(256/384/512)
* Signature: RSA-SSA(2048/3072/4096) / RSA-PSS(2048/3072/4096) / ECDSA (P256/P384)
* KeyExchange: ECDHE(P256/P384)
* AEAD: AES_GCM(128/256) / ChaCha20Poly1305

## Documentation
All documents are put at [doc](./doc/) folder.

## Build Rust SPDM

### Checkout repo
```
git clone https://github.com/ccc-spdm-tools/spdm-rs.git
git submodule update --init --recursive
```

Then patch the ring/webpki.
```
sh_script/pre-build.sh
```

### Tools

1. Install [RUST](https://www.rust-lang.org/)

Please use stable version.

2. Install [NASM](https://www.nasm.us/)

Please make sure nasm can be found in PATH.

3. Install [LLVM](https://llvm.org/)

Please make sure clang can be found in PATH.

4. Install [Perl](https://www.perl.org/)

    1.	This is for crate ring
    2.	This is for windows

Please make sure perl can be found in PATH.


Unset env (CC and AR):
```
export CC=
export AR=
```
Set the following environment variables:
```
export AR_x86_64_unknown_none=llvm-ar
export CC_x86_64_unknown_none=clang
```

### Build OS application

Enter linux shell or mingw shell (e.g. git bash) in windows.
```
cargo clippy
cargo fmt
cargo build
```

### Build async `no_std` spdm
```
pushd spdmlib
cargo build --target x86_64-unknown-none --release --no-default-features --features="spdm-ring"
```

### Build sync `no_std` spdm
```
pushd spdmlib
cargo build --target x86_64-unknown-none --release --no-default-features --features="spdm-ring,is_sync"
```

## Run Rust SPDM emulator

### Run emulator with default feature

Open one command windows and run:
```
cargo run -p spdm-responder-emu --no-default-features --features "spdm-ring,hashed-transcript-data,async-executor"
```

Open another command windows and run:
```
cargo run -p spdm-requester-emu --no-default-features --features "spdm-ring,hashed-transcript-data,async-executor"
```

### Run emulator with selected feature

The following list shows the supported combinations for both spdm-requester-emu and spdm-responder-emu


| Features                                           | CryptoLibrary | Hashed transcript data support | sync/async             | notes                                                                                                           |
|----------------------------------------------------|---------------|--------------------------------|------------------------|-----------------------------------------------------------------------------------------------------------------|
| spdm-ring,is_sync                                  | ring          | No                             | sync                   | use ring as crypto library with hashed-transcript-data disabled, sync version.                                  |
| spdm-ring,hashed-transcript-data,is_sync           | ring          | Yes                            | sync                   | use ring as crypto library with hashed-transcript-data enabled, sync version.                                   |
| spdm-ring,hashed-transcript-data,async-tokio       | ring          | Yes                            | tokio async runtime    | use ring as crypto library with hashed-transcript-data enabled, async version, use tokio as async runtime       |
| spdm-mbedtls,is_sync                               | mbedtls       | No                             | sync                   | use mbedtls as crypto library with hashed-transcript-data disabled, sync version.                               |
| spdm-mbedtls,hashed-transcript-data,is_sync        | mbedtls       | Yes                            | sync                   | use mbedtls as crypto library with hashed-transcript-data enabled, sync version.                                |
| spdm-mbedtls,hashed-transcript-data,async-executor | mbedtls       | Yes                            | executor async runtime | use mbedtls as crypto library with hashed-transcript-data enabled, async version, use executor as async runtime |


For example, run the emulator with spdm-ring enabled and without hashed-transcript-data enabled, and use executor as async runtime. 
Open one command windows and run:
```
cargo run -p spdm-responder-emu --no-default-features --features "spdm-ring,async-executor "
```

run the emulator with spdm-mbedtls enabled and with hashed-transcript-data enabled, and use tokio as async runtime.  
Open another command windows and run:
```
cargo run -p spdm-requester-emu --no-default-features --features "spdm-mbedtls,hashed-transcript-data,async-tokio"
```

run the emulator with spdm-mbedtls enabled and with hashed-transcript-data enabled, and without using async style.  
Open another command windows and run:
```
cargo run -p spdm-requester-emu --no-default-features --features "spdm-mbedtls,hashed-transcript-data,is_sync"
```

NOTE: In order to run the emu without hashed-transcript-data, please change `max_cert_chain_data_size` in `spdmlib/etc/config.json` from `4096` to `3500`.

### Run the responder emulator using the certificate chain and private key specified in environment variables

Open command window and run:

```bash
export SPDMRS_RSP_EMU_CERT_CHAIN_PATH=/path/to/cert_bundle.der
export SPDMRS_RSP_EMU_PRIVATE_KEY_PATH=/path/to/device.key.p8

cargo run -p spdm-responder-emu --no-default-features --features "spdm-ring,hashed-transcript-data,async-executor"
```

If RSA is used instead of ECDSA, following environment variables can be set before running spdm-requester-emu, spdm-responder-emu, or spdmlib-test:
```bash
export SPDMRS_USE_ECDSA=false        # controls base_asym_algo (BaseAsymAlgo)
export SPDMRS_REQ_USE_ECDSA=false    # controls req_asym_algo (ReqBaseAsymAlg)
```

### Cross test with [spdm_emu](https://github.com/DMTF/spdm-emu)
Open one command windows in workspace and run:

```
git clone https://github.com/DMTF/spdm-emu.git
cd spdm-emu
git submodule update --init --recursive
mkdir build
cd build
cmake -G"NMake Makefiles" -DARCH=<x64|ia32> -DTOOLCHAIN=<toolchain> -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
nmake copy_sample_key
nmake
```

Test spdm-rs as requester:

1. run libspdm in spdm-emu as responder:
```
cd bin
spdm_responder_emu.exe --trans PCI_DOE
```

2. run spdm-rs-emu as requester:
```
cargo run -p spdm-requester-emu --no-default-features --features "spdm-ring,hashed-transcript-data,async-executor "
```

Test spdm-rs as responder:

1. run spdm-rs-emu as Test spdm-rs as responder:
```
cargo run -p spdm-responder-emu --no-default-features --features "spdm-ring,hashed-transcript-data,async-executor "
```

2. run libspdm in spdm-emu as requester:
```
cd bin
spdm_requester_emu.exe --trans PCI_DOE --exe_conn DIGEST,CERT,CHAL,MEAS --exe_session KEY_EX,PSK,KEY_UPDATE,HEARTBEAT,MEAS,DIGEST,CERT
```

### Run test cases

Setting up enough stack before running tests

```
export RUST_MIN_STACK=10485760
```

Test with hashed-transcript-data:
```
cargo test --no-default-features --features "spdmlib/std,spdmlib/spdm-ring,spdmlib/hashed-transcript-data,async-executor" -- --test-threads=1
```

Test without hashed-transcript-data:
```
cargo test --no-default-features --features "spdmlib/std,spdmlib/spdm-ring,async-executor" -- --test-threads=1
```

To run a specific test, use `cargo test <test_func_name>`

To run test with println!() message, use `cargo test -- --nocapture`

To run tests with chunk capability:
```
export SPDM_CONFIG="etc/chunk_test_config.json"
cargo test --no-default-features --features "spdmlib/std,spdmlib/spdm-ring,spdm-emu/is_sync,spdmlib/is_sync,maybe-async/is_sync,idekm/is_sync,tdisp/is_sync,mctp_transport/is_sync,pcidoe_transport/is_sync,spdm-requester-emu/is_sync,spdm-responder-emu/is_sync,chunk-cap" -- --test-threads=1
export SPDM_CONFIG="etc/config.json"
```

To run spdmlib-test:
```
pushd test/spdmlib-test
cargo test --no-default-features -- --test-threads=1
popd
```

To run spdmlib-test with chunk capability:
```
pushd test/spdmlib-test
export SPDM_CONFIG="etc/chunk_test_config.json"
cargo test --no-default-features --features "chunk-cap" -- --test-threads=1
export SPDM_CONFIG="etc/config.json"
popd
```


## Collect memory usage

To collect memory usage, use

```
python sh_script/collect_memory_usage.py
```

This script will display the peak memory used by spdm-emu

## Known limitation
This package is only the sample code to show the concept. It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet. Any codes including the API definition, the libary and the drivers are subject to change.

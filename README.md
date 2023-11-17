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

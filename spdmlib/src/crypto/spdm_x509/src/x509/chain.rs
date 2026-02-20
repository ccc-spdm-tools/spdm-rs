// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! SPDM Certificate Chain Handling
//!
//! This module implements parsing and validation of SPDM certificate chains
//! according to DSP0274 specification.
//!
//! # SPDM Certificate Chain Format
//!
//! The SPDM certificate chain has a specific header format followed by certificates:
//!
//! ```text
//! struct spdm_cert_chain_t {
//!     uint16_t length;              // Total length in bytes
//!     uint16_t reserved;            // Must be 0
//!     uint8_t root_hash[hash_size]; // Hash of root certificate
//!     uint8_t certificates[];       // Concatenated DER certificates
//! }
//! ```
//!
//! # References
//! - DSP0274 Section 10.6.1 - Certificate Chain Format

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use super::validator::{ValidationOptions, Validator};
use crate::certificate::Certificate;
use crate::chain::CertificateChain;
use crate::crypto_backend::CryptoBackend;
use crate::error::{ChainError, Error, Result};

use super::signature::SpdmBaseHashAlgo;
use super::spdm_validator::{SpdmCertificateRole, SpdmValidator};
use der::Encode;

// =============================================================================
// SPDM Certificate Chain Header
// =============================================================================

/// SPDM Certificate Chain Header (DSP0274 Section 10.6.1)
///
/// This header precedes the certificate chain in SPDM messages.
/// It includes the total length and a hash of the root certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmCertChainHeader {
    /// Total length of the certificate chain (including this header)
    pub length: u16,

    /// Reserved field (must be 0)
    pub reserved: u16,

    /// Hash of the root certificate
    /// The size depends on the negotiated hash algorithm:
    /// - SHA-256: 32 bytes
    /// - SHA-384: 48 bytes
    /// - SHA-512: 64 bytes
    /// - SHA3-256: 32 bytes
    /// - SHA3-384: 48 bytes
    /// - SHA3-512: 64 bytes
    pub root_hash: Vec<u8>,
}

impl SpdmCertChainHeader {
    /// Minimum header size (without root hash)
    pub const MIN_SIZE: usize = 4;

    /// Create a new SPDM certificate chain header
    ///
    /// # Arguments
    /// * `length` - Total length of the certificate chain in bytes (including header)
    /// * `root_hash` - Hash of the root certificate using negotiated hash algorithm
    ///
    /// # Example
    /// ```no_run
    /// use spdm_x509::x509::SpdmCertChainHeader;
    /// let root_hash = vec![0u8; 32]; // SHA-256 hash
    /// let header = SpdmCertChainHeader::new(500, root_hash);
    /// assert_eq!(header.length, 500);
    /// ```
    pub fn new(length: u16, root_hash: Vec<u8>) -> Self {
        Self {
            length,
            reserved: 0,
            root_hash,
        }
    }

    /// Parse an SPDM certificate chain header from bytes
    ///
    /// # Arguments
    /// - `data`: The raw header bytes
    /// - `hash_size`: Expected size of the root hash (based on negotiated algorithm)
    ///
    /// # Returns
    /// - `Ok((header, remaining_bytes))` on success
    /// - `Err(Error)` if parsing fails
    pub fn from_bytes(data: &[u8], hash_size: usize) -> Result<(Self, &[u8])> {
        let expected_header_size = Self::MIN_SIZE + hash_size;

        if data.len() < expected_header_size {
            return Err(Error::ParseError(crate::error::ParseError::InvalidDer(
                alloc::format!(
                    "Certificate chain too short: expected at least {} bytes, got {}",
                    expected_header_size,
                    data.len()
                ),
            )));
        }

        // Parse length (little-endian)
        let length = u16::from_le_bytes([data[0], data[1]]);

        // Parse reserved field (must be 0)
        let reserved = u16::from_le_bytes([data[2], data[3]]);
        if reserved != 0 {
            return Err(Error::ParseError(crate::error::ParseError::InvalidDer(
                alloc::format!("Reserved field must be 0, got {}", reserved),
            )));
        }

        // Extract root hash
        let root_hash = data[4..4 + hash_size].to_vec();

        // Remaining bytes are the certificates
        let remaining = &data[expected_header_size..];

        Ok((
            Self {
                length,
                reserved,
                root_hash,
            },
            remaining,
        ))
    }

    /// Serialize the header to bytes
    ///
    /// # Returns
    /// A vector containing the serialized header in little-endian format:
    /// - Bytes 0-1: length (u16, little-endian)
    /// - Bytes 2-3: reserved (u16, always 0)
    /// - Remaining bytes: root hash
    ///
    /// # Example
    /// ```no_run
    /// use spdm_x509::x509::SpdmCertChainHeader;
    /// let header = SpdmCertChainHeader::new(100, vec![0u8; 32]);
    /// let bytes = header.to_bytes();
    /// assert_eq!(bytes.len(), 36); // 4 + 32
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.length.to_le_bytes());
        bytes.extend_from_slice(&self.reserved.to_le_bytes());
        bytes.extend_from_slice(&self.root_hash);
        bytes
    }

    /// Get the expected hash size for a given hash algorithm
    ///
    /// # Arguments
    /// * `algo` - The SPDM hash algorithm
    ///
    /// # Returns
    /// The hash size in bytes:
    /// - SHA-256/SHA3-256/SM3-256: 32 bytes
    /// - SHA-384/SHA3-384: 48 bytes
    /// - SHA-512/SHA3-512: 64 bytes
    ///
    /// # Example
    /// ```no_run
    /// use spdm_x509::x509::{SpdmBaseHashAlgo, SpdmCertChainHeader};
    /// assert_eq!(SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha256), 32);
    /// ```
    pub fn hash_size_for_algo(algo: SpdmBaseHashAlgo) -> usize {
        match algo {
            SpdmBaseHashAlgo::Sha256 | SpdmBaseHashAlgo::Sha3_256 | SpdmBaseHashAlgo::Sm3_256 => 32,
            SpdmBaseHashAlgo::Sha384 | SpdmBaseHashAlgo::Sha3_384 => 48,
            SpdmBaseHashAlgo::Sha512 | SpdmBaseHashAlgo::Sha3_512 => 64,
        }
    }
}

impl fmt::Display for SpdmCertChainHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SpdmCertChainHeader {{ length: {}, root_hash: {} bytes }}",
            self.length,
            self.root_hash.len()
        )
    }
}

// =============================================================================
// Certificate Chain Parsing
// =============================================================================

/// Parse an SPDM certificate chain from raw bytes
///
/// # Arguments
/// - `data`: The raw certificate chain data (including header)
/// - `base_hash_algo`: The negotiated SPDM base hash algorithm (bitfield)
///
/// # Returns
/// - `Ok((header, certificates))` containing the parsed header and certificate list
/// - `Err(Error)` if parsing fails
///
/// # Example
/// ```no_run
/// use spdm_x509::x509::{parse_spdm_cert_chain, SpdmBaseHashAlgo};
///
/// let chain_data: &[u8] = &[];
/// let base_hash_algo = 1 << 0; // SHA-256
/// let _ = SpdmBaseHashAlgo::Sha256;
/// let _ = parse_spdm_cert_chain(chain_data, base_hash_algo);
/// ```
pub fn parse_spdm_cert_chain(
    data: &[u8],
    base_hash_algo: u32,
) -> Result<(SpdmCertChainHeader, Vec<Certificate>)> {
    // Determine the hash size from the negotiated algorithm.
    // SPDM negotiation settles on exactly one hash algorithm; if the caller
    // passes a bitfield with multiple bits set we reject it to avoid
    // silently picking the wrong hash.
    let hash_algos = SpdmBaseHashAlgo::from_bits(base_hash_algo);
    if hash_algos.is_empty() {
        return Err(Error::ValidationError(alloc::string::String::from(
            "No hash algorithm negotiated",
        )));
    }
    if hash_algos.len() > 1 {
        return Err(Error::ValidationError(alloc::string::String::from(
            "Multiple hash algorithms in base_hash_algo bitfield; \
             expected exactly one negotiated algorithm",
        )));
    }

    let hash_size = SpdmCertChainHeader::hash_size_for_algo(hash_algos[0]);

    // Parse the header
    let (header, cert_data) = SpdmCertChainHeader::from_bytes(data, hash_size)?;

    // Verify the length field matches the actual data
    if (header.length as usize) != data.len() {
        return Err(Error::ParseError(crate::error::ParseError::InvalidDer(
            alloc::format!(
                "Chain length mismatch: header says {}, actual {}",
                header.length,
                data.len()
            ),
        )));
    }

    // Parse concatenated certificates
    let certificates = parse_concatenated_certificates(cert_data)?;

    if certificates.is_empty() {
        return Err(Error::ChainError(ChainError::EmptyChain));
    }

    Ok((header, certificates))
}

/// Parse concatenated DER-encoded certificates
///
/// Certificates in an SPDM chain are concatenated without delimiters.
/// Each certificate is a DER SEQUENCE, so we can parse them sequentially.
/// We determine each certificate's length by parsing the DER tag+length header
/// directly, rather than re-encoding (which could desync on non-canonical DER).
fn parse_concatenated_certificates(mut data: &[u8]) -> Result<Vec<Certificate>> {
    let mut certificates = Vec::new();

    while !data.is_empty() {
        // Determine the total TLV length of the next DER SEQUENCE by
        // parsing the tag + length header directly from the raw bytes.
        let cert_len = der_sequence_total_length(data)?;

        if cert_len > data.len() {
            return Err(Error::ParseError(crate::error::ParseError::InvalidDer(
                alloc::string::String::from("Certificate DER length exceeds remaining data"),
            )));
        }

        let cert = Certificate::from_der(&data[..cert_len]).map_err(|e| {
            Error::ParseError(crate::error::ParseError::InvalidDer(alloc::format!(
                "Failed to parse certificate in chain: {:?}",
                e
            )))
        })?;

        data = &data[cert_len..];
        certificates.push(cert);
    }

    Ok(certificates)
}

/// Parse a DER SEQUENCE tag + length to determine the total element size
/// (tag byte + length encoding + content).
///
/// Supports short-form and long-form (1-4 byte) DER length encoding.
fn der_sequence_total_length(data: &[u8]) -> Result<usize> {
    if data.len() < 2 {
        return Err(Error::ParseError(crate::error::ParseError::UnexpectedEof));
    }

    // Verify SEQUENCE tag (0x30)
    if data[0] != 0x30 {
        return Err(Error::ParseError(crate::error::ParseError::InvalidTag {
            expected: 0x30,
            found: data[0],
        }));
    }

    let (content_len, header_len) = if data[1] & 0x80 == 0 {
        // Short form: length fits in 7 bits
        (data[1] as usize, 2usize)
    } else {
        // Long form: lower 7 bits give the number of subsequent length bytes
        let num_len_bytes = (data[1] & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 {
            return Err(Error::ParseError(crate::error::ParseError::InvalidLength(
                alloc::format!(
                    "Unsupported DER length encoding: {} length bytes",
                    num_len_bytes
                ),
            )));
        }
        if data.len() < 2 + num_len_bytes {
            return Err(Error::ParseError(crate::error::ParseError::UnexpectedEof));
        }
        let mut len = 0usize;
        for i in 0..num_len_bytes {
            len = (len << 8) | (data[2 + i] as usize);
        }
        (len, 2 + num_len_bytes)
    };

    Ok(header_len + content_len)
}

// =============================================================================
// Certificate Chain Validation
// =============================================================================

/// Validate an SPDM certificate chain with SPDM-specific rules
///
/// This performs standard X.509 chain validation plus SPDM-specific checks:
/// - Verifies the root certificate hash matches the header
/// - Validates all certificates in the chain
/// - Ensures proper certificate ordering (root -> intermediate -> leaf)
///
/// # Arguments
/// - `header`: The parsed SPDM certificate chain header
/// - `certificates`: The list of certificates in the chain
/// - `base_hash_algo`: The negotiated SPDM base hash algorithm (bitfield)
/// - `options`: Validation options
///
/// # Returns
/// - `Ok(())` if validation succeeds
/// - `Err(Error)` if validation fails
///
/// Validate an SPDM certificate chain using the default Ring backend.
///
/// Convenience wrapper around [`validate_spdm_cert_chain_with_backend`].
#[cfg(feature = "ring-backend")]
pub fn validate_spdm_cert_chain(
    header: &SpdmCertChainHeader,
    certificates: &[Certificate],
    base_hash_algo: u32,
    options: &ValidationOptions,
) -> Result<()> {
    validate_spdm_cert_chain_with_backend(
        header,
        certificates,
        base_hash_algo,
        options,
        crate::crypto_backend::RingBackend,
    )
}

/// Fallback when no crypto backend is compiled in.
#[cfg(not(feature = "ring-backend"))]
pub fn validate_spdm_cert_chain(
    _header: &SpdmCertChainHeader,
    _certificates: &[Certificate],
    _base_hash_algo: u32,
    _options: &ValidationOptions,
) -> Result<()> {
    unimplemented!("validate_spdm_cert_chain requires a crypto backend feature (e.g. ring-backend)")
}

/// Validate an SPDM certificate chain with SPDM-specific rules using the
/// given crypto backend.
///
/// This performs standard X.509 chain validation plus SPDM-specific checks:
/// - Verifies the root certificate hash matches the header
/// - Validates all certificates in the chain
/// - Ensures proper certificate ordering (root -> intermediate -> leaf)
pub fn validate_spdm_cert_chain_with_backend<B: CryptoBackend>(
    header: &SpdmCertChainHeader,
    certificates: &[Certificate],
    base_hash_algo: u32,
    options: &ValidationOptions,
    backend: B,
) -> Result<()> {
    if certificates.is_empty() {
        return Err(Error::ChainError(ChainError::EmptyChain));
    }

    // Verify the root certificate hash.
    // In the SPDM cert chain format (DSP0274) certificates are ordered
    // root -> intermediate -> leaf, so certificates[0] is the root.
    verify_root_cert_hash(&certificates[0], &header.root_hash, base_hash_algo)?;

    // IMPORTANT: The X.509 chain validator expects leaf -> root order,
    // but SPDM cert chains are root -> leaf.  Reverse before validating.
    let mut reversed = certificates.to_vec();
    reversed.reverse();
    let chain = CertificateChain::new(reversed);

    // Perform standard X.509 chain validation
    let validator = Validator::with_backend(backend);
    validator.validate_chain(&chain, options)?;

    Ok(())
}

/// Verify that the hash of the root certificate matches the header
fn verify_root_cert_hash(
    root_cert: &Certificate,
    expected_hash: &[u8],
    base_hash_algo: u32,
) -> Result<()> {
    // Get the DER encoding of the root certificate
    let root_der = root_cert.to_der().map_err(|e| {
        Error::ParseError(crate::error::ParseError::InvalidDer(alloc::format!(
            "Failed to encode root certificate: {:?}",
            e
        )))
    })?;

    // Compute the hash using the negotiated algorithm
    let hash_algos = SpdmBaseHashAlgo::from_bits(base_hash_algo);
    if hash_algos.is_empty() {
        return Err(Error::ValidationError(alloc::string::String::from(
            "No hash algorithm negotiated",
        )));
    }

    let computed_hash = compute_hash(&root_der, hash_algos[0])?;

    // Constant-time comparison to prevent timing side-channels on the root
    // trust anchor hash. We iterate all bytes unconditionally (XOR + OR
    // accumulator) so the execution time is independent of where a mismatch
    // occurs.
    if computed_hash.len() != expected_hash.len()
        || computed_hash
            .iter()
            .zip(expected_hash.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            != 0
    {
        return Err(Error::ValidationError(alloc::string::String::from(
            "Root certificate hash mismatch",
        )));
    }

    Ok(())
}

/// Compute hash of data using the specified SPDM hash algorithm
fn compute_hash(data: &[u8], algo: SpdmBaseHashAlgo) -> Result<Vec<u8>> {
    #[cfg(feature = "ring-backend")]
    {
        use ring::digest;

        let algorithm = match algo {
            SpdmBaseHashAlgo::Sha256 => &digest::SHA256,
            SpdmBaseHashAlgo::Sha384 => &digest::SHA384,
            SpdmBaseHashAlgo::Sha512 => &digest::SHA512,
            _ => {
                return Err(Error::AlgorithmError(
                    crate::error::AlgorithmError::Unsupported(alloc::format!(
                        "Hash algorithm not supported by ring backend: {:?}",
                        algo
                    )),
                ));
            }
        };

        let hash = digest::digest(algorithm, data);
        Ok(hash.as_ref().to_vec())
    }

    #[cfg(not(feature = "ring-backend"))]
    {
        let _ = data;
        let _ = algo;
        Err(Error::AlgorithmError(
            crate::error::AlgorithmError::Unsupported(alloc::string::String::from(
                "Hash computation backend not available",
            )),
        ))
    }
}

#[cfg(all(test, feature = "ring-backend"))]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec;

    #[test]
    fn test_spdm_cert_chain_header_size() {
        assert_eq!(
            SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha256),
            32
        );
        assert_eq!(
            SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha384),
            48
        );
        assert_eq!(
            SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha512),
            64
        );
    }

    #[test]
    fn test_header_serialization() {
        let header = SpdmCertChainHeader::new(100, vec![0u8; 32]);
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), 4 + 32);
        assert_eq!(bytes[0], 100);
        assert_eq!(bytes[1], 0);
        assert_eq!(bytes[2], 0); // reserved
        assert_eq!(bytes[3], 0); // reserved
    }

    #[test]
    fn test_header_parsing() {
        let mut data = vec![0u8; 36]; // 4 byte header + 32 byte hash
        data[0] = 36; // length low byte
        data[1] = 0; // length high byte
        data[2] = 0; // reserved low byte
        data[3] = 0; // reserved high byte
                     // Hash bytes are all zeros

        let (header, remaining) = SpdmCertChainHeader::from_bytes(&data, 32).unwrap();

        assert_eq!(header.length, 36);
        assert_eq!(header.reserved, 0);
        assert_eq!(header.root_hash.len(), 32);
        assert_eq!(remaining.len(), 0);
    }

    #[test]
    fn test_header_parsing_invalid_reserved() {
        let mut data = vec![0u8; 36];
        data[0] = 36;
        data[2] = 1; // reserved should be 0

        let result = SpdmCertChainHeader::from_bytes(&data, 32);
        assert!(result.is_err());
    }

    // ── der_sequence_total_length ──

    #[test]
    fn test_der_seq_short_form_length() {
        // SEQUENCE { 10 bytes of content }
        let mut data = vec![0x30, 0x0A];
        data.extend_from_slice(&[0u8; 10]);
        assert_eq!(der_sequence_total_length(&data).unwrap(), 12);
    }

    #[test]
    fn test_der_seq_long_form_1_byte() {
        // SEQUENCE { 200 bytes of content } — 0x81 0xC8
        let mut data = vec![0x30, 0x81, 0xC8];
        data.extend_from_slice(&[0u8; 200]);
        assert_eq!(der_sequence_total_length(&data).unwrap(), 203);
    }

    #[test]
    fn test_der_seq_long_form_2_bytes() {
        // SEQUENCE { 300 bytes } — 0x82 0x01 0x2C
        let mut data = vec![0x30, 0x82, 0x01, 0x2C];
        data.extend_from_slice(&[0u8; 300]);
        assert_eq!(der_sequence_total_length(&data).unwrap(), 304);
    }

    #[test]
    fn test_der_seq_not_sequence_tag() {
        let data = [0x31, 0x00]; // SET, not SEQUENCE
        assert!(der_sequence_total_length(&data).is_err());
    }

    #[test]
    fn test_der_seq_too_short() {
        let data = [0x30]; // only 1 byte
        assert!(der_sequence_total_length(&data).is_err());
    }

    #[test]
    fn test_der_seq_empty_input() {
        let data: &[u8] = &[];
        assert!(der_sequence_total_length(data).is_err());
    }

    #[test]
    fn test_der_seq_zero_length() {
        let data = [0x30, 0x00]; // SEQUENCE with 0 content
        assert_eq!(der_sequence_total_length(&data).unwrap(), 2);
    }

    // ── get_cert_from_cert_chain ──

    #[test]
    fn test_get_cert_index_0_from_real_chain() {
        let chain = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/ecp256/bundle_responder.certchain.der"
        ))
        .expect("ecp256 certchain");

        let (start, end) = get_cert_from_cert_chain(&chain, 0).unwrap();
        assert_eq!(start, 0);
        assert!(end > 0);
        assert!(end <= chain.len());
        // Should be a valid DER certificate
        let cert = Certificate::from_der(&chain[start..end]);
        assert!(cert.is_ok(), "cert 0 parse failed: {:?}", cert.err());
    }

    #[test]
    fn test_get_cert_last_from_real_chain() {
        let chain = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/ecp256/bundle_responder.certchain.der"
        ))
        .expect("ecp256 certchain");

        let (start, end) = get_cert_from_cert_chain(&chain, -1).unwrap();
        assert!(start < end);
        assert_eq!(end, chain.len()); // last cert goes to the end
        let cert = Certificate::from_der(&chain[start..end]);
        assert!(cert.is_ok(), "last cert parse failed: {:?}", cert.err());
    }

    #[test]
    fn test_get_cert_out_of_bounds() {
        let chain = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/ecp256/bundle_responder.certchain.der"
        ))
        .expect("ecp256 certchain");

        let result = get_cert_from_cert_chain(&chain, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_cert_empty_chain() {
        let result = get_cert_from_cert_chain(&[], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_cert_garbage_data() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        let result = get_cert_from_cert_chain(&data, 0);
        assert!(result.is_err());
    }

    // ── parse_spdm_cert_chain ──

    #[test]
    fn test_parse_spdm_cert_chain_no_hash_algo() {
        let data = vec![0u8; 100];
        let result = parse_spdm_cert_chain(&data, 0); // 0 = no hash algo
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_spdm_cert_chain_multiple_hash_algos_rejected() {
        let data = vec![0u8; 100];
        let hash = (1u32 << 0) | (1u32 << 1); // SHA-256 + SHA-384
        let result = parse_spdm_cert_chain(&data, hash);
        assert!(result.is_err());
    }

    // ── verify_cert_chain with real certificates ──

    #[test]
    fn test_verify_cert_chain_ecp256_real() {
        let chain = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/ecp256/bundle_responder.certchain.der"
        ))
        .expect("ecp256 certchain");

        let result = verify_cert_chain(&chain);
        assert!(
            result.is_ok(),
            "ecp256 chain validation failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_cert_chain_ecp384_real() {
        let chain = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/ecp384/bundle_responder.certchain.der"
        ))
        .expect("ecp384 certchain");

        let result = verify_cert_chain(&chain);
        assert!(
            result.is_ok(),
            "ecp384 chain validation failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_cert_chain_rsa3072_real() {
        let chain = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/rsa3072/bundle_responder.certchain.der"
        ))
        .expect("rsa3072 certchain");

        let result = verify_cert_chain(&chain);
        assert!(
            result.is_ok(),
            "rsa3072 chain validation failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_cert_chain_empty_rejected() {
        let result = verify_cert_chain(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_cert_chain_garbage_rejected() {
        let result = verify_cert_chain(&[0x01, 0x02, 0x03]);
        assert!(result.is_err());
    }

    // ── verify_cert_chain_with_options: algorithm enforcement ──

    #[test]
    fn test_verify_cert_chain_with_ecdsa_p256_algo_match() {
        let chain = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/ecp256/bundle_responder.certchain.der"
        ))
        .expect("ecp256 certchain");

        let asym = 1u32 << 4; // EcdsaP256
        let hash = 1u32 << 0; // SHA-256
        let result = verify_cert_chain_with_options(&chain, Some(asym), Some(hash));
        assert!(
            result.is_ok(),
            "ecp256 algo match failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_cert_chain_with_wrong_asym_algo_rejected() {
        let chain = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/ecp256/bundle_responder.certchain.der"
        ))
        .expect("ecp256 certchain");

        let asym = 1u32 << 0; // RsaSsa2048 only — wrong for ECC chain
        let hash = 1u32 << 0; // SHA-256
        let result = verify_cert_chain_with_options(&chain, Some(asym), Some(hash));
        assert!(result.is_err(), "should reject RSA-only algo for ECC chain");
    }

    // ── compute_hash ──

    #[test]
    fn test_compute_hash_sha256() {
        let data = b"hello spdm";
        let hash = compute_hash(data, SpdmBaseHashAlgo::Sha256).unwrap();
        assert_eq!(hash.len(), 32);
        // SHA-256 of "hello spdm" should be deterministic
        let hash2 = compute_hash(data, SpdmBaseHashAlgo::Sha256).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_compute_hash_sha384() {
        let data = b"hello spdm";
        let hash = compute_hash(data, SpdmBaseHashAlgo::Sha384).unwrap();
        assert_eq!(hash.len(), 48);
    }

    #[test]
    fn test_compute_hash_sha512() {
        let data = b"hello spdm";
        let hash = compute_hash(data, SpdmBaseHashAlgo::Sha512).unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_compute_hash_empty_data() {
        let hash = compute_hash(&[], SpdmBaseHashAlgo::Sha256).unwrap();
        assert_eq!(hash.len(), 32);
    }

    // ── parse_concatenated_certificates ──

    #[test]
    fn test_parse_concatenated_certs_from_real_chain() {
        let chain = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/ecp256/bundle_responder.certchain.der"
        ))
        .expect("ecp256 certchain");

        let certs = parse_concatenated_certificates(&chain).unwrap();
        assert!(
            certs.len() >= 2,
            "Expected at least root + leaf, got {}",
            certs.len()
        );
    }

    #[test]
    fn test_parse_concatenated_certs_single_cert() {
        let cert_der = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/ecp256/ca.cert.der"
        ))
        .expect("ca cert");

        let certs = parse_concatenated_certificates(&cert_der).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_parse_concatenated_certs_empty() {
        let certs = parse_concatenated_certificates(&[]).unwrap();
        assert!(certs.is_empty());
    }
}

// =============================================================================
// spdmlib-compatible Functions (for spdm-rs integration)
// =============================================================================

/// Gets a certificate from a DER certificate chain by index
///
/// This function is **directly compatible** with spdmlib interface.
/// It parses concatenated DER certificates and returns byte offsets
/// for the requested certificate.
///
/// # Arguments
/// * `cert_chain` - Buffer containing concatenated DER certificates
/// * `index` - Certificate index (0=first, -1=last/leaf)
///
/// # Returns
/// * `Ok((start_offset, end_offset))` - Byte offsets of the certificate
/// * `Err` - If certificate doesn't exist or format is invalid
///
/// # Format
/// Each DER certificate starts with:
/// - Tag: 0x30 (SEQUENCE)
/// - Length: Variable encoding (0x81, 0x82 for long form)
/// - Content: Certificate data
///
/// # Example
/// ```no_run
/// use spdm_x509::x509::get_cert_from_cert_chain;
/// let cert_chain: &[u8] = &[];
/// let _ = get_cert_from_cert_chain(cert_chain, -1);
/// let _ = get_cert_from_cert_chain(cert_chain, 0);
/// ```
pub fn get_cert_from_cert_chain(cert_chain: &[u8], index: isize) -> Result<(usize, usize)> {
    let mut offset = 0usize;
    let mut cert_index = 0isize;
    let chain_size = cert_chain.len();

    // Handle empty chain
    if chain_size < 4 {
        return Err(Error::ChainError(ChainError::EmptyChain));
    }

    loop {
        // Need at least 2 bytes for tag + length header
        if offset + 2 > chain_size {
            break;
        }

        // Reuse the canonical DER SEQUENCE length parser (supports short-form
        // and 1-4 byte long-form) instead of duplicating the logic here.
        let cert_len = der_sequence_total_length(&cert_chain[offset..])?;

        // Validate length
        if offset + cert_len > chain_size {
            return Err(Error::ValidationError(alloc::format!(
                "Certificate length {} exceeds chain size at offset {}",
                cert_len,
                offset
            )));
        }

        // Check if this is the requested certificate
        if cert_index == index {
            return Ok((offset, offset + cert_len));
        }

        // Check for last certificate (index == -1)
        if (offset + cert_len == chain_size) && (index == -1) {
            return Ok((offset, offset + cert_len));
        }

        // Move to next certificate
        cert_index += 1;
        offset += cert_len;

        // Safety check
        if cert_index > 100 {
            return Err(Error::ValidationError(
                "Certificate chain too long (>100 certificates)".into(),
            ));
        }
    }

    Err(Error::ValidationError(alloc::format!(
        "Certificate index {} not found in chain",
        index
    )))
}

/// Validates a DER certificate chain according to DSP0274
///
/// This function is **directly compatible** with spdmlib interface.
/// It parses and validates a concatenated DER certificate chain.
///
/// # Arguments
/// * `cert_chain` - Buffer containing concatenated DER certificates
///
/// # Returns
/// * `Ok(())` - If validation succeeds
/// * `Err` - If validation fails
///
/// # Validation Steps
/// 1. Parse individual certificates from the chain
/// 2. Build a CertificateChain structure
/// 3. Validate using standard X.509 validator
/// 4. Check signatures, validity periods, and extensions
/// 5. Validate SPDM EKU on the leaf certificate
///
/// # Note
/// This function performs structural and cryptographic chain validation
/// but does **not** verify SPDM algorithm negotiation constraints
/// (base_asym_algo / base_hash_algo) since those parameters are not
/// available at this API level.  Use [`SpdmValidator::validate_spdm_certificate`]
/// for full SPDM algorithm enforcement.
///
/// # Example
/// ```no_run
/// use spdm_x509::x509::verify_cert_chain;
/// let cert_chain: &[u8] = &[];
/// let _ = verify_cert_chain(cert_chain);
/// ```
/// Convenience wrapper using the default Ring backend.
///
/// See [`verify_cert_chain_with_backend`] for the generic version.
#[cfg(feature = "ring-backend")]
pub fn verify_cert_chain(cert_chain: &[u8]) -> Result<()> {
    verify_cert_chain_with_backend(cert_chain, crate::crypto_backend::RingBackend, None, None)
}

/// Fallback when no crypto backend is compiled in.
#[cfg(not(feature = "ring-backend"))]
pub fn verify_cert_chain(_cert_chain: &[u8]) -> Result<()> {
    unimplemented!("verify_cert_chain requires a crypto backend feature (e.g. ring-backend)")
}

/// Convenience wrapper using the default Ring backend with algorithm options.
///
/// See [`verify_cert_chain_with_backend`] for the generic version.
#[cfg(feature = "ring-backend")]
pub fn verify_cert_chain_with_options(
    cert_chain: &[u8],
    base_asym_algo: Option<u32>,
    base_hash_algo: Option<u32>,
) -> Result<()> {
    verify_cert_chain_with_backend(
        cert_chain,
        crate::crypto_backend::RingBackend,
        base_asym_algo,
        base_hash_algo,
    )
}

/// Fallback when no crypto backend is compiled in.
#[cfg(not(feature = "ring-backend"))]
pub fn verify_cert_chain_with_options(
    _cert_chain: &[u8],
    _base_asym_algo: Option<u32>,
    _base_hash_algo: Option<u32>,
) -> Result<()> {
    unimplemented!(
        "verify_cert_chain_with_options requires a crypto backend feature (e.g. ring-backend)"
    )
}

/// Validates a DER certificate chain with a specific crypto backend and
/// optional SPDM algorithm enforcement.
///
/// This is the core chain validation function.  It:
/// 1. Parses individual certificates from the concatenated DER chain
/// 2. Reverses the SPDM root→leaf order to leaf→root for X.509 validation
/// 3. Validates the chain with the standard X.509 validator
/// 4. Validates SPDM EKU on the leaf certificate
/// 5. Optionally validates the leaf's algorithms against negotiated SPDM params
///
/// # Arguments
/// * `cert_chain` - Buffer containing concatenated DER certificates
/// * `backend`    - Crypto backend for signature verification
/// * `base_asym_algo` - Optional negotiated SPDM base asymmetric algorithm (bitfield)
/// * `base_hash_algo` - Optional negotiated SPDM base hash algorithm (bitfield)
pub fn verify_cert_chain_with_backend<B: CryptoBackend>(
    cert_chain: &[u8],
    backend: B,
    base_asym_algo: Option<u32>,
    base_hash_algo: Option<u32>,
) -> Result<()> {
    log::trace!("verify_cert_chain: chain_len={}", cert_chain.len());

    // Parse all certificates from the chain
    let mut certificates = Vec::new();
    let mut cert_index = 0isize;

    while let Ok((start, end)) = get_cert_from_cert_chain(cert_chain, cert_index) {
        log::trace!(
            "verify_cert_chain: parsed cert {} at [{}, {})",
            cert_index,
            start,
            end
        );
        let cert_der = &cert_chain[start..end];
        let cert = Certificate::from_der(cert_der)?;
        log::trace!(
            "verify_cert_chain: cert {} subject={:?}",
            cert_index,
            cert.tbs_certificate.subject
        );
        log::trace!(
            "verify_cert_chain: cert {} issuer={:?}",
            cert_index,
            cert.tbs_certificate.issuer
        );
        certificates.push(cert);
        cert_index += 1;

        if cert_index > 100 {
            log::error!("verify_cert_chain: chain too long (>100)");
            return Err(Error::ValidationError(
                "Certificate chain too long (>100 certificates)".into(),
            ));
        }
    }

    if certificates.is_empty() {
        log::error!("verify_cert_chain: empty chain");
        return Err(Error::ChainError(ChainError::EmptyChain));
    }

    log::trace!(
        "verify_cert_chain: parsed {} certificates, building chain",
        certificates.len()
    );

    // IMPORTANT: SPDM certificate chains are ordered root -> intermediate -> leaf
    // but the X.509 validator expects leaf -> intermediate -> root
    // So we must reverse the chain before validation
    certificates.reverse();
    log::trace!("verify_cert_chain: reversed chain for validation (leaf -> root)");

    // Build certificate chain
    let chain = CertificateChain::new(certificates);

    // Use SPDM validator with EKU validation
    let spdm_validator = SpdmValidator::with_backend(backend);

    let options = if crate::time::current_time().is_ok() {
        ValidationOptions::default()
    } else {
        ValidationOptions::default().skip_time_validation()
    };

    // First, perform standard X.509 chain validation
    // (re-use the validator's inner backend reference is not possible since
    //  Validator is not exposed from SpdmValidator; create a fresh one via
    //  the chain's own Validator::with_backend — but SpdmValidator already
    //  holds one, so we delegate through it where possible.)
    //  For chain validation we need Validator directly.
    //  Since `backend` was moved into spdm_validator, we access the inner
    //  validator through a helper.
    spdm_validator.validate_chain(&chain, &options)?;

    log::trace!("verify_cert_chain: validating leaf certificate EKU (Responder role)");

    // Then, validate SPDM EKU on the leaf certificate (first in reversed chain)
    // The leaf certificate is a Responder certificate in SPDM protocol
    if !chain.is_empty() {
        match spdm_validator
            .validate_spdm_eku(&chain.certificates[0], SpdmCertificateRole::Responder)
        {
            Ok(_) => {
                log::trace!("verify_cert_chain: SPDM EKU validation successful");
            }
            Err(e) => {
                log::error!("verify_cert_chain: SPDM EKU validation failed: {:?}", e);
                return Err(e);
            }
        }
    }

    // If SPDM algorithm parameters are provided, validate the leaf certificate's
    // signature algorithm and public key algorithm against the negotiated values.
    if let (Some(asym_algo), Some(hash_algo)) = (base_asym_algo, base_hash_algo) {
        if let Some(leaf) = chain.certificates.first() {
            use super::oids;
            use super::signature::{
                verify_ecc_curve, verify_rsa_key_size, verify_signature_algorithm,
            };

            log::trace!(
                "verify_cert_chain: validating leaf algorithms against negotiated SPDM params"
            );

            // Verify signature algorithm family + hash
            verify_signature_algorithm(&leaf.signature_algorithm.oid, asym_algo, hash_algo)?;

            // Verify public key algorithm / key size
            let pk_algo_oid = &leaf.tbs_certificate.subject_public_key_info.algorithm.oid;
            if pk_algo_oid == &oids::RSA {
                let pk_der = leaf
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .map_err(|e| {
                        Error::ValidationError(alloc::format!(
                            "Failed to encode public key: {:?}",
                            e
                        ))
                    })?;
                verify_rsa_key_size(&pk_der, asym_algo)?;
            } else if let Some(params) = &leaf
                .tbs_certificate
                .subject_public_key_info
                .algorithm
                .parameters
            {
                if let Ok(curve_oid) =
                    <const_oid::ObjectIdentifier as der::Decode>::from_der(params.value())
                {
                    verify_ecc_curve(&curve_oid, asym_algo)?;
                }
            }

            log::trace!("verify_cert_chain: leaf algorithm validation successful");
        }
    }

    log::trace!("verify_cert_chain: validation successful");
    Ok(())
}

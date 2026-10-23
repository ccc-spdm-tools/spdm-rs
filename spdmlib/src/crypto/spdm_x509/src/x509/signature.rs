// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! SPDM Algorithm Verification
//!
//! This module implements algorithm verification according to DSP0274 SPDM specification.
//! It verifies that the leaf public key matches the negotiated authentication
//! algorithm. Issuer certificate signatures are verified independently.
//!
//! # SPDM Algorithm Negotiation
//! During SPDM session establishment, Requester and Responder negotiate:
//! - Base asymmetric algorithm (signature algorithm)
//! - Base hash algorithm
//! - Optional post-quantum asymmetric algorithm
//!
//! # Certificate Requirements
//! - The certificate's public key algorithm MUST match the negotiated base_asym_algo
//! - RSA keys must be 2048, 3072, or 4096 bits
//! - ECC keys must use P-256, P-384, or P-521 curves
//!
//! # References
//! - DSP0274 1.2 Section 10.4 and 10.6.1
//! - DSP0274 1.4 Section 10.7 and 10.32.1

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use const_oid::ObjectIdentifier;

use super::oids;
use crate::error::{AlgorithmError, Error, Result};

// =============================================================================
// SPDM Base Asymmetric Algorithm (DSP0274 Table 21)
// =============================================================================

/// SPDM Base Asymmetric Algorithm flags
///
/// These correspond to the `BaseAsymAlgo` field in SPDM ALGORITHMS response (DSP0274 Table 21).
/// Multiple algorithms can be supported using bitwise OR.
///
/// # DSP0274 Requirements
/// - The certificate's public key algorithm MUST match the negotiated base_asym_algo
/// - RSA keys must be 2048, 3072, or 4096 bits
/// - ECC keys must use NIST P-256, P-384, or P-521 curves
///
/// # Example
/// ```no_run
/// use spdm_x509::x509::SpdmBaseAsymAlgo;
///
/// // Multiple algorithms can be OR'd together
/// let algos = (1 << 4) | (1 << 2); // ECDSA P-256 + RSA-3072
/// let parsed = SpdmBaseAsymAlgo::from_bits(algos);
/// assert_eq!(parsed.len(), 2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SpdmBaseAsymAlgo {
    /// TPM_ALG_RSASSA_2048 (bit 0)
    RsaSsa2048 = 1 << 0,
    /// TPM_ALG_RSAPSS_2048 (bit 1)
    RsaPss2048 = 1 << 1,
    /// TPM_ALG_RSASSA_3072 (bit 2)
    RsaSsa3072 = 1 << 2,
    /// TPM_ALG_RSAPSS_3072 (bit 3)
    RsaPss3072 = 1 << 3,
    /// TPM_ALG_ECDSA_ECC_NIST_P256 (bit 4)
    EcdsaP256 = 1 << 4,
    /// TPM_ALG_RSASSA_4096 (bit 5)
    RsaSsa4096 = 1 << 5,
    /// TPM_ALG_RSAPSS_4096 (bit 6)
    RsaPss4096 = 1 << 6,
    /// TPM_ALG_ECDSA_ECC_NIST_P384 (bit 7)
    EcdsaP384 = 1 << 7,
    /// TPM_ALG_ECDSA_ECC_NIST_P521 (bit 8)
    EcdsaP521 = 1 << 8,
    /// TPM_ALG_SM2_ECC_SM2_P256 (bit 9)
    Sm2P256 = 1 << 9,
    /// EDDSA_ED25519 (bit 10)
    Ed25519 = 1 << 10,
    /// EDDSA_ED448 (bit 11)
    Ed448 = 1 << 11,
}

impl SpdmBaseAsymAlgo {
    /// Convert from u32 bitfield to algorithm enum
    ///
    /// # Arguments
    /// * `bits` - The bitfield representing supported algorithms from SPDM ALGORITHMS response
    ///
    /// # Returns
    /// A vector of all algorithms represented in the bitfield
    ///
    /// # Example
    /// ```no_run
    /// use spdm_x509::x509::SpdmBaseAsymAlgo;
    /// let algos = SpdmBaseAsymAlgo::from_bits(0b10010); // bits 1 and 4 set
    /// // Returns [RsaPss2048, EcdsaP256]
    /// ```
    pub fn from_bits(bits: u32) -> Vec<Self> {
        let mut algos = Vec::new();

        if bits & (1 << 0) != 0 {
            algos.push(Self::RsaSsa2048);
        }
        if bits & (1 << 1) != 0 {
            algos.push(Self::RsaPss2048);
        }
        if bits & (1 << 2) != 0 {
            algos.push(Self::RsaSsa3072);
        }
        if bits & (1 << 3) != 0 {
            algos.push(Self::RsaPss3072);
        }
        if bits & (1 << 4) != 0 {
            algos.push(Self::EcdsaP256);
        }
        if bits & (1 << 5) != 0 {
            algos.push(Self::RsaSsa4096);
        }
        if bits & (1 << 6) != 0 {
            algos.push(Self::RsaPss4096);
        }
        if bits & (1 << 7) != 0 {
            algos.push(Self::EcdsaP384);
        }
        if bits & (1 << 8) != 0 {
            algos.push(Self::EcdsaP521);
        }
        if bits & (1 << 9) != 0 {
            algos.push(Self::Sm2P256);
        }
        if bits & (1 << 10) != 0 {
            algos.push(Self::Ed25519);
        }
        if bits & (1 << 11) != 0 {
            algos.push(Self::Ed448);
        }

        algos
    }

    /// Get the key size in bits for RSA algorithms
    ///
    /// # Returns
    /// * `Some(size)` - The key size in bits (2048, 3072, or 4096) for RSA algorithms
    /// * `None` - If this is not an RSA algorithm
    ///
    /// # Example
    /// ```no_run
    /// use spdm_x509::x509::SpdmBaseAsymAlgo;
    /// assert_eq!(SpdmBaseAsymAlgo::RsaSsa3072.rsa_key_size(), Some(3072));
    /// assert_eq!(SpdmBaseAsymAlgo::EcdsaP256.rsa_key_size(), None);
    /// ```
    pub fn rsa_key_size(&self) -> Option<usize> {
        match self {
            Self::RsaSsa2048 | Self::RsaPss2048 => Some(2048),
            Self::RsaSsa3072 | Self::RsaPss3072 => Some(3072),
            Self::RsaSsa4096 | Self::RsaPss4096 => Some(4096),
            _ => None,
        }
    }

    /// Get the curve OID for ECC algorithms
    ///
    /// # Returns
    /// * `Some(oid)` - The curve OID for ECC algorithms (P-256, P-384, or P-521)
    /// * `None` - If this is not an ECC algorithm
    ///
    /// # Example
    /// ```no_run
    /// use spdm_x509::x509::{oids, SpdmBaseAsymAlgo};
    /// assert_eq!(SpdmBaseAsymAlgo::EcdsaP256.ecc_curve_oid(), Some(oids::ECDSA_P256));
    /// assert_eq!(SpdmBaseAsymAlgo::RsaSsa2048.ecc_curve_oid(), None);
    /// ```
    pub fn ecc_curve_oid(&self) -> Option<ObjectIdentifier> {
        match self {
            Self::EcdsaP256 => Some(oids::ECDSA_P256),
            Self::EcdsaP384 => Some(oids::ECDSA_P384),
            Self::EcdsaP521 => Some(oids::ECDSA_P521),
            _ => None,
        }
    }

    /// Check if this is an RSA algorithm
    ///
    /// # Returns
    /// `true` if this represents any RSA variant (RSASSA or RSAPSS), `false` otherwise
    pub fn is_rsa(&self) -> bool {
        matches!(
            self,
            Self::RsaSsa2048
                | Self::RsaPss2048
                | Self::RsaSsa3072
                | Self::RsaPss3072
                | Self::RsaSsa4096
                | Self::RsaPss4096
        )
    }

    /// Check if this is an ECC algorithm
    ///
    /// # Returns
    /// `true` if this represents any ECC algorithm (ECDSA P-256/384/521, SM2), `false` otherwise
    pub fn is_ecc(&self) -> bool {
        matches!(
            self,
            Self::EcdsaP256 | Self::EcdsaP384 | Self::EcdsaP521 | Self::Sm2P256
        )
    }

    /// Check if this is an EdDSA algorithm
    ///
    /// # Returns
    /// `true` if this represents an EdDSA algorithm (Ed25519 or Ed448), `false` otherwise
    pub fn is_eddsa(&self) -> bool {
        matches!(self, Self::Ed25519 | Self::Ed448)
    }
}

// =============================================================================
// SPDM Base Hash Algorithm (DSP0274 Table 22)
// =============================================================================

/// SPDM Base Hash Algorithm flags
///
/// These correspond to the `BaseHashAlgo` field in SPDM ALGORITHMS response (DSP0274 Table 22).
///
/// # DSP0274 Requirements
/// - The selected hash applies to SPDM transcripts, not issuer certificate signatures
/// - Hash size determines the root certificate hash size in SPDM certificate chains
///
/// # Example
/// ```no_run
/// use spdm_x509::x509::SpdmBaseHashAlgo;
///
/// let algos = (1 << 0); // SHA-256
/// let parsed = SpdmBaseHashAlgo::from_bits(algos);
/// assert_eq!(parsed[0].oid().to_string(), "2.16.840.1.101.3.4.2.1");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SpdmBaseHashAlgo {
    /// TPM_ALG_SHA_256 (bit 0)
    Sha256 = 1 << 0,
    /// TPM_ALG_SHA_384 (bit 1)
    Sha384 = 1 << 1,
    /// TPM_ALG_SHA_512 (bit 2)
    Sha512 = 1 << 2,
    /// TPM_ALG_SHA3_256 (bit 3)
    Sha3_256 = 1 << 3,
    /// TPM_ALG_SHA3_384 (bit 4)
    Sha3_384 = 1 << 4,
    /// TPM_ALG_SHA3_512 (bit 5)
    Sha3_512 = 1 << 5,
    /// TPM_ALG_SM3_256 (bit 6)
    Sm3_256 = 1 << 6,
}

impl SpdmBaseHashAlgo {
    /// Convert from u32 bitfield to algorithm enum
    ///
    /// # Arguments
    /// * `bits` - The bitfield representing supported hash algorithms from SPDM ALGORITHMS response
    ///
    /// # Returns
    /// A vector of all hash algorithms represented in the bitfield
    ///
    /// # Example
    /// ```no_run
    /// use spdm_x509::x509::SpdmBaseHashAlgo;
    /// let algos = SpdmBaseHashAlgo::from_bits(0b11); // bits 0 and 1 set
    /// // Returns [Sha256, Sha384]
    /// ```
    pub fn from_bits(bits: u32) -> Vec<Self> {
        let mut algos = Vec::new();

        if bits & (1 << 0) != 0 {
            algos.push(Self::Sha256);
        }
        if bits & (1 << 1) != 0 {
            algos.push(Self::Sha384);
        }
        if bits & (1 << 2) != 0 {
            algos.push(Self::Sha512);
        }
        if bits & (1 << 3) != 0 {
            algos.push(Self::Sha3_256);
        }
        if bits & (1 << 4) != 0 {
            algos.push(Self::Sha3_384);
        }
        if bits & (1 << 5) != 0 {
            algos.push(Self::Sha3_512);
        }
        if bits & (1 << 6) != 0 {
            algos.push(Self::Sm3_256);
        }

        algos
    }

    /// Get the hash algorithm OID
    ///
    /// # Returns
    /// The OID representing this hash algorithm
    ///
    /// # Example
    /// ```no_run
    /// use spdm_x509::x509::{oids, SpdmBaseHashAlgo};
    /// assert_eq!(SpdmBaseHashAlgo::Sha256.oid(), oids::SHA256);
    /// ```
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            Self::Sha256 => oids::SHA256,
            Self::Sha384 => oids::SHA384,
            Self::Sha512 => oids::SHA512,
            Self::Sha3_256 => oids::SHA3_256,
            Self::Sha3_384 => oids::SHA3_384,
            Self::Sha3_512 => oids::SHA3_512,
            Self::Sm3_256 => {
                // SM3-256 OID: 1.2.156.10197.1.401
                ObjectIdentifier::new_unwrap("1.2.156.10197.1.401")
            }
        }
    }
}

// =============================================================================
// Algorithm Verification Functions
// =============================================================================

/// Legacy OID family/hash policy helper.
///
/// This is not an SPDM certificate acceptance requirement: negotiated algorithms
/// describe the endpoint's authentication key, not the issuer's signature.
///
/// # Arguments
/// - `cert_sig_algo_oid`: The OID of the certificate's signature algorithm
/// - `base_asym_algo`: The negotiated SPDM base asymmetric algorithm (bitfield)
/// - `base_hash_algo`: The negotiated SPDM base hash algorithm (bitfield)
///
/// # Returns
/// - `Ok(())` if the signature algorithm is allowed
/// - `Err(AlgorithmError)` if the algorithm doesn't match
pub fn verify_signature_algorithm(
    cert_sig_algo_oid: &ObjectIdentifier,
    base_asym_algo: u32,
    base_hash_algo: u32,
) -> Result<()> {
    // Signature algorithm OID constants.  Grouped by hash component.
    //
    // SHA-256 family:
    const SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    // SHA-384 family:
    const SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
    const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
    // SHA-512 family:
    const SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
    const ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
    // RSA-PSS (hash is in parameters, not OID – accept if any hash is negotiated):
    const RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
    // EdDSA (hash is intrinsic – Ed25519 uses SHA-512, Ed448 uses SHAKE256):
    const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
    const ED448: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.113");

    let hash_algos = SpdmBaseHashAlgo::from_bits(base_hash_algo);
    let asym_algos = SpdmBaseAsymAlgo::from_bits(base_asym_algo);

    // Match the caller's OID policy, independently of endpoint-key validation.
    let is_rsa_sig = matches!(
        *cert_sig_algo_oid,
        SHA256_RSA | SHA384_RSA | SHA512_RSA | RSA_PSS
    );
    let is_ecdsa_sig = matches!(
        *cert_sig_algo_oid,
        ECDSA_SHA256 | ECDSA_SHA384 | ECDSA_SHA512
    );
    let is_ed25519_sig = *cert_sig_algo_oid == ED25519;
    let is_ed448_sig = *cert_sig_algo_oid == ED448;

    let asym_family_match = if is_rsa_sig {
        asym_algos.iter().any(|a| a.is_rsa())
    } else if is_ecdsa_sig {
        asym_algos.iter().any(|a| a.is_ecc())
    } else if is_ed25519_sig || is_ed448_sig {
        asym_algos.iter().any(|a| a.is_eddsa())
    } else {
        false
    };

    if !asym_family_match {
        return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::format!(
                "Signature algorithm family not in negotiated base_asym_algo: {}",
                cert_sig_algo_oid
            ),
        )));
    }

    // ── Step 2: Verify the hash component matches the negotiated
    //    base_hash_algo.
    let hash_match = match *cert_sig_algo_oid {
        // SHA-256 family
        SHA256_RSA | ECDSA_SHA256 => hash_algos
            .iter()
            .any(|h| matches!(h, SpdmBaseHashAlgo::Sha256)),
        // SHA-384 family
        SHA384_RSA | ECDSA_SHA384 => hash_algos
            .iter()
            .any(|h| matches!(h, SpdmBaseHashAlgo::Sha384)),
        // SHA-512 family
        SHA512_RSA | ECDSA_SHA512 => hash_algos
            .iter()
            .any(|h| matches!(h, SpdmBaseHashAlgo::Sha512)),
        // RSA-PSS: the hash is encoded in the algorithm parameters, not the OID
        // itself.  Accept as long as at least one hash algorithm is negotiated;
        // this OID-only helper cannot inspect those parameters.
        RSA_PSS => !hash_algos.is_empty(),
        // EdDSA: Ed25519 intrinsically uses SHA-512.
        ED25519 => hash_algos
            .iter()
            .any(|h| matches!(h, SpdmBaseHashAlgo::Sha512)),
        // Ed448: intrinsically uses SHAKE256 — accept unconditionally since
        // SPDM doesn't negotiate SHAKE family separately.
        ED448 => true,
        _ => false,
    };

    if !hash_match {
        return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::format!(
                "Signature hash algorithm not in negotiated algorithms: {}",
                cert_sig_algo_oid
            ),
        )));
    }

    Ok(())
}

/// Match a leaf SubjectPublicKeyInfo to exactly one selected authentication
/// algorithm. Classical and ML-DSA masks are separate because their bits overlap.
///
/// This checks key type, encoding, and negotiated size/curve, not signatures,
/// trust, or the mathematical validity of public-key material.
pub fn verify_public_key_algorithm(
    public_key: &crate::certificate::SubjectPublicKeyInfo,
    base_asym_algo: u32,
    pqc_asym_algo: u32,
) -> Result<()> {
    use der::{Encode, Tagged};

    let invalid =
        |message: &str| Error::AlgorithmError(AlgorithmError::InvalidParameters(message.into()));
    if base_asym_algo.count_ones() + pqc_asym_algo.count_ones() != 1 {
        return Err(invalid(
            "Expected exactly one selected authentication algorithm",
        ));
    }
    let key = public_key
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| invalid("Public key must be byte-aligned"))?;
    let oid = public_key.algorithm.oid;
    let parameters = &public_key.algorithm.parameters;
    let algorithms = SpdmBaseAsymAlgo::from_bits(base_asym_algo);
    if let Some(algorithm) = algorithms.first() {
        if algorithm.is_rsa() {
            if oid != oids::RSA {
                return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
                    "Selected RSA algorithm requires an RSA public key".into(),
                )));
            }
            if parameters
                .as_ref()
                .is_some_and(|p| p.tag() != der::Tag::Null || !p.value().is_empty())
            {
                return Err(invalid("Invalid rsaEncryption parameters"));
            }
            let encoded = public_key.to_der()?;
            return verify_rsa_key_size(&encoded, base_asym_algo);
        }
        if let Some(curve) = algorithm.ecc_curve_oid() {
            if oid != oids::ECPUBLICKEY {
                return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
                    "Selected ECDSA algorithm requires an EC public key".into(),
                )));
            }
            let actual_curve = parameters
                .as_ref()
                .ok_or(Error::AlgorithmError(AlgorithmError::MissingParameters))?
                .decode_as::<ObjectIdentifier>()
                .map_err(|_| invalid("EC parameters must contain a named-curve OID"))?;
            verify_ecc_curve(&actual_curve, base_asym_algo)?;
            let coordinate_size = match curve {
                oids::ECDSA_P256 => 32,
                oids::ECDSA_P384 => 48,
                oids::ECDSA_P521 => 66,
                _ => return Err(invalid("Unsupported EC curve")),
            };
            let valid_point_encoding = match key.first() {
                Some(4) => key.len() == 1 + 2 * coordinate_size,
                Some(2 | 3) => key.len() == 1 + coordinate_size,
                _ => false,
            };
            return if valid_point_encoding {
                Ok(())
            } else {
                Err(invalid("Invalid EC point encoding or length"))
            };
        }
    }

    let (expected_oid, expected_size) = match (base_asym_algo, pqc_asym_algo) {
        (a, 0) if a == SpdmBaseAsymAlgo::Ed25519 as u32 => (oids::ED25519, 32),
        (a, 0) if a == SpdmBaseAsymAlgo::Ed448 as u32 => (oids::ED448, 57),
        (0, 1) => (oids::ML_DSA_44, 1312),
        (0, 2) => (oids::ML_DSA_65, 1952),
        (0, 4) => (oids::ML_DSA_87, 2592),
        _ => {
            return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
                "Unsupported selected authentication algorithm".into(),
            )))
        }
    };
    if oid != expected_oid {
        return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::format!(
                "Public key {} does not match selected {}",
                oid,
                expected_oid
            ),
        )));
    }
    if parameters.is_some() {
        return Err(invalid("EdDSA and ML-DSA parameters must be absent"));
    }
    if key.len() != expected_size {
        return Err(invalid("Incorrect public key length"));
    }
    Ok(())
}

/// Verify that an RSA public key has an allowed key size (2048, 3072, or 4096 bits)
///
/// # Arguments
/// - `public_key_der`: The DER-encoded RSA public key (SubjectPublicKeyInfo)
/// - `base_asym_algo`: The negotiated SPDM base asymmetric algorithm (bitfield)
///
/// # Returns
/// - `Ok(())` if the key size is valid
/// - `Err(AlgorithmError)` if the key size is invalid or not supported
pub fn verify_rsa_key_size(public_key_der: &[u8], base_asym_algo: u32) -> Result<()> {
    // Parse the RSA public key to get the modulus size
    // RSA public key format in DER:
    // SubjectPublicKeyInfo:
    //   algorithm: rsaEncryption
    //   subjectPublicKey: BIT STRING containing RSAPublicKey
    //     RSAPublicKey ::= SEQUENCE {
    //       modulus INTEGER,
    //       publicExponent INTEGER
    //     }

    // Extract supported RSA key sizes from base_asym_algo
    let asym_algos = SpdmBaseAsymAlgo::from_bits(base_asym_algo);
    let supported_sizes: Vec<usize> = asym_algos.iter().filter_map(|a| a.rsa_key_size()).collect();

    if supported_sizes.is_empty() {
        return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::string::String::from("No RSA algorithms in negotiated base_asym_algo"),
        )));
    }

    // Parse SubjectPublicKeyInfo via the `der` crate to extract the RSA modulus size.
    let key_size_bits = estimate_rsa_key_size(public_key_der)?;

    if !supported_sizes.contains(&key_size_bits) {
        return Err(Error::KeyError(crate::error::KeyError::WeakKey {
            algorithm: "RSA".to_string(),
            bits: key_size_bits,
        }));
    }

    Ok(())
}

/// Compute RSA key size from DER-encoded SubjectPublicKeyInfo.
///
/// Uses proper DER decoding via the `der` crate to parse the
/// RSAPublicKey SEQUENCE and extract the modulus INTEGER, avoiding
/// fragile hand-rolled byte parsing.
fn estimate_rsa_key_size(spki_der: &[u8]) -> Result<usize> {
    use der::{asn1::UintRef, Decode, Reader, SliceReader};
    use spki::SubjectPublicKeyInfo;

    // 1. Parse the outer SubjectPublicKeyInfo to get the BIT STRING payload.
    let spki = SubjectPublicKeyInfo::<der::Any, der::asn1::BitString>::from_der(spki_der).map_err(
        |e| {
            Error::AlgorithmError(AlgorithmError::Unsupported(alloc::format!(
                "Failed to parse RSA SubjectPublicKeyInfo: {:?}",
                e
            )))
        },
    )?;

    let key_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
        Error::AlgorithmError(AlgorithmError::InvalidParameters(
            "RSA public key must be byte-aligned".into(),
        ))
    })?;

    // 2. Parse RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    //    using the der crate's SliceReader so every length check is handled
    //    by the library rather than manual index arithmetic.
    let mut reader = SliceReader::new(key_bytes).map_err(|e| {
        Error::AlgorithmError(AlgorithmError::Unsupported(alloc::format!(
            "Invalid RSAPublicKey encoding: {:?}",
            e
        )))
    })?;

    // Read the outer SEQUENCE
    let seq_header = der::Header::decode(&mut reader).map_err(|e| {
        Error::AlgorithmError(AlgorithmError::Unsupported(alloc::format!(
            "Invalid RSAPublicKey SEQUENCE header: {:?}",
            e
        )))
    })?;

    if seq_header.tag != der::Tag::Sequence {
        return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::string::String::from("Expected SEQUENCE for RSAPublicKey"),
        )));
    }

    // Read the modulus INTEGER inside the SEQUENCE, consuming the exponent
    // as well so that `read_nested` does not report TrailingData.
    let modulus = reader
        .read_nested(seq_header.length, |seq_reader| {
            let m = UintRef::decode(seq_reader)?;
            // Consume the publicExponent INTEGER.
            let _exponent = UintRef::decode(seq_reader)?;
            Ok(m)
        })
        .map_err(|e| {
            Error::AlgorithmError(AlgorithmError::Unsupported(alloc::format!(
                "Failed to parse RSA modulus: {:?}",
                e
            )))
        })?;

    if !reader.is_finished() {
        return Err(Error::AlgorithmError(AlgorithmError::InvalidParameters(
            "Trailing data after RSAPublicKey".into(),
        )));
    }
    let magnitude = modulus.as_bytes();
    let key_size_bits = magnitude.first().map_or(0, |byte| {
        magnitude.len() * 8 - byte.leading_zeros() as usize
    });

    if key_size_bits < 2048 {
        return Err(Error::KeyError(crate::error::KeyError::WeakKey {
            algorithm: "RSA".to_string(),
            bits: key_size_bits,
        }));
    }

    Ok(key_size_bits)
}

/// Verify that an ECC public key uses an allowed curve (P-256, P-384, or P-521)
///
/// # Arguments
/// - `curve_oid`: The OID of the elliptic curve
/// - `base_asym_algo`: The negotiated SPDM base asymmetric algorithm (bitfield)
///
/// # Returns
/// - `Ok(())` if the curve is valid
/// - `Err(AlgorithmError)` if the curve is not supported
pub fn verify_ecc_curve(curve_oid: &ObjectIdentifier, base_asym_algo: u32) -> Result<()> {
    let asym_algos = SpdmBaseAsymAlgo::from_bits(base_asym_algo);

    // Check if the curve is in the supported list
    let curve_supported = asym_algos.iter().any(|algo| {
        if let Some(algo_curve) = algo.ecc_curve_oid() {
            &algo_curve == curve_oid
        } else {
            false
        }
    });

    if !curve_supported {
        return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::format!("ECC curve not in negotiated algorithms: {}", curve_oid),
        )));
    }

    Ok(())
}

/// Verify that a hash algorithm OID is in the negotiated SPDM hash algorithms
///
/// # Arguments
/// - `hash_oid`: The hash algorithm OID
/// - `base_hash_algo`: The negotiated SPDM base hash algorithm (bitfield)
///
/// # Returns
/// - `Ok(())` if the hash algorithm is supported
/// - `Err(AlgorithmError)` if the hash algorithm is not supported
pub fn verify_hash_algorithm(hash_oid: &ObjectIdentifier, base_hash_algo: u32) -> Result<()> {
    let hash_algos = SpdmBaseHashAlgo::from_bits(base_hash_algo);

    let hash_supported = hash_algos.iter().any(|algo| &algo.oid() == hash_oid);

    if !hash_supported {
        return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::format!("Hash algorithm not in negotiated algorithms: {}", hash_oid),
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use der::{Decode, Encode};

    fn public_key(directory: &str) -> crate::certificate::SubjectPublicKeyInfo {
        let bytes = std::fs::read(alloc::format!(
            "{}/../../../../test_key/{}/end_responder.cert.der",
            env!("CARGO_MANIFEST_DIR"),
            directory
        ))
        .unwrap();
        crate::Certificate::from_der(&bytes)
            .unwrap()
            .tbs_certificate
            .subject_public_key_info
    }

    #[test]
    fn test_public_key_selected_algorithm_matrix() {
        use SpdmBaseAsymAlgo::*;
        let cases = [
            ("rsa2048", RsaSsa2048 as u32, 0),
            ("rsa3072", RsaSsa3072 as u32, 0),
            ("rsa4096", RsaSsa4096 as u32, 0),
            ("ecp256", EcdsaP256 as u32, 0),
            ("ecp384", EcdsaP384 as u32, 0),
            ("ecp521", EcdsaP521 as u32, 0),
            ("ed25519", Ed25519 as u32, 0),
            ("ed448", Ed448 as u32, 0),
            ("mldsa44", 0, 1),
            ("mldsa65", 0, 2),
            ("mldsa87", 0, 4),
        ];
        for (key_index, (directory, _, _)) in cases.iter().enumerate() {
            let key = public_key(directory);
            for (selection_index, (_, asym, pqc)) in cases.iter().enumerate() {
                let result = verify_public_key_algorithm(&key, *asym, *pqc);
                if key_index == selection_index {
                    result.unwrap();
                } else {
                    assert!(
                        matches!(
                            result,
                            Err(Error::AlgorithmError(AlgorithmError::Unsupported(_)))
                                | Err(Error::KeyError(crate::error::KeyError::WeakKey { .. }))
                        ),
                        "{} versus ({}, {}): {:?}",
                        directory,
                        asym,
                        pqc,
                        result
                    );
                }
            }
        }
        for (directory, algorithm) in [
            ("rsa2048", RsaPss2048),
            ("rsa3072", RsaPss3072),
            ("rsa4096", RsaPss4096),
        ] {
            verify_public_key_algorithm(&public_key(directory), algorithm as u32, 0).unwrap();
        }
    }

    #[test]
    fn test_public_key_invalid_algorithm_selections() {
        let key = public_key("ecp256");
        for (asym, pqc) in [(0, 0), (0x90, 0), (0x10, 1), (0, 3)] {
            assert!(matches!(
                verify_public_key_algorithm(&key, asym, pqc),
                Err(Error::AlgorithmError(AlgorithmError::InvalidParameters(_)))
            ));
        }
        for (asym, pqc) in [(1 << 31, 0), (0, 1 << 31), (1 << 9, 0)] {
            assert!(matches!(
                verify_public_key_algorithm(&key, asym, pqc),
                Err(Error::AlgorithmError(AlgorithmError::Unsupported(_)))
            ));
        }
    }

    #[test]
    fn test_public_key_ec_parameters_and_point_encoding() {
        let key = public_key("ecp256");
        let mut modified = key.clone();
        modified.algorithm.parameters = None;
        assert!(matches!(
            verify_public_key_algorithm(&modified, 1 << 4, 0),
            Err(Error::AlgorithmError(AlgorithmError::MissingParameters))
        ));
        for parameters in [
            der::Any::from_der(&[5, 0]).unwrap(),
            der::Any::new(der::Tag::ObjectIdentifier, alloc::vec![0x80]).unwrap(),
        ] {
            modified.algorithm.parameters = Some(parameters);
            assert!(matches!(
                verify_public_key_algorithm(&modified, 1 << 4, 0),
                Err(Error::AlgorithmError(AlgorithmError::InvalidParameters(_)))
            ));
        }
        modified.algorithm.parameters =
            Some(der::Any::from_der(&oids::ECDSA_P384.to_der().unwrap()).unwrap());
        assert!(matches!(
            verify_public_key_algorithm(&modified, 1 << 4, 0),
            Err(Error::AlgorithmError(AlgorithmError::Unsupported(_)))
        ));
        modified = key.clone();
        modified.algorithm.oid = ObjectIdentifier::new_unwrap("1.2.3.4");
        assert!(matches!(
            verify_public_key_algorithm(&modified, 1 << 4, 0),
            Err(Error::AlgorithmError(AlgorithmError::Unsupported(_)))
        ));
        for bytes in [alloc::vec![], alloc::vec![4; 64], alloc::vec![0; 65]] {
            modified = key.clone();
            modified.subject_public_key = der::asn1::BitString::from_bytes(&bytes).unwrap();
            assert!(matches!(
                verify_public_key_algorithm(&modified, 1 << 4, 0),
                Err(Error::AlgorithmError(AlgorithmError::InvalidParameters(_)))
            ));
        }
        modified = key.clone();
        modified.subject_public_key = der::asn1::BitString::new(1, alloc::vec![0; 65]).unwrap();
        assert!(matches!(
            verify_public_key_algorithm(&modified, 1 << 4, 0),
            Err(Error::AlgorithmError(AlgorithmError::InvalidParameters(_)))
        ));
        let mut compressed = alloc::vec![2];
        compressed.extend_from_slice(&key.subject_public_key.raw_bytes()[1..33]);
        modified.subject_public_key = der::asn1::BitString::from_bytes(&compressed).unwrap();
        verify_public_key_algorithm(&modified, 1 << 4, 0).unwrap();
    }

    #[test]
    fn test_public_key_parameterless_algorithms_require_exact_encoding() {
        for (directory, asym, pqc) in [
            ("ed25519", 1 << 10, 0),
            ("ed448", 1 << 11, 0),
            ("mldsa44", 0, 1),
            ("mldsa65", 0, 2),
            ("mldsa87", 0, 4),
        ] {
            let key = public_key(directory);
            let mut modified = key.clone();
            modified.algorithm.parameters = Some(der::Any::from_der(&[5, 0]).unwrap());
            assert!(matches!(
                verify_public_key_algorithm(&modified, asym, pqc),
                Err(Error::AlgorithmError(AlgorithmError::InvalidParameters(_)))
            ));
            modified = key;
            let mut bytes = modified.subject_public_key.raw_bytes().to_vec();
            bytes.pop();
            modified.subject_public_key = der::asn1::BitString::from_bytes(&bytes).unwrap();
            assert!(matches!(
                verify_public_key_algorithm(&modified, asym, pqc),
                Err(Error::AlgorithmError(AlgorithmError::InvalidParameters(_)))
            ));
        }
    }

    #[test]
    fn test_public_key_rsa_exact_modulus_bits_and_der_boundaries() {
        #[derive(der::Sequence)]
        struct RsaPublicKey<'a> {
            modulus: der::asn1::UintRef<'a>,
            exponent: der::asn1::UintRef<'a>,
        }

        let original = public_key("rsa2048");
        for (first, expected_bits) in [(0x80, 2048), (0x01, 2041), (0, 2040)] {
            let mut modulus = alloc::vec![0xff; 256];
            modulus[0] = first;
            let encoded = RsaPublicKey {
                modulus: der::asn1::UintRef::new(&modulus).unwrap(),
                exponent: der::asn1::UintRef::new(&[1, 0, 1]).unwrap(),
            }
            .to_der()
            .unwrap();
            let mut key = original.clone();
            key.subject_public_key = der::asn1::BitString::from_bytes(&encoded).unwrap();
            let result = verify_public_key_algorithm(&key, 1, 0);
            if expected_bits == 2048 {
                result.unwrap();
            } else {
                assert!(matches!(
                    result,
                    Err(Error::KeyError(crate::error::KeyError::WeakKey { bits, .. }))
                        if bits == expected_bits
                ));
            }
        }
        let mut key = original;
        key.subject_public_key =
            der::asn1::BitString::from_bytes(&[0x30, 6, 2, 1, 0, 2, 1, 3]).unwrap();
        assert!(matches!(
            verify_public_key_algorithm(&key, 1, 0),
            Err(Error::KeyError(crate::error::KeyError::WeakKey {
                bits: 0,
                ..
            }))
        ));
        let mut bytes = key.subject_public_key.raw_bytes().to_vec();
        bytes.push(0);
        key.subject_public_key = der::asn1::BitString::from_bytes(&bytes).unwrap();
        assert!(matches!(
            verify_public_key_algorithm(&key, 1, 0),
            Err(Error::AlgorithmError(AlgorithmError::InvalidParameters(_)))
        ));
        key = public_key("rsa2048");
        key.algorithm.parameters =
            Some(der::Any::from_der(&oids::ECDSA_P256.to_der().unwrap()).unwrap());
        assert!(matches!(
            verify_public_key_algorithm(&key, 1, 0),
            Err(Error::AlgorithmError(AlgorithmError::InvalidParameters(_)))
        ));
    }

    #[test]
    fn test_spdm_base_asym_algo_from_bits() {
        let bits = (1 << 0) | (1 << 4); // RSA-2048 + ECDSA-P256
        let algos = SpdmBaseAsymAlgo::from_bits(bits);
        assert_eq!(algos.len(), 2);
        assert!(algos.contains(&SpdmBaseAsymAlgo::RsaSsa2048));
        assert!(algos.contains(&SpdmBaseAsymAlgo::EcdsaP256));
    }

    #[test]
    fn test_rsa_key_size() {
        assert_eq!(SpdmBaseAsymAlgo::RsaSsa2048.rsa_key_size(), Some(2048));
        assert_eq!(SpdmBaseAsymAlgo::RsaSsa3072.rsa_key_size(), Some(3072));
        assert_eq!(SpdmBaseAsymAlgo::RsaSsa4096.rsa_key_size(), Some(4096));
        assert_eq!(SpdmBaseAsymAlgo::EcdsaP256.rsa_key_size(), None);
    }

    #[test]
    fn test_ecc_curve_oid() {
        assert_eq!(
            SpdmBaseAsymAlgo::EcdsaP256.ecc_curve_oid(),
            Some(oids::ECDSA_P256)
        );
        assert_eq!(
            SpdmBaseAsymAlgo::EcdsaP384.ecc_curve_oid(),
            Some(oids::ECDSA_P384)
        );
        assert_eq!(
            SpdmBaseAsymAlgo::EcdsaP521.ecc_curve_oid(),
            Some(oids::ECDSA_P521)
        );
        assert_eq!(SpdmBaseAsymAlgo::RsaSsa2048.ecc_curve_oid(), None);
    }

    #[test]
    fn test_hash_algo_oid() {
        assert_eq!(SpdmBaseHashAlgo::Sha256.oid(), oids::SHA256);
        assert_eq!(SpdmBaseHashAlgo::Sha384.oid(), oids::SHA384);
        assert_eq!(SpdmBaseHashAlgo::Sha512.oid(), oids::SHA512);
    }

    // ── verify_signature_algorithm: asymmetric family checks ──

    #[test]
    fn test_verify_sig_algo_rsa_accepted_when_rsa_negotiated() {
        let rsa_sha256 = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        let asym = 1u32 << 0; // RsaSsa2048
        let hash = 1u32 << 0; // SHA-256
        assert!(verify_signature_algorithm(&rsa_sha256, asym, hash).is_ok());
    }

    #[test]
    fn test_verify_sig_algo_rsa_rejected_when_only_ecdsa_negotiated() {
        let rsa_sha256 = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        let asym = 1u32 << 4; // EcdsaP256 only
        let hash = 1u32 << 0; // SHA-256
        assert!(verify_signature_algorithm(&rsa_sha256, asym, hash).is_err());
    }

    #[test]
    fn test_verify_sig_algo_ecdsa_rejected_when_only_rsa_negotiated() {
        let ecdsa_sha256 = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        let asym = 1u32 << 0; // RsaSsa2048 only
        let hash = 1u32 << 0; // SHA-256
        assert!(verify_signature_algorithm(&ecdsa_sha256, asym, hash).is_err());
    }

    #[test]
    fn test_verify_sig_algo_ecdsa_accepted_when_ecdsa_negotiated() {
        let ecdsa_sha384 = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
        let asym = 1u32 << 7; // EcdsaP384 (bit 7)
        let hash = 1u32 << 1; // SHA-384
        assert!(verify_signature_algorithm(&ecdsa_sha384, asym, hash).is_ok());
    }

    // ── verify_signature_algorithm: hash checks ──

    #[test]
    fn test_verify_sig_algo_hash_mismatch_rejected() {
        let rsa_sha256 = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        let asym = 1u32 << 0; // RsaSsa2048
        let hash = 1u32 << 1; // SHA-384 only (no SHA-256)
        assert!(verify_signature_algorithm(&rsa_sha256, asym, hash).is_err());
    }

    #[test]
    fn test_verify_sig_algo_rsa_pss_accepted_with_any_hash() {
        let rsa_pss = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
        let asym = 1u32 << 3; // RsaPss2048
        let hash = 1u32 << 1; // SHA-384
        assert!(verify_signature_algorithm(&rsa_pss, asym, hash).is_ok());
    }

    #[test]
    fn test_verify_sig_algo_ed25519_requires_sha512() {
        let ed25519 = ObjectIdentifier::new_unwrap("1.3.101.112");
        let asym = 1u32 << 10; // Ed25519 (bit 10)
                               // Ed25519 intrinsically uses SHA-512
        let hash_ok = 1u32 << 2; // SHA-512
        assert!(verify_signature_algorithm(&ed25519, asym, hash_ok).is_ok());
        let hash_bad = 1u32 << 0; // SHA-256 only
        assert!(verify_signature_algorithm(&ed25519, asym, hash_bad).is_err());
    }

    #[test]
    fn test_verify_sig_algo_ed448_accepted_unconditionally() {
        let ed448 = ObjectIdentifier::new_unwrap("1.3.101.113");
        let asym = 1u32 << 11; // Ed448 (bit 11)
        let hash = 1u32 << 0; // SHA-256 (doesn't matter for Ed448)
        assert!(verify_signature_algorithm(&ed448, asym, hash).is_ok());
    }

    #[test]
    fn test_verify_sig_algo_unknown_oid_rejected() {
        let unknown = ObjectIdentifier::new_unwrap("1.2.3.4.5");
        let asym = 0xFFu32; // all bits set
        let hash = 0xFFu32;
        assert!(verify_signature_algorithm(&unknown, asym, hash).is_err());
    }

    // ── verify_signature_algorithm: multiple negotiated algorithms ──

    #[test]
    fn test_verify_sig_algo_multiple_asym_negotiated() {
        let rsa_sha256 = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        let asym = (1u32 << 0) | (1u32 << 4); // RsaSsa2048 + EcdsaP256
        let hash = 1u32 << 0; // SHA-256
                              // RSA sig should pass because RSA is in the negotiated set
        assert!(verify_signature_algorithm(&rsa_sha256, asym, hash).is_ok());
    }

    // ── verify_ecc_curve ──

    #[test]
    fn test_verify_ecc_curve_p256_accepted() {
        let curve = oids::ECDSA_P256;
        let asym = 1u32 << 4; // EcdsaP256
        assert!(verify_ecc_curve(&curve, asym).is_ok());
    }

    #[test]
    fn test_verify_ecc_curve_p384_accepted() {
        let curve = oids::ECDSA_P384;
        let asym = 1u32 << 7; // EcdsaP384 (bit 7)
        assert!(verify_ecc_curve(&curve, asym).is_ok());
    }

    #[test]
    fn test_verify_ecc_curve_p256_rejected_when_only_p384() {
        let curve = oids::ECDSA_P256;
        let asym = 1u32 << 7; // EcdsaP384 only (bit 7)
        assert!(verify_ecc_curve(&curve, asym).is_err());
    }

    #[test]
    fn test_verify_ecc_curve_rejected_when_only_rsa() {
        let curve = oids::ECDSA_P256;
        let asym = 1u32 << 0; // RsaSsa2048 only
        assert!(verify_ecc_curve(&curve, asym).is_err());
    }

    // ── verify_hash_algorithm ──

    #[test]
    fn test_verify_hash_algo_sha256_accepted() {
        let hash_oid = oids::SHA256;
        let hash = 1u32 << 0; // SHA-256
        assert!(verify_hash_algorithm(&hash_oid, hash).is_ok());
    }

    #[test]
    fn test_verify_hash_algo_sha256_rejected_when_only_sha384() {
        let hash_oid = oids::SHA256;
        let hash = 1u32 << 1; // SHA-384 only
        assert!(verify_hash_algorithm(&hash_oid, hash).is_err());
    }

    #[test]
    fn test_verify_hash_algo_sha384_accepted() {
        let hash_oid = oids::SHA384;
        let hash = 1u32 << 1; // SHA-384
        assert!(verify_hash_algorithm(&hash_oid, hash).is_ok());
    }

    // ── verify_rsa_key_size with real key ──

    #[test]
    fn test_verify_rsa_key_size_2048_with_real_key() {
        let pk_der = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/rsa2048/end_responder.key.pub.der"
        ))
        .expect("rsa2048 test key");
        let asym = 1u32 << 0; // RsaSsa2048
        assert!(verify_rsa_key_size(&pk_der, asym).is_ok());
    }

    #[test]
    fn test_verify_rsa_key_size_2048_rejected_when_only_3072() {
        let pk_der = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/rsa2048/end_responder.key.pub.der"
        ))
        .expect("rsa2048 test key");
        let asym = 1u32 << 2; // RsaSsa3072 only (bit 2)
        assert!(verify_rsa_key_size(&pk_der, asym).is_err());
    }

    #[test]
    fn test_verify_rsa_key_size_3072_with_real_key() {
        let pk_der = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/rsa3072/end_responder.key.pub.der"
        ))
        .expect("rsa3072 test key");
        let asym = 1u32 << 2; // RsaSsa3072 (bit 2)
        assert!(verify_rsa_key_size(&pk_der, asym).is_ok());
    }

    #[test]
    fn test_verify_rsa_key_size_no_rsa_negotiated() {
        let pk_der = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/rsa2048/end_responder.key.pub.der"
        ))
        .expect("rsa2048 test key");
        let asym = 1u32 << 4; // EcdsaP256 only
        assert!(verify_rsa_key_size(&pk_der, asym).is_err());
    }

    // ── estimate_rsa_key_size ──

    #[test]
    fn test_estimate_rsa_key_size_malformed_der() {
        let garbage = &[0x01, 0x02, 0x03, 0x04];
        assert!(estimate_rsa_key_size(garbage).is_err());
    }

    // ── SpdmBaseAsymAlgo family checks ──

    #[test]
    fn test_is_rsa() {
        assert!(SpdmBaseAsymAlgo::RsaSsa2048.is_rsa());
        assert!(SpdmBaseAsymAlgo::RsaSsa3072.is_rsa());
        assert!(SpdmBaseAsymAlgo::RsaPss4096.is_rsa());
        assert!(!SpdmBaseAsymAlgo::EcdsaP256.is_rsa());
        assert!(!SpdmBaseAsymAlgo::Ed25519.is_rsa());
    }

    #[test]
    fn test_is_ecc() {
        assert!(SpdmBaseAsymAlgo::EcdsaP256.is_ecc());
        assert!(SpdmBaseAsymAlgo::EcdsaP384.is_ecc());
        assert!(SpdmBaseAsymAlgo::EcdsaP521.is_ecc());
        assert!(!SpdmBaseAsymAlgo::RsaSsa2048.is_ecc());
        assert!(!SpdmBaseAsymAlgo::Ed25519.is_ecc());
    }

    #[test]
    fn test_is_eddsa() {
        assert!(SpdmBaseAsymAlgo::Ed25519.is_eddsa());
        assert!(SpdmBaseAsymAlgo::Ed448.is_eddsa());
        assert!(!SpdmBaseAsymAlgo::RsaSsa2048.is_eddsa());
        assert!(!SpdmBaseAsymAlgo::EcdsaP256.is_eddsa());
    }

    // ── SpdmBaseHashAlgo::from_bits ──

    #[test]
    fn test_hash_algo_from_bits_multiple() {
        let bits = (1u32 << 0) | (1u32 << 1); // SHA-256 + SHA-384
        let algos = SpdmBaseHashAlgo::from_bits(bits);
        assert_eq!(algos.len(), 2);
        assert!(algos.contains(&SpdmBaseHashAlgo::Sha256));
        assert!(algos.contains(&SpdmBaseHashAlgo::Sha384));
    }

    #[test]
    fn test_hash_algo_from_bits_empty() {
        let algos = SpdmBaseHashAlgo::from_bits(0);
        assert!(algos.is_empty());
    }

    // ── Certificate loading with real DER ──

    #[test]
    fn test_load_ecp256_cert_from_der() {
        let cert_der = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/ecp256/end_responder.cert.der"
        ))
        .expect("ecp256 cert");
        let cert = crate::certificate::Certificate::from_der(&cert_der);
        assert!(
            cert.is_ok(),
            "Failed to parse ecp256 cert: {:?}",
            cert.err()
        );
    }

    #[test]
    fn test_load_rsa3072_cert_from_der() {
        let cert_der = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../test_key/rsa3072/end_responder.cert.der"
        ))
        .expect("rsa3072 cert");
        let cert = crate::certificate::Certificate::from_der(&cert_der);
        assert!(
            cert.is_ok(),
            "Failed to parse rsa3072 cert: {:?}",
            cert.err()
        );
    }
}

// =============================================================================
// spdmlib-compatible Functions (for spdm-rs integration)
// =============================================================================

/// Verifies a signature on data using a certificate and a specific crypto backend.
///
/// Backend-agnostic version of [`verify_signature`].  Maps the SPDM algorithm
/// pair to a [`SignatureAlgorithm`] and delegates to
/// [`CryptoBackend::verify_signature`].
///
/// # Arguments
/// * `base_hash_algo` - SPDM base hash algorithm (from negotiation)
/// * `base_asym_algo` - SPDM base asymmetric algorithm (from negotiation)
/// * `public_cert_der` - Certificate in DER format (or RFC7250 public key)
/// * `data` - Data that was signed
/// * `signature` - Signature to verify
/// * `backend` - Crypto backend to use
pub fn verify_signature_with_backend<B: crate::crypto_backend::CryptoBackend>(
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    public_cert_der: &[u8],
    data: &[u8],
    signature: &[u8],
    backend: &B,
) -> Result<()> {
    use crate::certificate::Certificate;
    use crate::crypto_backend::SignatureAlgorithm;

    // Parse certificate to get public key
    let cert = Certificate::from_der(public_cert_der)?;

    // Get public key bytes
    let public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    // Map SPDM algorithm pair to SignatureAlgorithm
    let sig_algo = SignatureAlgorithm::from_spdm_algos(base_hash_algo, base_asym_algo)?;

    backend.verify_signature(sig_algo, data, signature, public_key)
}

/// Verifies a signature using the bundled test-only ring backend.
///
/// Convenience wrapper around [`verify_signature_with_backend`].  Only
/// available in this crate's own test builds (`cfg(test)`); production code calls
/// [`verify_signature_with_backend`] with its own backend.
///
/// # Example
/// ```no_run
/// use spdm_x509::x509::{verify_signature, SpdmBaseAsymAlgo, SpdmBaseHashAlgo};
/// let cert_der: &[u8] = &[];
/// let data: &[u8] = &[];
/// let signature: &[u8] = &[];
/// let _ = verify_signature(
///     SpdmBaseHashAlgo::Sha256,
///     SpdmBaseAsymAlgo::EcdsaP256,
///     cert_der,
///     data,
///     signature
/// );
/// ```
#[cfg(test)]
pub fn verify_signature(
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    public_cert_der: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    verify_signature_with_backend(
        base_hash_algo,
        base_asym_algo,
        public_cert_der,
        data,
        signature,
        &crate::crypto_backend::RingBackend,
    )
}

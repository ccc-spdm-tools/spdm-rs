# x509-limbo conformance fixtures

The `spdm_x509` tests use curated certificate-path cases from
[C2SP/x509-limbo](https://github.com/C2SP/x509-limbo). Tests never access the
network: fixtures are generated from a local checkout pinned by
`spdmlib/src/crypto/spdm_x509/etc/x509_limbo_capabilities.json` and committed to
the repository.

Each manifest entry has one of these statuses:

- `supported`: copied into its suite fixture and enforced by the Rust runner.
- `unsupported`: omitted with a required explanation of the missing capability.
- `not-applicable`: omitted with a required explanation of why the case is
  outside the SPDM certificate profile.

To regenerate the fixtures from a checkout at the pinned revision:

```sh
python3 sh_script/update_x509_limbo.py /path/to/x509-limbo/limbo.json
```

Use `--check` in automation to detect fixture drift without modifying files.
For a standalone `limbo.json`, pass its verified commit using
`--source-revision`. The importer rejects an unpinned or mismatched revision,
missing testcase IDs, duplicate classifications, unknown statuses, and outputs
that escape the manifest directory.

Generated testcases preserve the upstream fields except `peer_certificate_key`.
The certificate-validation runner does not use private keys, so the importer
omits that field rather than vendoring unnecessary key material. Certificate
PEMs, expected results, and source provenance remain unchanged.

The current Rust adapter assembles a single leaf-to-root chain. Do not classify
path-building cases with alternate or unrelated intermediates as `supported`
until the runner can treat untrusted intermediates as a candidate pool.

## Current suites

- `name_constraints` isolates Name Constraints behavior by disabling signature
  and time validation.
- `rfc5280_core` keeps signature and extension validation enabled for linear
  Basic Constraints, Key Usage, and unknown critical extension cases. Its cases
  do not specify a validation time, so the suite disables time validation.

The capability manifest records the current adapter and implementation
boundaries. Its missing-root-Basic-Constraints skip is not a general SPDM
exemption: DSP0274 1.4.0 clause 10.9.2 requires Basic Constraints for leaf,
intermediate, and root certificates. Review that classification when extending
the suite; accepting an existing fixture is not evidence of specification
conformance.

## SPDM certificate requirements-to-tests matrix

### Scope and interpretation

The normative baseline for this inventory is
[DSP0274 1.4.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.4.0.pdf),
particularly clauses 7.2.1.1, 10.4, 10.7, and 10.9.2. RFC 5280 supplies the
underlying X.509 rules referenced by DSP0274. This is a coverage inventory and
implementation backlog, not a declaration of complete SPDM conformance.

The protocol [version type](../spdmlib/src/protocol/version.rs) represents
SPDM 1.0 through 1.4. That does not establish certificate conformance for every
revision. New native cases must identify the SPDM revision, role, certificate
model, slot, and relevant negotiated capabilities. Earlier revisions need their
own normative mapping before claiming equivalent coverage; do not apply a
1.4-only wire format or capability to an older revision.

Status meanings:

- **Partial**: named tests exercise part of the requirement, but do not establish
  complete coverage or coverage through every production caller.
- **Gap**: implementation behavior or the test adapter does not yet represent
  the stated requirement.
- **Out of scope**: deliberately excluded from this work, not silently passed.

Each row needs both accepting and rejecting cases where applicable. Assertions
must identify the expected rejection category: an unrelated unsupported
algorithm or parsing failure must not stand in for the rule under test.

### Path validation and certificate fields

| ID | Requirement and normative reference | Current evidence | Status and next cases |
| --- | --- | --- | --- |
| C01 | Certificates are DER-encoded X.509 v3; serial numbers are positive. DSP0274 10.7 and 10.9.2, Table 48. | [Certificate parser][certificate] accepts version values; [chain tests][chain] include `test_verify_cert_chain_garbage_rejected`; [validator tests][validator] cover several malformed names and extensions. | **Gap.** Add explicit v1/v2 rejection, zero/negative serials, malformed DER, truncation, and trailing bytes through the SPDM entry point. An enum conversion test does not prove v3-only enforcement. |
| C02 | A supplied chain has at least one certificate, is ordered toward the leaf, and each certificate after the first is signed by its predecessor. DSP0274 10.7. | [Chain tests][chain]: `test_verify_cert_chain_ecp256_real`, `test_verify_cert_chain_empty_rejected`; [validator tests][validator]: `test_validate_chain_wrong_order_rejected`, `test_validate_chain_issuer_mismatch_rejected`, `test_verify_signature_wrong_issuer_fails`. | **Partial.** Add signed mutations of each chain position, missing/reordered intermediates, and depth-boundary cases through the root-to-leaf production adapter. |
| C03 | The first supplied certificate may be the root or a certificate signed by the root. The final certificate authenticates the endpoint; single-certificate model restrictions apply. DSP0274 10.7. | [Chain validation][validator] verifies the final element of its reversed chain as self-signed; [requester acceptance][requester] requires the first supplied certificate to be self-issued. | **Gap.** Represent a separately supplied/provisioned root when omitted on the wire. Add permitted and forbidden single-certificate model/capability combinations. General-purpose unordered path building is not required for these ordered-chain cases. |
| C04 | Intermediate and root certificates contain Basic Constraints with `cA=TRUE`. DSP0274 10.9.2, after Table 48; RFC 5280 4.2.1.9. | [Validator][validator] `verify_issuer_is_ca` accepts an absent extension. `test_verify_issuer_is_ca_with_leaf_fails` and the core Limbo intermediate-CA case cover `cA=FALSE`. | **Gap.** Add missing, malformed, false-CA, and extension-criticality cases for each issuer position. Revisit the manifest's missing-root skip instead of treating current permissiveness as a normative exception. |
| C05 | Leaf Basic Constraints is mandatory and has `cA=FALSE` for DeviceCert, AliasCert, and GenericCert. DSP0274 10.9.2, Table 48. | [SPDM tests][spdm-validator]: `test_bc_spdm_device_cert_with_ca_true_rejected`, `test_bc_spdm_alias_cert_with_ca_true_rejected`, `test_bc_spdm_no_bc_extension_passes`, and `test_bc_spdm_generic_cert_ca_true_passes`; [leaf helper][crypto] permits omission. | **Gap.** Existing permissive expectations are not 1.4 conformance tests. Add the model-by-model presence/value matrix and exercise the actual acceptance flow before changing behavior. |
| C06 | Leaf Key Usage is mandatory for DeviceCert/AliasCert, optional for GenericCert; if present it includes `digitalSignature`. DSP0274 10.9.2, Table 48. | [Leaf helper][crypto] checks `digitalSignature` only when Key Usage is present. [Extension tests][extensions] test bit decoding. | **Gap.** Add absent, malformed, correct, and incorrect Key Usage for all three models, including production leaf validation rather than bit decoding alone. |
| C07 | CA Key Usage and path-length limits obey the applicable RFC 5280 rules, including self-issued handling. DSP0274 10.9.2 references RFC 5280; RFC 5280 4.2.1.3, 4.2.1.9, and 6.1. | [Validator][validator] checks issuer `keyCertSign` and path length; tests include maximum chain depth and self-issued Name Constraints cases. | **Partial.** Add dedicated `keyCertSign` and path-length boundary vectors. Name Constraints self-issued tests do not establish correct path-length counting. Distinguish implementation depth limits from certificate path constraints. |
| C08 | Process applicable critical extensions and reject malformed/duplicate extensions as required by RFC 5280. DSP0274 10.9.2; RFC 5280 4.2 and 6.1. | Core Limbo cases cover unknown critical extensions in the leaf and intermediate. [Validator tests][validator] include `test_duplicate_extension_oids_are_rejected_before_constraint_processing`. | **Partial.** Extend across root/intermediate/leaf positions; check malformed values of recognized extensions and non-critical unknown-extension acceptance with valid signatures. |
| C09 | Enforce Name Constraints across the supplied path for each applicable name form. DSP0274 10.9.2; RFC 5280 4.2.1.10 and 6.1. | Six Limbo cases plus [validator regressions][validator], including `test_every_present_name_is_checked_and_absent_forms_are_allowed`, `test_mailbox_constraints_require_exact_san_representation`, and `test_directory_constraint_comparison_errors_fail_closed`. | **Partial.** Expand signed linear-chain cases for cumulative constraints, every supported form, excluded precedence, and self-issued boundaries. Keep signature-disabled isolation tests, but do not count them as signed end-to-end validation. |

### SPDM purpose, model, and integration

| ID | Requirement and normative reference | Current evidence | Status and next cases |
| --- | --- | --- | --- |
| S01 | SPDM EKU OIDs identify Requester and Responder authentication; both may be present, and alternate OIDs are permissible. DSP0274 10.9.2.1. | [SPDM tests][spdm-validator] cover opposite-role rejection, matching roles, both OIDs, and absent EKU; [Ring adapter tests][ring-cert] also exercise Responder EKU. | **Partial.** The generic [chain entry point][chain] currently chooses Responder role. Add a role-aware acceptance matrix for Requester mutual authentication, both roles, absent/alternate OIDs, malformed EKU, and placement outside the leaf. |
| S02 | The optional SPDM extension is non-critical and follows the specified nested OID/value format. DSP0274 10.9.2.2. | [SPDM validator][spdm-validator] has an absent-extension test and a parser that also accepts bare OIDs and warns about unknown OIDs. | **Gap.** Add canonical nested encoding, critical-bit, empty-container, invalid OID, trailing-field, and OID-definition cases. Verify the production caller actually invokes the checks; helper availability is not integration coverage. |
| S03 | Hardware Identity is recommended for DeviceCert/device CA, not universally mandatory; it is forbidden in alias certificates. Its definition value is absent. DSP0274 7.2.1.1 and 10.9.2.2.1. | [SPDM tests][spdm-validator] include `test_hw_identity_device_cert_without_spdm_ext_rejected` and generic omission acceptance. [Leaf helper][crypto] selects AliasCert or GenericCert. | **Gap.** Reconcile the helper's mandatory DeviceCert expectation with the recommendation. Test identity placement in the device CA and every alias certificate, not just the leaf, plus forbidden definition bytes. |
| S04 | Certificate models depend on the slot and negotiated capabilities; GenericCert requires the applicable multi-key connection mode and is not allowed in slot 0. DSP0274 10.7. | [SPDM validator][spdm-validator] represents the three models; [requester leaf acceptance][requester] currently passes an alias-capability boolean. | **Gap.** Add version/capability/slot/model combinations and single-certificate restrictions. An enum-name test is not evidence that the negotiated model reaches leaf validation. |
| S05 | Validate certificate signatures and endpoint public-key compatibility at the appropriate algorithm-negotiation layer. DSP0274 10.4, 10.7, and 10.9.2, Table 48. | [Signature tests][signature] cover algorithm families, curves, RSA sizes, and hash selection; [chain tests][chain] cover a matching ECDSA chain and wrong asymmetric selection. | **Partial.** Add valid/invalid signature parameters, wrong keys, supported classical/PQC combinations, and role-specific negotiated selections. Separately identify certificate-issuer signature algorithms and the endpoint authentication key; do not assume every issuer must use the negotiated leaf algorithm. |
| S06 | Check certificate-chain framing and RootHash using the selected hash algorithm. DSP0274 10.7, Table 39; certificate retrieval in 10.9. | [Chain tests][chain] cover header parsing and hashing; [requester acceptance][requester] checks total length and root digest. [Retrieval tests][retrieval-tests] include `test_case0_send_receive_spdm_certificate` and `test_handle_spdm_certificate_partial_response`. | **Partial.** Add hash mismatch, wrong hash selection, incomplete/extra bytes, malformed lengths, and omitted-root cases through real certificate callbacks. Distinguish pre-1.4 framing from the 1.4 four-byte length. |
| S07 | Requester and Responder certificate retrieval exchange roles for mutual authentication. DSP0274 10.9.1. | [Encapsulated acceptance][encap-requester] verifies chain signatures, RootHash, and provisioned roots; [encapsulated tests][encap-tests] exercise message handling. | **Partial.** Use equivalent accepting/rejecting certificate vectors in both directions. Verify that role-specific EKU and leaf-model checks are applied, rather than assuming symmetry from successful message handling. |
| S08 | Establish trust in the root separately from verifying a chain's internal consistency. DSP0274 7.2.1.1 and 10.7; deployment trust provisioning is an explicit input. | [Requester][requester] and [encapsulated acceptance][encap-requester] compare provisioned roots when present and allow an unprovisioned mode. | **Partial.** Add matching/nonmatching/missing provisioned-root tests and name the deployment policy for each case. A valid RootHash or self-signature must not be reported as proof that a root is authorized. Do not change the unprovisioned policy as part of test expansion. |
| S09 | Results should be consistent for each backend's supported algorithm set. Test strategy for the preceding requirements, not a separate wire-protocol requirement. | [Limbo runner][limbo] currently runs inside `spdm_x509` tests using its test-only Ring backend. | **Gap.** Reuse the applicable native vectors through production Ring, AWS-LC, and mbedTLS callbacks. Report unsupported algorithms explicitly; never count them as successful negative validation cases. |

### Explicit exclusions

- **Out of scope: time-based decisions.** No current-time/expiry/not-yet-valid
  decisions, injected clock, or validity-period ordering work is planned here.
  DER syntax and mandatory-field presence remain structural certificate tests;
  disabling time decisions does not waive those checks.
- **Out of scope: WebPKI identity matching.** No TLS DNS/IP hostname matching,
  browser policy, or browser trust-store behavior. Name Constraints remain
  in scope because they constrain certification paths independently of a TLS
  reference hostname.
- **Out of scope: general path discovery.** No AIA fetching or unordered
  alternate-path search. An omitted root in an ordered SPDM chain remains in
  scope and needs an explicit trust-anchor input.
- **Not claimed by this increment:** complete certificate-policy processing or
  CRL/OCSP validation. This is a scope boundary, not a claim that SPDM waives
  every applicable RFC 5280 rule.

### Execution order and completion criteria

1. Expand the linear-path Limbo vectors for C02 and C07-C09. Classify time,
   TLS-specific, unsupported-algorithm, and path-discovery cases explicitly.
2. Add native SPDM fixtures for C01 and C03-C06, then S01-S05, using the
   normative model/capability inputs rather than preserving permissive
   expectations as conformance rules.
3. Exercise S06-S08 through both production acceptance flows with real crypto
   callbacks, then run S09 against each supported backend.
4. Produce a per-requirement result with accepting/rejecting case IDs, revision,
   role/model/capability inputs, expected rejection category, and explicit skip
   reasons. Collect all mismatches rather than stopping after the first one.

A row is complete only when the implementation and its actual callers satisfy
the stated rule and the applicable positive/negative cases run in CI. Merely
adding an ID to the capability manifest, passing a helper test, or rejecting
a testcase for an unrelated reason does not close a gap.

[certificate]: ../spdmlib/src/crypto/spdm_x509/src/certificate/mod.rs
[chain]: ../spdmlib/src/crypto/spdm_x509/src/x509/chain.rs
[validator]: ../spdmlib/src/crypto/spdm_x509/src/x509/validator.rs
[spdm-validator]: ../spdmlib/src/crypto/spdm_x509/src/x509/spdm_validator.rs
[extensions]: ../spdmlib/src/crypto/spdm_x509/src/x509/extensions.rs
[signature]: ../spdmlib/src/crypto/spdm_x509/src/x509/signature.rs
[crypto]: ../spdmlib/src/crypto/mod.rs
[ring-cert]: ../spdmlib/src/crypto/spdm_ring/cert_operation_impl.rs
[requester]: ../spdmlib/src/requester/get_certificate_req.rs
[encap-requester]: ../spdmlib/src/responder/encap_get_certificate.rs
[retrieval-tests]: ../test/spdmlib-test/src/requester_tests/get_certificate_req.rs
[encap-tests]: ../test/spdmlib-test/src/responder_tests/encap_get_certificate.rs
[limbo]: ../spdmlib/src/crypto/spdm_x509/src/x509/limbo.rs

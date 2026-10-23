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

All three suites enable signature and extension validation and disable
time-based decisions. Their selected cases do not require a validation time,
CRLs, algorithm allowlists, or the upstream logical-intermediate depth option.

| Suite | Cases | Accept | Reject | Path-rule coverage |
| --- | --- | --- | --- | --- |
| `name_constraints` | 46 | 14 | 32 | DNS, IP, directory and email names; cumulative constraints; self-issued exceptions; malformed and unsupported constrained forms. |
| `rfc5280_core` | 9 | 3 | 6 | CA flags and Key Usage consistency, unknown critical extensions at every position, duplicate extensions, and optional leaf extensions. |
| `rfc5280_pathlen` | 7 | 5 | 2 | Path-length boundaries, increasing intermediate limits, and self-issued rollover certificates. |

Run the 62 curated cases with:

```sh
cargo test -p spdm_x509 x509_limbo_conformance -- --nocapture
```

For each accepting chain, the tests additionally corrupt each certificate's
signature in turn and require a signature-verification error. Rejecting chains
must fail in the intended error category, not because of an unrelated
unsupported algorithm, missing issuer, or certificate-decoding failure. The
deliberately malformed IP SAN case specifically permits its ASN.1 decoding
error. Existing signature-disabled unit tests remain useful isolation tests,
but are not substituted for these signed chains.

These are path-rule tests, not complete SPDM endpoint acceptance tests. The
runner does not evaluate upstream TLS peer-name or client/server EKU inputs.
In particular, the core suite's missing-leaf-extension cases establish generic
path behavior, not permission to omit mandatory SPDM leaf fields.

The manifest classifies all 48 pinned `rfc5280::nc` cases: 46 supported and two
requiring path discovery. Across the three suites, it classifies 81 cases:
62 supported, 11 unsupported, and eight not applicable. It does not classify
the entire 9,786-case upstream corpus.

Explicit skips include time-based acceptance, TLS-purpose EKU, alternate-path
discovery, and CA-as-final-target cases. Unsupported entries include ML-DSA
verification in the test-only Ring backend and upstream `max_chain_depth`,
which counts logical intermediates rather than our total-certificate limit.
The pinned `rfc5280::ica-ku-keycertsign` case omits the intermediate described
by its documentation; it is not counted as successful Key Usage coverage
merely because the supplied chain cannot link.

The capability manifest records the current adapter and implementation
boundaries. Its missing-root-Basic-Constraints skip is not a general SPDM
exemption: DSP0274 1.4.0 clause 10.9.2 requires Basic Constraints for leaf,
intermediate, and root certificates. Review that classification when extending
the suite; accepting an existing fixture is not evidence of specification
conformance.

## SPDM certificate requirements-to-tests matrix

### Native SPDM 1.4 field enforcement

For negotiated SPDM 1.4 connections, both GET_CERTIFICATE and encapsulated
GET_CERTIFICATE acceptance run a shared, backend-independent field check:

- Every supplied certificate is v3 with a positive serial number.
- Root/intermediate Basic Constraints is present with `cA=TRUE`.
- Leaf Basic Constraints is present with `cA=FALSE` and no path length.
- DeviceCert/AliasCert leaf Key Usage is present; GenericCert may omit it.
  Present leaf Key Usage includes `digitalSignature` and excludes `keyCertSign`.

Multi-key connections use the selected slot's certificate model from DIGESTS.
Missing/invalid models and GenericCert in slot 0 are rejected. Single-key
Responder connections use ALIAS_CERT_CAP; single-key Requester connections
have no model flag, but DeviceCert/AliasCert have identical mandatory-field
requirements. Existing leaf hardware-identity checks use the selected model,
not a global Responder capability, in both 1.4 acceptance paths.

Encapsulated DIGESTS uses MULTI_KEY_CONN_REQ for 1.4 encoding/decoding,
retains packed per-slot metadata, and computes digests before encoding so
metadata is not overwritten by digest patching. Normal DIGESTS continues to
use MULTI_KEY_CONN_RSP.

SPDM 1.0-1.3 acceptance is unchanged. The legacy leaf and `SpdmValidator`
helpers remain compatibility APIs, not independent proof of 1.4 conformance.
Generic Limbo validation does not run the additional SPDM field profile; its
missing-Basic-Constraints capability exclusions remain intentional.

The [native field tests][spdm-validator] exercise rejection categories at each
certificate position and the model-specific leaf matrix. Mutated unit-test
certificates test fields only, not signatures. The [acceptance tests][native-tests]
reuse signed public DeviceCert/AliasCert chains and the signed missing-leaf-BC
regression in both directions, verify version gating and slot/model selection,
and check that corrupt signatures still fail. No private keys are added.

```sh
cargo test -p spdm_x509 test_spdm14
cargo test -p spdmlib-test --test spdm14_certificate_fields
```

This increment does not fix omitted-root/single-certificate handling,
role-aware EKU in crypto callbacks, the full SPDM extension format, or
algorithm negotiation. Time decisions and deployment trust policy are unchanged.

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
| C01 | Certificates are DER-encoded X.509 v3; serial numbers are positive. DSP0274 10.7 and 10.9.2, Table 48. | The 1.4 field profile checks every certificate. [Native tests][spdm-validator]: `test_spdm14_version_and_serial_at_every_position` and `test_spdm14_der_boundaries_and_negative_serial` cover v1/v2, zero/negative serials, positive sign-padding, malformed DER, truncation, and trailing bytes. Both [acceptance paths][native-tests] invoke the profile. | **Partial.** Structural mutations isolate the field rule; extend signed per-position field vectors through both production paths. No earlier-revision conformance claim. |
| C02 | A supplied chain has at least one certificate, is ordered toward the leaf, and each certificate after the first is signed by its predecessor. DSP0274 10.7. | [Chain tests][chain]: `test_verify_cert_chain_ecp256_real`, `test_verify_cert_chain_empty_rejected`; [validator tests][validator]: `test_validate_chain_wrong_order_rejected`, `test_validate_chain_issuer_mismatch_rejected`, `test_verify_signature_wrong_issuer_fails`; all accepting Limbo chains reject signature corruption at each position. | **Partial.** Extend signature mutations, missing/reordered intermediates, and depth-boundary cases through the root-to-leaf production adapter. |
| C03 | The first supplied certificate may be the root or a certificate signed by the root. The final certificate authenticates the endpoint; single-certificate model restrictions apply. DSP0274 10.7. | [Chain validation][validator] verifies the final element of its reversed chain as self-signed; [requester acceptance][requester] requires the first supplied certificate to be self-issued. | **Gap.** Represent a separately supplied/provisioned root when omitted on the wire. Add permitted and forbidden single-certificate model/capability combinations. General-purpose unordered path building is not required for these ordered-chain cases. |
| C04 | Intermediate and root certificates contain Basic Constraints with `cA=TRUE`. DSP0274 10.9.2, after Table 48; RFC 5280 4.2.1.9. | The 1.4 field profile requires the extension and `cA=TRUE`. [Native tests][spdm-validator]: `test_spdm14_issuer_field_matrix` isolates missing, malformed, and false-CA errors at root/intermediate positions. Generic X.509 validation retains its prior omission behavior. | **Partial.** Add signed missing/malformed issuer vectors through both acceptance paths and address extension criticality separately. Generic Limbo's missing-root exclusion is not a SPDM profile exemption. |
| C05 | Leaf Basic Constraints is mandatory and has `cA=FALSE` for DeviceCert, AliasCert, and GenericCert. DSP0274 10.9.2, Table 48. | [Native tests][spdm-validator]: `test_spdm14_leaf_field_matrix` covers all three models, missing/malformed BC, `cA=TRUE`, and forbidden leaf path length. [Acceptance tests][native-tests] accept signed chains and reject the signed missing-BC leaf in both 1.4 directions, while preserving 1.0-1.3 behavior. | **Partial.** The production 1.4 checks are wired; extend the signed value/malformed matrix. Permissive legacy helper expectations are not 1.4 conformance tests. |
| C06 | Leaf Key Usage is mandatory for DeviceCert/AliasCert, optional for GenericCert; if present it includes `digitalSignature`. DSP0274 10.9.2, Table 48. | The 1.4 profile enforces presence by the negotiated model and rejects `keyCertSign` on leaves. [Native tests][spdm-validator]: `test_spdm14_leaf_field_matrix` covers absent, malformed, correct, and incorrect KU for each model. [Acceptance tests][native-tests] exercise per-slot model selection in both directions. | **Partial.** Extend signed missing/incorrect KU vectors through both production acceptance paths; native field mutations do not prove cryptographic acceptance. |
| C07 | CA Key Usage and path-length limits obey the applicable RFC 5280 rules, including self-issued handling. DSP0274 10.9.2 references RFC 5280; RFC 5280 4.2.1.3, 4.2.1.9, and 6.1. | [Validator][validator] checks issuer `keyCertSign` and counts non-self-issued intermediates for path length. `test_pathlen_x509_limbo_conformance` covers seven signed paths, including rollover and exceeded limits; the core suite rejects inconsistent root CA/Key Usage. | **Partial.** Add validly linked intermediate `keyCertSign` rejection vectors. Distinguish implementation depth limits from certificate path constraints; the upstream logical-depth cases remain explicitly unsupported. |
| C08 | Process applicable critical extensions and reject malformed/duplicate extensions as required by RFC 5280. DSP0274 10.9.2; RFC 5280 4.2 and 6.1. | Core Limbo cases cover unknown critical extensions in the root, intermediate, and leaf, duplicate extensions, and non-critical AIA acceptance. [Validator tests][validator] include `test_duplicate_extension_oids_are_rejected_before_constraint_processing`. | **Partial.** Add malformed recognized-extension values at each position and extend coverage through the production SPDM acceptance flows. |
| C09 | Enforce Name Constraints across the supplied path for each applicable name form. DSP0274 10.9.2; RFC 5280 4.2.1.10 and 6.1. | 46 signed Limbo cases plus [validator regressions][validator], including `test_every_present_name_is_checked_and_absent_forms_are_allowed`, `test_mailbox_constraints_require_exact_san_representation`, and `test_directory_constraint_comparison_errors_fail_closed`. | **Partial.** The signed cases now cover cumulative constraints, excluded precedence, self-issued boundaries, DNS/IP/directory/email names, and unsupported-name handling. Extend URI-specific signed cases and exercise the production acceptance flows. |

### SPDM purpose, model, and integration

| ID | Requirement and normative reference | Current evidence | Status and next cases |
| --- | --- | --- | --- |
| S01 | SPDM EKU OIDs identify Requester and Responder authentication; both may be present, and alternate OIDs are permissible. DSP0274 10.9.2.1. | [SPDM tests][spdm-validator] cover opposite-role rejection, matching roles, both OIDs, and absent EKU; [Ring adapter tests][ring-cert] also exercise Responder EKU. | **Partial.** The generic [chain entry point][chain] currently chooses Responder role. Add a role-aware acceptance matrix for Requester mutual authentication, both roles, absent/alternate OIDs, malformed EKU, and placement outside the leaf. |
| S02 | The optional SPDM extension is non-critical and follows the specified nested OID/value format. DSP0274 10.9.2.2. | [SPDM validator][spdm-validator] has an absent-extension test and a parser that also accepts bare OIDs and warns about unknown OIDs. | **Gap.** Add canonical nested encoding, critical-bit, empty-container, invalid OID, trailing-field, and OID-definition cases. Verify the production caller actually invokes the checks; helper availability is not integration coverage. |
| S03 | Hardware Identity is recommended for DeviceCert/device CA, not universally mandatory; it is forbidden in alias certificates. Its definition value is absent. DSP0274 7.2.1.1 and 10.9.2.2.1. | [Acceptance tests][native-tests] verify alias leaf hardware-identity rejection in both 1.4 directions using the selected model; DeviceCert identity omission is not made mandatory there. The standalone [SPDM helper][spdm-validator] still has a mandatory DeviceCert expectation. | **Partial.** Reconcile that standalone helper with the recommendation. Test identity placement in the device CA and every alias certificate, not just the leaf, plus forbidden definition bytes. |
| S04 | Certificate models depend on the slot and negotiated capabilities; GenericCert requires the applicable multi-key connection mode and is not allowed in slot 0. DSP0274 10.7. | Both 1.4 acceptance paths resolve the selected slot's model, reject missing/invalid multi-key models and GenericCert in slot 0, and distinguish Requester/Responder connection mode. [Acceptance tests][native-tests] cover slots 0/3, model values, asymmetric multi-key flags, and packed encapsulated DIGESTS metadata/hash roundtrips. | **Partial.** Add single-certificate restrictions and the remaining capability/model combinations. Single-key Requester model identity is not advertised by a capability flag. |
| S05 | Validate certificate signatures and endpoint public-key compatibility at the appropriate algorithm-negotiation layer. DSP0274 10.4, 10.7, and 10.9.2, Table 48. | [Signature tests][signature] cover algorithm families, curves, RSA sizes, and hash selection; [chain tests][chain] cover a matching ECDSA chain and wrong asymmetric selection. | **Partial.** Add valid/invalid signature parameters, wrong keys, supported classical/PQC combinations, and role-specific negotiated selections. Separately identify certificate-issuer signature algorithms and the endpoint authentication key; do not assume every issuer must use the negotiated leaf algorithm. |
| S06 | Check certificate-chain framing and RootHash using the selected hash algorithm. DSP0274 10.7, Table 39; certificate retrieval in 10.9. | [Chain tests][chain] cover header parsing and hashing; [requester acceptance][requester] checks total length and root digest. [Retrieval tests][retrieval-tests] include `test_case0_send_receive_spdm_certificate` and `test_handle_spdm_certificate_partial_response`. | **Partial.** Add hash mismatch, wrong hash selection, incomplete/extra bytes, malformed lengths, and omitted-root cases through real certificate callbacks. Distinguish pre-1.4 framing from the 1.4 four-byte length. |
| S07 | Requester and Responder certificate retrieval exchange roles for mutual authentication. DSP0274 10.9.1. | [Acceptance tests][native-tests] run signed accepting/missing-leaf-BC cases, model checks, and corrupt signatures in both directions. Encapsulated DIGESTS uses the Requester multi-key mode for 1.4 metadata. | **Partial.** The 1.4 fields and leaf-model checks are wired in both directions; crypto callbacks still hardcode Responder EKU. Add role-aware EKU and role-specific algorithms rather than claiming full symmetry. |
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

1. The linear-path expansion for C02 and C07-C09 now contains 62 signed
   cases with explicit exclusions. Remaining path-rule work includes URI
   constraints and intermediate Key Usage vectors that can isolate the rule.
2. The first native increment enforces C01 and C04-C06 fields for 1.4 in both
   production directions, with field-category matrices and signed acceptance
   regressions. Extend signed field vectors, then address C03 and S01-S05
   (including role-aware crypto callbacks) using normative model/capability
   inputs rather than permissive compatibility expectations.
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
[native-tests]: ../test/spdmlib-test/tests/spdm14_certificate_fields.rs

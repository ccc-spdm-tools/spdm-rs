# Design Guideline

## Threat Model and Crypto Usage

1. <B>spdm_secret</B> is to handle <B>persistent secret</B>. (Device Specific)

It can access the device private key and sign the message. It can access the PSK and HMAC the message. It can collect the device measurement.

API: Sign the data with private key. HMAC the data with PSK. Return DeviceMeasurement.

External Input: None.

Internal Input: Data to be signed. Data to be HMACed.

Threat: Information disclosure (including side channel), Elevation of privilege, Tampering with data.

2. <B>spdm_session_secret</B> is to handle <B>ephemeral secret</B>. (Crypto engine specific)

It can generate DH secret and derive the session key. (The keys can be imported and exported as an option.) It can handle key update. It can encrypt and decrypt the message.

API: Generate DH secret. Manage the SPDM session. Encrypt and decrypt the SPDM secured message.

External Input: Cipher message to be decrypted. (Malicious)

Internal Input: Plain message to be encrypted. Internal SPDM session context.

Threat: Information disclosure (including side channel), Elevation of privilege, Tampering with data, Denial of service.

3. <B>spdm_crypto</B> is to handle <B>no secret</B> operation.

API: Verify the signature. Hash data. Generate random number.

External Input: Public certificate/key. (Malicious)

Internal Input: Message to be hashed. Internal SPDM context.

Threat: Tampering with data, Denial of service.

## Execution Environment

1. spdmlib should only use core.

2. alloc is not allowed in spdmlib or the trait defined by spdmlib, such as spdm_crypt.

The trait implenmtation may use alloc, such as ring or webpki.

3. std is not allowed in spdmlib.

The whole solution may use std, such as spdm_emu tool.

## Sanity Check

### A. Data Structure Check

1. <B>Every</B> data structure / function should do sanity check based upon its own knowledge, and return error if requirement is not satisfied. Every data structure function should rely on the checkin result from the lower layer and not duplicate the check. Every data structure should NOT check for the upper layer use case.

<B>Example 1</B>: It is legal that SpdmBaseHashAlgo contains mutiple bits in requester, but illegal in responder.

SpdmBaseHashAlgo.read() should not check that it only contains 1 bit.

SpdmAlgorithmsResponderPayload.read() should check it contains 1 bit or none.

send_receive_spdm_algorithm() should check the responder bit is also supported by requeter.

<B>Example 2</B>: Digest/Signature structure should match the negotiated digest/signature algorithm.

SpdmDigestStruct/SpdmSignatureStruct need guarantee the match between size and algorithm.

2. For bitflags type, the reserved field should be ingored during read(), and should be 0 during encode().

3. For enum type, the reserved type should be treated as error during read(), and should not be present during encode().

4. For enum type, the enum_name::Unknown(v) may be a valid or invalid type in some data structure. If the data structure should do sanity check based upon its own knowledge, and only reject the invalid one.

<B>Example 1</B>: SpdmMeasurementOperation::Unknown(0x1) may be a valid type. It means to return measurement index 1.

<B>Example 2</B>: SpdmAlg::SpdmAlgoUnknown(SpdmUnknownAlgo) is invalid type. It should be treated as an error.

### B. Error handling in Codec

1. read() uses Option<>, because it is from untrusted source.

2. encode() uses panic!(), because it is from trusted source.

### C. Error Code

1. Use Option<>, if the function just returns Some(v)/None.

2. Use Result<(),()>, if the function wants to return Ok(v)/Err(e).



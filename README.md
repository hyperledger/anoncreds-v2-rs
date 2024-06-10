# AnonCreds v2

This repository contains the basis for the AnonCreds v2 implementation, an
evolution of the AnonCreds v1 open [specification] and open source
[implementation] that has been widely used around the world since 2017.  The
goal of AnonCreds v2 is to retain and extend the privacy-preserving features of
AnonCreds v1, while improving capabilities, performance, extensibility, and
security.

> Want to help with AnonCreds v2? Check out the [To Do Items] to extend this
implementation from a starting point to where it can be used in production
solutions.

[specification]: https://hyperledger.github.io/anoncreds-spec/
[implementation]: https://github.com/hyperledger/anoncreds-rs

Concretely, AnonCreds v2:

- Is intended to retain the objects from AnonCreds v1 -- the credential schema,
  credential definition, presentation request, and presentation.
  - Although none of the objects are identical to those in AnonCreds v1, the interactions with the objects are the same. This will enable a path for migrating implementations from AnonCreds v1 to v2.
- Substantially increases the information included in the [credential
  schema](#credential-schema) about the claim types such that the encoding and
  cryptographic handling of the claims can be enhanced to provide more:
  - capabilities - additional ZKP presentation options and different, swapable signature schemes
  - performance - via support for different signature schemes
  - extensibility - additional ZKP presentation options and different, swapable signature schemes
  - security - support for more secure signature schemes
- Supports [PS Signatures] in the current implementation and can be updated to support [BBS+ Signatures]
  - The [BBS+ Signatures] support has been tested in this implementation in the past, but is not part of the current codebase.
  - [CL Signatures] could be used.
  - PS Signatures have a [post-quantum option] that will be experimented with in the context of AnonCreds v2.
- Supports additional kinds of ZKP presentation capabilities, including:
  - Signed integer expressions
  - Range proof
  - Domain proof (also known as a per verifier credential identifier)
  - Set membership
  - Verified encryption
  - Blinded secret
  - Equality proof of claims from different credentials
  - Revocation
- Supports revocation in a substantially simpler and more scalable way using the [ALLOSAUR] revocation scheme
  - Other techniques for revocation are being considered for AnonCreds v2.

[PS Signatures]: https://eprint.iacr.org/2015/525.pdf
[BBS+ Signatures]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures
[CL Signatures]: https://eprint.iacr.org/2001/019.pdf
[ALLOSAUR]: https://eprint.iacr.org/2022/1362
[post-quantum option]: https://eprint.iacr.org/2022/509

## To Do for AnonCreds v2

AnonCreds v2 is currently in production and ready for use. This repository is but an initial
(thorough but incomplete) implementation. The issues contain a list of the
labelled [To Do Items] (open and closed) that we envision are needed for a
complete implementation. We are now seeking collaborators to help with the
implementation to knock off the [To Do Items].

[To Do Items]: https://github.com/hyperledger/anoncreds-v2-rs/issues?q=label%3A%22AnonCreds+v2+To+Do%22+

Some of the [To Do Items] are focused around making AnonCreds v2 sufficiently
opinionated to enable interoperability. The success to date of AnonCreds to now
has been because of its ZKP-capabilities combined with its opinionated
specification that makes it obvious to all parties in an AnonCreds verifiable
credential ecosystem to know what is required of each other. Comparable
opinionated specifications are needed in AnonCreds v2 to simplify deployments.

## Implementation Overview

The following is an overview of the current AnonCreds v2 implementation.

### Claims

Credentials are composed of claims. Claims are a tuple of information consisting of a _label_, _type_, and _value_. The _label_ is distinct per credential
allowing a reference to the claim by a user-friendly name. For each type there is a mapping from the content
value to the cryptographic value–the form that can be used by the cryptographic algorithms.
AnonCreds v2 supports the following types: integers, dates, enumerations, raw cryptographic material like
secret keys or pseudonyms, and arbitrary length data like strings, images and biometrics. Arbitrary length
data and enumerations are mapped using a hash function, integers are restricted to 64 bits and do not require
mapping. Dates are mapped to integers based on the resolution needed. For example, birthdays could be
encoded as the number of days since 1/1/1900. Timestamps with precision to the second are the number of
seconds since 1/1/1970.

Each of these is represented as the types 

1. `EnumerationClaim` - Defines a fixed set of values where the claim value is one of them.
2. `NumberClaim` - A claim is a 64-bit integer like numbers, dates, and times.
3. `HashedClaim` - The claim is an arbitrary length value that will be hashed like strings, images, and biometrics.
4. `ScalarClaim` - The claim is already a cryptographic value and should be taken as is like a secret key.
5. `RevocationClaim` - The claim is meant to indicate revocation status of the claim.

Claims can also be checked against a set of validators which can be zero or more of the following:

1. `LengthValidator` checks the claim's length is correct.
    - _min_(optional) The minimum claim length. If missing the default value is 0.
    - _max_(optional)  The maximum claim length. If missing the default value is 4,294,967,295.
2. `RangeValidator` checks if the claim value is between the correct range. The claim value is interpreted as an
   integer. The result is false if the value is not in range or cannot be interpreted as an integer. The
   ranges are inclusive
   - _min_(optional) The minimum claim value. If missing, the default value is -9,223,372,036,854,775,808
   - _max_(optional) The maximum claim value. If missing the default value is 9,223,372,036,854,775,807
3. `RegexValidator` check if the claim data matches a regular expression
   - _pattern_(required) The regular expression
4. `AnyOne` check if a claim value matches any value in the list.
   - _values_(required) The fixed set of values.

The _label_, _type_, _value_, and _validators_ are combined into a `ClaimSchema`. An ordered list of `ClaimSchema`'s
can be used to create a `CredentialSchema`

### Credential Schema

The schema is data definition and layout for the credential. The schema defines what data is included in the
credential, how it should be interpreted, what rules the data must follow to be well formed, and which claims
are allowed to be blindly signed. 

```rust
let cred_schema = CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims)?; 
                                        ^            ^                  ^    ^
                                        |            |                  |    |
                                        The Label    |                  |    |
                                                     The description    |    |
                                                                        |    The claim schemas
                                                                        |
                                                                        The claim labels of blindable claims
    
```

Once a schema has been created, any number of issuers can be created.

### Issuer setup

The issuer manages a set of keys for signing credentials, decrypting verifiable
encryptions, and updating revocation registries. The secret keys are never
communicated or disclosed and should be stored in secure vaults. The public keys
contain cryptographic information for verification. The public keys should be
accessible for holders and verifiers to use and trust. These keys can be
anchored to a blockchain, S3 bucket, IPFS, or CDN.

```rust
let (issuer_public, issuer) = Issuer::new(&cred_schema);
```

In the code example above, the `issuer_public` can be given to anyone while `issuer` must be kept private.
`issuer_public` allows anyone to verify the credential (or presentation) was signed by the issuer.
`issuer` contains the secret signing keys and should be protected.

### Credential Issuance

This protocol has a Holder role, executed by the end user, and the Issuer role, executed by an organization (e.g.
business or government). During the issuance protocol, the Issuer and Holder interactively create a signature
for the Holder, which is the cryptographic part of the credential. Credentials can be issued entirely by the Issuer
or a three step blind signing protocol. At each step of this three flow protocol, a zero knowledge proof ensures
that both parties are correctly implementing the protocol. The Holder first computes signature with Blind and
sends the commitment and proof of knowledge of blind messages to the Issuer. The Issuer verifies the proof
and computes the blind signature using Blind Sign. The blind signature and known messages are sent to the
Holder who unblinds the signature with Unblind and uses Verification to check the signature validity.

The issuer signs the `ClaimData` which becomes the credential. The `ClaimData` must match the same order as the
credential schema otherwise issuance will fail.

```rust
    let credential = issuer.sign_credential(&[
        RevocationClaim::from(CRED_ID).into(),
        HashedClaim::from("John Doe").into(),
        HashedClaim::from("P Sherman 42 Wallaby Way Sydney").into(),
        NumberClaim::from(30303).into(),
    ])?;
```

### Credential Revocation

This protocol is executed by the Issuer role. When Issuers revoke a credential, the revocation registry update
is published and all existing revocation handles become stale—holders cannot show that their credential has
not been revoked for the newer version–thus users need to update their handles. Users can request an updated
revocation handle from the Issuer at any time with a presentation that proves the previous handle was valid. The
Issuer checks if that user’s signature is not currently revoked and if still valid, returns a fresh handle. Revocation
handles can be used for unlimited presentations until the next revocation update occurs. This model is different
from current PKI in that PKI requires users to reveal a unique ID or handle to the verifier who then queries the
Issue directly or indirectly downloads a list to verify the ID or handle has not been revoked. This newer model
requires no such check. Instead, users use their handles to prove they are not revoked to verifiers. The verifier
only needs the revocation verifying key and registry value to validate the proof. Issuers revoke a credential with
Remove and publish the updated accumulator value.

### Revocation Handle Update

This protocol is executed between the Holder and the Issuer roles. After
publishing an updated accumulator, the Holder’s revocation handle will be stale.
The Issuer checks revocation handle claim to see if it's still in the
non-revoked set. If successful, Witness generation is used to create and return
a new witness handle for the Holder.

### Presentation Schema

A presentation schema is similar to a credential schema in that it defines a set of statements and conditions that a user must satisfy for the verifier to be convinced about the
veracity of the user’s interaction. Statements indicate what must be proved. A credential from a specific issuer
or a revocation check are examples of statements. Each statement contains a unique identifier, the statement
type, and the public data used to verify the statement like keys or numeric constants.

To combine and connect all the statements contained in the specification, that is glue all parts
together into a single ZKP, we use schnorr proofs. For generating a schnorr proof that encompasses multiple
statements, for each statement one requires a hash contribution on the one hand, a proof contribution based
on an aggregation of the hash contributions on the other. Thus, each statement contributes to the aggregated
proof. The hash contributions are done on the generation side, and proof contributions on the verifier side.

Ultimately, claims are disclosed or remain hidden. Disclosed claims are revealed to the verifier.
Hidden claims can be unrevealed completely or partially revealed in predicate statements.

All statements except signatures represent predicate statements. Predicates can prove a claim is in a set, in a range
equal to a previously sent but different message, or encrypted in a ciphertext.

#### Presentation Statements

AnonCreds v2 supports the following presentation statement types:

1. `SignatureStatement` defines which issuer a signature must come from and which claims must be disclosed.
2. `AccumulatorSetMembershipStatement` defines a proof where the claim is a member of the set. The claim is not disclosed, only if it is a member of the set.
3. `EqualityStatement` is used to check that a non-disclosed claim is the same across multiple other statements.
4. `CommtimentStatement` creates a unique value based on a claim. Is also used to link to range statements.
5. `RangeStatement` defines a proof where a claim is in a range. Requires a commitment statement for the specified claim.
6. `VerifiableEncryptionStatement` defines a proof where a claim is proven to be encrypted in a ciphertext.

### Presentation

A presentation can be created by taking a list of credentials and a presentation schema.
A unique presentation id called a nonce should also be included to prevent a holder from
reusing a presentation previously sent. This shows the holder is able to create the presentation
fresh and not copy it from another holder including themselves.

```rust
let presentation = Presentation::create(&credentials, &presentation_schema, &nonce)?;
```

To verify the presentation, the verifier simply calls verify using the same 
public information the holder used.

```rust
presentation.verify(&presentation_schema, &nonce)?;
```

## Getting Started

To run the `cargo` tests for AnonCreds, fork/clone this repository and in the root folder,
execute the following. Rust must be installed on your system. The code currently compiles
into a crate called `credx`.

``` bash
cargo tests
```

Take a look at [tests/flow.rs](./tests/flow.rs) to see the objects in AnonCreds
v2, especially the issuance input [credential schema](#credential-schema) and
[presentation statements](#presentation-statements).

## Acknowledgement

A special thanks to Cryptid Technologies, Inc for sponsoring and collaboration in development of this library. 

## License

Licensed under Apache License, Version 2.0, ([LICENSE](LICENSE) or https://www.apache.org/licenses/LICENSE-2.0)

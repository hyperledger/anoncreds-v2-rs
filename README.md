CredX
-----


Credential Exchange (CredX) is a library for issuing, presenting and verifying credentials.

Claims
------

Credentials are composed of claims. Claims are a tuple of information consisting of a _label_, _type_, and _value_. The _label_ is distinct per credential
allowing a reference to the claim by a user-friendly name. For each type there is a mapping from the content
value to the cryptographic value–the form that can be used by the cryptographic algorithms.
CredX supports the following types: integers, dates, enumerations, raw cryptographic material like
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

Credential Schema
-----------------

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

Issuer setup
------------
The issuer manages a set of keys for signing credentials, decrypting verifiable encryptions, and updating revoca-
tion registries. The secret keys are never communicated or disclosed and should be stored in secure vaults. The
public keys contain cryptographic information for verification. The public keys should be accessible for holders
and verifiers to use and trust. These keys can be anchored to a blockchain, S3 bucket, IPFS, or CDN.

```rust
let (issuer_public, issuer) = Issuer::new(&cred_schema);
```

In the code example above, the `issuer_public` can be given to anyone while `issuer` must be kept private.
`issuer_public` allows anyone to verify the credential (or presentation) was signed by the issuer.
`issuer` contains the secret signing keys and should be protected.

Credential Issuance
-------------------

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

Credential Revocation
---------------------
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

Revocation Handle Update
------------------------

This protocol is executed between the Holder and the Issuer roles. After publishing an updated accumulator,
the Holder’s revocation handle will be stale. The Issuer checks revocation handle claim to see if it's still in the non-revoked set. If successful, Witness generation is used to
create and return a new witness handle for the Holder.

Presentation Schema
-------------------
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

Statements
----------
CredX supports the following statement types:

1. `SignatureStatement` defines which issuer a signature must come from and which claims must be disclosed.
2. `AccumulatorSetMembershipStatement` defines a proof where the claim is a member of the set. The claim is not disclosed, only if it is a member of the set.
3. `EqualityStatement` is used to check that a non-disclosed claim is the same across multiple other statements.
4. `CommtimentStatement` creates a unique value based on a claim. Is also used to link to range statements.
5. `RangeStatement` defines a proof where a claim is in a range. Requires a commitment statement for the specified claim.
6. `VerifiableEncryptionStatement` defines a proof where a claim is proven to be encrypted in a ciphertext.

Presentation
------------

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

Acknowledgement
---------------

A special thanks to Cryptid Technologies, Inc for sponsoring and collaboration in development of this library. 

License
-------

Licensed under Apache License, Version 2.0, ([LICENSE](LICENSE) or https://www.apache.org/licenses/LICENSE-2.0)


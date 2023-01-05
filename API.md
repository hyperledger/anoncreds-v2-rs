# NodeJS

## Methods

1. [newIssuerKeys](#newissuerkeys)
2. [signCredential](#signcredential)
3. [revokeCredentials](#revokecredentials)
4. [updateRevocationHandle](#updaterevocationhandle)
5. [createBlindSignRequest](#createblindsignrequest)
6. [blindSignCredential](#blindsigncredential)
7. [createCredentialProof](#createcredentialproof)
8. [verifyCredentialProof](#verifycredentialproof)

## Objects

- [CredentialSchema](#credentialschema)
- [ClaimSchema](#claimschema)
- [ClaimValidator](#claimvalidator)
- [IssuerPublic](#issuerpublic)
- [ClaimData](#claimdata)
- [Credential](#credential)
- [BlindCredentialRequest](#blindcredentialrequest)
- [BlindCredentialBundle](#blindcredentialbundle)
- [BlindCredential](#blindcredential)
- [PresentationSchema](#presentationschema)
- [Presentation](#presentation)
- [PresentationProofs](#presentationproofs)
- [Statements](#statements)

### newIssuerKeys

Role: Issuer

Create new issuer signing keys based on the credential schema provided.

Returns the public keys and revocation registry.

**Input**
1. schema: CredentialSchema

**Output**
- issuer: IssuerPublic

Example:

Input
```json
{
  "id": "262cbfd3-c478-486e-ae0b-2641a27440e2",
  "label": "demo-schema",
  "blind_claims": [],
  "claims": [
    {
      "claim_type": "revocation",
      "label": "credential_id",
      "print_friendly": true,
      "validators": []
    },
    {
      "claim_type": "hashed",
      "label": "first_name",
      "print_friendly": true,
      "validators": [
        {
          "Length": {
            "min": 3,
            "max": 255
          }
        }
      ]
    },
    {
      "claim_type": "hashed",
      "label": "phone_number",
      "print_friendly": true,
      "validators": [
        {
          "Regex": "^(?:+)?\d-\d{3}-\d{3}-\d{4}$"
        }  
      ]
    },
    {
      "claim_type": "number",
      "label": "birthdate",
      "print_friendly": true,
      "validators": [
        {
          "Range": {
            "min": 1000,
            "max": 65535,
          }
        }
      ]
    },
    {
      "claim_type": "scalar",
      "label": "link_secret",
      "print_friendly": false,
      "validators": []
    }
  ]
}
```

Output
```json
{
  "id": "dGhpc2lzYXRlc3Rpc3N1ZXJpZA",
  "signing_key": {
    "x": "5a6a5f53890c03e4c90292d0d28099544f7c8e8b7aa39a0265eaa8df2f3c362773cbb3e3f05b1ae195a67e89ef79cdd0",    
    "w": "d2b2082ee86a4155b7a8a850143a54169cd3fd3d012996741eecddd848b354e231ced565bd23f4e3aa6cd429a74a2ac0",
    "y": [
      "6c4bf1aa345275b3cb952515a67c95a602d44fb568efeebf2721c7091bd58caebe3fde5c40bcd6b18da33ca95643fb35",
      "d6e0683b03b153153462bd10b9d1c3d7ff12beaa0ef31747afd8e52755bd68a4cfa2c6919185a95c780779b93e97e988",
      "9585dce37d960b16f003fae343a73a8a14e8f38aa8e0f119da6fa38029352ef4cb3469f0bae212e357428be1db29fc33",
      "3670f20aeabbccc4391611a634e2b9005455863fd699d68e49fd7e4f618f1ae9e2ec9f625b957af9ae4c8d8bd7c0ce6f",
      "2a568b1982dd9789af200cfde1b24be96dfe73b5e1b79a6006786cda40a73b1802ff107bad4495b2544cfe4660fe8735",
    ],
    "y_blinds": [
      "8c164e059e11f81731abd5b9dd54f74400e9d4d492121bfb",
      "c56b49a3512a1c131fcf304dcb2e4dfbddf42d513032d7a9",
      "d37f9ac8c80b2662d7d54ce9341bbddef5c911e6fe4bf6d7",
      "60241b8ce57286d77a49a139f539119b600638634d87f327",
      "b49a852ae49747805fd779dd05f5ce464ae0a2719a537199",
    ],
  },
  "revocation_key": "746869736973616f6e6574696d65737472696e67ab4b13bb35123b6",
  "verifiable_decryption_key": "616E6F7468657272616E646F6D737472696E67746861746C6F6F6B737265616C6C79636F6F6C7768656E656E636F646564",
  "revocation_registry": "6C6F7473616E646C6F74736F6672616E646F6D627974657362697473616E646F746865727374756666746861746C6F6F6B73636F6F6C",
  "schema": {
    "id": "262cbfd3-c478-486e-ae0b-2641a27440e2",
    "label": "demo-schema",
    "blind_claims": [],
    "claims": [
      {
        "claim_type": "revocation",
        "label": "credential_id",
        "print_friendly": true,
        "validators": []
      },
      {
        "claim_type": "hashed",
        "label": "first_name",
        "print_friendly": true,
        "validators": [
          {
            "Length": {
              "min": 3,
              "max": 255
            }
          }
        ]
      },
      {
        "claim_type": "hashed",
        "label": "phone_number",
        "print_friendly": true,
        "validators": [
          {
            "Regex": "^(?:+)?\d-\d{3}-\d{3}-\d{4}$"
          }
        ]
      },
      {
        "claim_type": "number",
        "label": "birthdate",
        "print_friendly": true,
        "validators": [
          {
            "Range": {
              "min": 1000,
              "max": 65535,
            }
          }
        ]
      },
      {
        "claim_type": "scalar",
        "label": "link_secret",
        "print_friendly": false,
        "validators": []
      }
    ]
  }
}
```

### signCredential

Role: Issuer

Given a list of claims and the issuer id of the keys to use, sign the claims to create a credential if the claims
meet the validators criteria.

Returns the credential

**Input**
1. issuer_id: String
2. claims: Array[[ClaimData](#claimdata)]

**Output**
- Credential

### revokeCredentials

Role: Issuer

Revoke credentials with the provided ids using the specified issuer keys.

Returns the updated revocation registry.

**Input**
1. issuer_id: String,
2. ids: Array[String]

**Output**
- revocation_registry: String

### updateRevocationHandle

Role: Issuer

After a credential has been revoked, existing but still valid credentials will
need their revocation handles updated. This method returns an updated handle provided
the revocation id hasn't been revoked.

**Input**
1. issuer_id: String,
2. id: String

**Output**
- revocation_handle: String

### createBlindSignRequest

Role: Holder or Prover

Creates a blind signing request. Returns a request that can be forwarded to an issuer

**Input**
1. issuer: IssuerPublic
2. claims: Object[String][ClaimData](#claimdata)

**Output**
- request: [BlindCredentialRequest](#blindcredentialrequest)

### blindSignCredential

Role: Issuer

Complete a blind signing request. Returns a blinded signature.

**Input**
1. issuer_id: String
2. blind_request: [BlindCredentialRequest](#blindcredentialrequest)
3. claims: Object[String][ClaimData](#claimdata)

**Output**
- bundle: [BlindCredentialBundle](#blindcredentialbundle)

### createCredentialProof

Role: Holder or Prover

Create a credential proof given a presentation schema

**Input**
1. credentials: Object[String][Credential](#credential)
2. presentation_schema: [PresentationSchema](#presentationschema)

**Output**
- presentation: [Presentation](#presentation)

### verifyCredentialProof

Role: Verifier

Verify a credential proof according to a presentation schema

**Input**
1. presentation: [Presentation](#presentation)
2. presentation_schema: [PresentationSchema](#presentationschema)
3. nonce: String

**Output**
- result: Boolean

### CredentialSchema

- **id**(required): String
  - No spaces allowed
- **label**(optional): String
  - No spaces allowed
- **description**(optional): String
- **blind_claims**(required): Array[String]
  - The claim labels that are allowed to be blindly signed
- **claims**(required): Array[[ClaimSchema](#claimschema)]

### ClaimSchema

- **claim_type**(required): String
  - Any of the following ["revocation", "hashed", "scalar", "number"]
- **label**(required): String
  - No spaces allowed. Must be unique per credential schema
- **print_friendly**(required): Boolean
- **validators**(required): Array[[ClaimValidator](#claimvalidator)]
  - 0 or more validators

### ClaimValidator

Is one of the following 

- Length: Object
  - **min**(optional): Unsigned Integer
    - Defaults to 0 if not provided
  - **max**(optional): Unsigned Integer
    - Defaults to 0xFFFF_FFFF_FFFF_FFFF if not provided
- Range: Object
  - **min**(optional): Signed Integer
    - Defaults to 0xFFFF_FFFF_FFFF_FFFF if not provided
  - **max**(optional): Signed Integer
      - Defaults to 0x7FFF_FFFF_FFFF_FFFF if not provided
- Regex: String
  - A regular expression
- Anyone: Array[[ClaimData](#claimdata)]
  - Array of fixed values

### IssuerPublic

- **id**(required): String
- **schema**(required): [CredentialSchema](#credentialschema)
- **verifying_key**(required): Object
- **revocation_verifying_key**(required): String
- **verifiable_encryption_key**(required): String
- **revocation_registry**(required): String

### ClaimData

Is one of the following

- Hashed: Object
  - **value**: Array[byte]
    - Represents an arbitrary length value to be signed like a string, image, biometric.
  - **print_friendly**: Boolean
    - Whether the claim can be printed in human readable format
- Number: Object
  - **value**: Number
    - Represents a 64-bit signed number to be signed.
- Scalar: Object
  - **value**: Array[byte]
    - Represents a cryptographic secret to be signed
- Revocation: Object
    - **value**: String
      - The revocable value to be signed

### Credential

- **claims**: Array[[ClaimData](#claimdata)]
  - The raw claims that were signed
- **signature**: Array[byte]
  - The credential signature
- **revocation_handle**: Array[byte]
  - The credential's revocation handle
- **revocation_index**: Number
  - The credential claim serving as the revocation claim


### BlindCredentialRequest

- **nonce**(required): String
- **blind_claim_labels**(required): Array[String]
- **blind_signature_context**(required): Object


### BlindCredentialBundle

- **issuer_public**(required): [IssuerPublic](#issuerpublic)
- **credential**(required): [BlindCredential](#blindcredential)


### BlindCredential

- **claims**: Array[[ClaimData](#claimdata)]
    - The raw claims that were signed
- **signature**: Array[byte]
    - The credential signature
- **revocation_handle**: Array[byte]
    - The credential's revocation handle
- **revocation_index**: Number
    - The credential claim serving as the revocation claim

### PresentationSchema

- **id**(required): String
- **statements**(required): Object[String][Statements](#statements)

### Presentation

- **proofs**(required): [PresentationProofs](#presentationproofs)
  - The cryptographic proofs
- **challenge**(required): String
  - A unique challenge proof
- **disclosed_messages**(required): Object[String]Object[String][ClaimData](#claimdata)
  - The disclosed or revealed messages by statement id and credential id


### PresentationProofs

Is one of the following

- Signature
  - **id**(required): String
  - **disclosed_messages**(required): Object[Number]String
  - **pok**(required): String
- AccumulatorSetMembership
  - **id**(required): String
  - **proof**(required): String
- Equality
  - **id**(required): String
- Commitment
  - **id**(required): String
  - **commitment**(required): String
  - **message_proof**(required): String
  - **blinder_proof**(required): String
- VerifiableEncryption
  - **id**(required): String
  - **c1**(required): String
  - **c2**(required): String
  - **message_proof**(required): String
  - **blinder_proof**(required): String
- Range
  - **id**(required): String
  - **proof**(required): String

### Statements

Is one of the following

- Signature
  - **id**(required): String
  - **disclosed**(required): Array[String]
    - The claim labels that should be disclosed or revealed
  - **issuer**(required): [IssuerPublic](#issuerpublic)
    - The Issuer public key information
- AccumulatorSetMembership
  - **id**(required): String
  - **reference_id**(required): String
    - The signature statement id
  - **accumulator**(required): String
    - The accumulator value
  - **verification_key**(required): String
  - **claim**(required): Number
    - The claim index in the signature statement
- Equality
  - **id**(required): String
  - **ref_id_claim_index**(required): Object[String]Number
    - The other statement ids and the claims to prove are equal
- Commitment
  - **id**(required): String
  - **reference_id**(required): String
      - The signature statement id
  - **message_generator**(required): String
  - **blinder_generator**(required): String
  - **claim**(required): Number
      - The claim index in the signature statement
- VerifiableEncryption
    - **id**(required): String
  - **reference_id**(required): String
      - The signature statement id
  - **message_generator**(required): String
  - **encryption_key**(required): String
  - **claim**(required): Number
      - The claim index in the signature statement
- Range
  - **id**(required): String
  - **reference_id**(required): String
    - The commitment statement id
  - **signature_id**(required): String
    - The signature statement id
  - **claim**(required): Number
    - The claim index in the signature statement
  - **lower**(optional): Number
    - The lower bound to test against if set. **lower** or **upper** or **both** can be set but at least one must be.
  - **upper**(optional): Number
    - The upper bound to test against if set. **lower** or **upper** or **both** can be set but at least one must be.

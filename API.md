# NodeJS

## Methods

1. [newIssuerKeys](#newissuerkeys)
2. [signCredential](#signcredential)
3. [revokeCredential](#revokecredential)
4. [updateRevocationHandle](#updaterevocationhandle)
5. [createBlindSignRequest](#createblindsignrequest)
6. [blindSignCredential](#blindsigncredential)
7. [createCredentialProof](#createcredentialproof)
8. [verifyCredentialProof](#verifycredentialproof)

## Objects

- [CredentialSchema](#credentialschema)
- [IssuerPublic](#issuerpublic)
- [ClaimSchema](#claimschema)
- [ClaimData](#claimdata)
- [ClaimValidator](#claimvalidator)
- [Credential](#credential)

### newIssuerKeys

**Input**
1. schema: CredentialSchema

**Output**
- issuer: IssuerPublic

### signCredential

**Input**
1. issuer_id: String
2. claims: Array[ClaimData]

**Output**
- Credential

### revokeCredential

### updateRevocationHandle

### createBlindSignRequest

### blindSignCredential

### createCredentialProof

### verifyCredentialProof

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
  - A regular expresssion
- Anyone: Array[[ClaimData](#claimdata)]
  - Array of fixed values

### IssuerPublic

- **id**(required): String
- **schema**(required): [CredentialSchema](#credentialschema)
- **verifying_key**(required): Object
- **revocation_verifying_key**(required): Array[byte]
- **verifiable_encryption_key**(required): Array[byte]
- **revocation_registry**(required): Array[byte]

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
- Enumeration
  - **dst**: String
    - A unique domain for this enumeration. Example: "United States Capitols"
  - **value**: Number
    - The index of the value in the list
  - **total_values**: Number
    - The total number of values in the list

### Credential

- **claims**: Array[[ClaimData](#claimdata)]
  - The raw claims that were signed
- **signature**: Array[byte]
  - The credential signature
- **revocation_handle**: Array[byte]
  - The credential's revocation handle
- **revocation_index**: Number
  - The credential claim serving as the revocation claim

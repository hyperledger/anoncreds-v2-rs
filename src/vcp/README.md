<!--- DO NOT EDIT.  GENERATED FROM README.org --->

# Table of Contents

1.  [Introduction](#org8baab61)
2.  [Caveats](#org66823f3)
3.  [User abstraction](#orgd741a15)
4.  [Running tests](#org977f979)
5.  [The test framework](#org9343700)
    1.  [JSON test file naming and contents](#org05e5963)
    2.  [Overview of test framework](#org84f2470)
    3.  [An example](#orgb3a606d)
    4.  [TestSteps](#org299b089)
        1.  [CreateIssuer](#orgcb83e6c)
            1.  [Effects](#org835f003)
            2.  [Arguments](#org1680fdc)
            3.  [API method(s) invoked](#org42f1ff3)
        2.  [CreateAccumulators](#orgefb0eaf)
            1.  [Effects](#org0626e5d)
            2.  [Arguments](#orga0f30c8)
            3.  [API method(s) invoked](#org51d4785)
        3.  [SignCredential](#orgad6e16b)
            1.  [Effects](#org704c81c)
            2.  [Arguments](#org09485a6)
            3.  [API method(s) invoked](#org3c6edf1)
        4.  [AccumulatorAddRemove](#orgb5e3579)
            1.  [Effects](#org84293ac)
            2.  [Arguments](#org3f8a9bc)
            3.  [API method(s) invoked](#org80013f7)
        5.  [UpdateAccumulatorWitness](#org07dc8e9)
            1.  [Effects](#orgef1230b)
            2.  [Arguments](#orge08ceae)
            3.  [Comments](#orgf31a1b1)
            4.  [API method(s) invoked](#orged8e484)
        6.  [Reveal](#org18ddeb9)
            1.  [Effects](#orgf4beeeb)
            2.  [Arguments](#org2f418af)
            3.  [API method(s) invoked](#org89a1011)
        7.  [InRange](#org26e76f5)
            1.  [Effects](#org763927e)
            2.  [Arguments](#orgbe627de)
            3.  [Comments](#org517fc45)
            4.  [API method(s) invoked](#org81a7bbc)
        8.  [InAccum](#org0113f8a)
            1.  [Effects](#org1bbf707)
            2.  [Arguments](#org02f638c)
            3.  [API method(s) invoked](#org712e212)
        9.  [Equality](#org1020ea5)
            1.  [Effects](#org18079fc)
            2.  [Arguments](#orgbb4dddc)
            3.  [Comments](#org141034b)
            4.  [API method(s) invoked](#org2359f9a)
        10. [CreateAndVerifyProof](#org036b498)
            1.  [Effects](#org5a79a0f)
            2.  [Arguments](#org267f07f)
            3.  [API method(s) invoked](#org6c2dcdd)
        11. [CreateAuthority](#org802d95b)
            1.  [Arguments](#org2e89c71)
            2.  [API method(s) invoked](#orgce987ce)
        12. [EncryptFor](#orgc173bd7)
            1.  [Effects](#orgf47fde2)
            2.  [Arguments](#orge41524d)
            3.  [API method(s) invoked](#org23cef87)
        13. [Decrypt](#orgf3b5ed1)
            1.  [Effects](#org07d2ec3)
            2.  [Arguments](#org090376c)
            3.  [API method(s) invoked](#org7686eac)
        14. [VerifyDecryption](#orgab5eae8)
            1.  [Effects](#org400e7e3)
            2.  [Arguments](#org0684d5e)
            3.  [API method(s) invoked](#orgd7fa00d)
    5.  [Overriding tests](#org59490a8)
    6.  [Test framework files](#org82e34ea)
6.  [The VCP architecture](#org3a2ac70)
    1.  [General](#org4a08daf)
    2.  [Specific](#orgf9ac069)
7.  [Guide to `src/vcp` code](#orgeaaa7a2)
    1.  [Directory structure](#org67d11d1)
    2.  [Example of connecting a specific ZKP library to `PlatformApi`](#orgebca771)
    3.  [Creating an Issuer's public and secret data (e.g., keys)](#orgeede47c)
    4.  [Issuer signing a credential](#org8e5d63a)
    5.  [Creating a proof](#org91f8034)
    6.  [Verifying a proof](#org47b9094)
    7.  [Proofs with revealed values](#orgd379f23)
    8.  [Proofs with range proofs](#org0c5f4ac)
    9.  [Proofs with verifiable encryption](#org6fb487c)
    10. [Proofs with equalities between attributes](#orga7e495f)
    11. [Proofs with accumulators](#org1f53a37)
    12. [Accumulator functions](#org8c7cbc6)



<a id="org8baab61"></a>

# Introduction

This directory contains work towards defining and implementing an abstraction to decouple verifiable
credential formats and presentation/proof requests on one hand from underlying zero-knowledge proof (ZKP)
libraries on the other.  Test code related to this work, including the test framework described
below, is under the [tests/vcp/test_framework](../../tests/vcp/test_framework/) directory.

We have instantiated our abstraction with two underlying ZKP libraries

-   the ZKP library that is part of the [AnonCreds v2](https://github.com/hyperledger/anoncreds-v2-rs) repo
    -   referred to as AC2C in order to distinguish it from the broader project
-   the ZKP library that is part of the [DockNetwork crypto](https://github.com/docknetwork/crypto/) repo
    -   referred to as DNC

The information below is intended to help the reader approach this code after gaining some
familiarity with the work by reviewing the [slides](https://www.dropbox.com/preview/Presentations/IIW%20Oct%202024%20-%20VC%20and%20ZPK%20abstraction.pdf) that we presented at
[IIW](https://internetidentityworkshop.com) in October, 2024.

This work is by [Harold Carr](https://github.com/haroldcarr) and [Mark Moir](https://github.com/mark-moir) of Oracle Labs, and [Henry Blanchette](https://github.com/rybla)
of the University of Maryland at College Park, during his Summer 2024 internship at Oracle Labs.


<a id="org66823f3"></a>

# Caveats

This is research work in progress aimed at exploring and demonstrating the benefits and feasibility
of establishing an abstraction between credential formats and cryptography/ZKP libraries.  This work
should in no way be considered for use in production or for any purpose other than engaging in such
exploration.  In particular,

-   This Rust work has been contributed by three different developers with different levels of
    experience and expertise in the relevant languages and knowledge about the domain and details of
    the internal Haskell prototype on which it is based.
-   Some code was written by an intern who is experienced in Rust, and some was written by his Oracle
    Labs mentors at different times during their Rust learning process.  Therefore, different styles,
    tastes, and levels of expertise are evident in different parts of the code.  While we have made
    progress towards more consistent styles throughout, this is not complete.
-   There are quite a few TODOs, potentially including some that would undermine security if left
    undone before this code were used in a practical application.
-   While we hope to eventually contribute to [Hyperledger AnonCreds, v2](https://github.com/hyperledger/anoncreds-v2-rs) based on this work, we are not
    raising a Pull Request at this stage. Rather, we have made this work public in order to facilitate
    feedback and engagement towards something that we can offer as a contribution.


<a id="orgd741a15"></a>

# User abstraction

From an application/user perspective, our abstraction is defined by the
`PlatformAPI` type in [./api.rs](./api.rs). There are several possible ways to access it:

-   By using the `implement_platform_api_using` function in [./api_utils.rs](./api_utils.rs) and providing an instance of
    `CryptoInterface`, such as `CRYPTO_INTERFACE_AC2C` (defined in [./zkp_backends/ac2c/crypto_interface.rs](./zkp_backends/ac2c/crypto_interface.rs)) and calling
    its methods directly.  See [7.3](#orgb6020b6) for more details.
-   By accessing the functionality via a Swagger/OpenAPI interface. We have built an HTTP/REST
    server serving such an interface.  See [../../server/README.org](../../server/README.org).
-   Via our test framework, described below.  We recommend this approach as the easiest way to get
    started gaining some familiarity with our interface because, as detailed below, the test framework
    handles a lot of common setup tasks and manages data for all roles, which a user would otherwise
    have to do explicitly.  In the sections below, we first describe the test framework and how tests can be
    added without any programming. We then explain how those tests connect to the API and to the
    underlying implementation.

We note that there are a number of additional tests, beyond those that use the test framework.  These
are less general, more historic, less well organised, etc.  We recommend focusing on the JSON tests
that are run by the test framework.


<a id="org977f979"></a>

# Running tests

We have added a number of tests, many of which are expressed in JSON.  More such tests can be added
simply by adding JSON files, with no programming required.  The test framework that enables this is
described in the next section.

The [../../Makefile](../../Makefile) supports a number of `make` targets for running/skipping tests according to various
criteria.  The two most important are `make test` and `make test-all`.  The former skips tests that are
overridden to fail (see Section [5.4.14.3](#org27b3cb4)), so that unexpected failures are not masked by
those tests.  The latter runs these tests as well, so that the failures can be seen.


<a id="org9343700"></a>

# The test framework

The goal of our test framework is to enable easily specifying a sequence of actions that exercise
the API and test its behavior in various scenarios.  Tests are expressed in JSON and automatically
run by our framework.  A new JSON test can be added to
[../../tests/data/JSON/TestSequences/LicenseSubscription](../../tests/data/JSON/TestSequences/LicenseSubscription), where there are a number of examples
already. Tests are generated at compile time from these JSON files. Therefore, after adding a new
test it is necessary to ensure recompilation, using these steps, for example:

    cd <root of this repo>
    touch tests/data/JSON/TestSequences/LicenseSubscription/*.json  # It is *not* sufficient to touch only the new test
    make test


<a id="org05e5963"></a>

## JSON test file naming and contents

JSON test files contain the following fields:

-   `descr` - a short description of the test
-   `provenance` - information to enable finding where the test came from, how it was generated, etc.
-   `comment` (optional) - a comment about the test
-   `testseq` - an array of `TestStep`, see below

The filename for the JSON test must be `json_test_nnn_<str>` for some three-digit `nnn`, where `str`
must be identical to the contents of its `descr` field.

Including `expected_to_fail` in the test's `descr` field (and therefore in its filename) "reverses" the
test, so that if the test (at the level of the test framework) <span class="underline">succeeds</span>, then the test is reported
as a failure, and vice versa.  (Note that we sometimes include `negative_test` in a test name.  This
has no bearing on whether and how the test is run: it is merely a <span class="underline">convention</span> to indicate that this
test is using the API differently than intended.)

In addition to running all tests using `make test`, an individual test can be run using its `descr` field.  For example,
to run only the test described in the next section:

    cd <root of this repo>
    cargo test example_single_issuer_and_credential_in_accum_no_update


<a id="org84f2470"></a>

## Overview of test framework

The test framework maintains state representing all data of all roles (Issuers, Holders,
Authorities, and Revocation Managers. It is assumed that there is a single, unnamed verifier). (This
is represented in the `TestState` data type in
[../../tests/vcp/test_framework/types.rs](../../tests/vcp/test_framework/types.rs)).

Each `TestStep` updates the state and/or checks whether some condition holds in that state.  The
implementation of each `TestStep` invokes one or more methods in the API as noted in the description
for each `TestStep` below. For convenience and ease of use, some `TestSteps` model multiple real world
events. For example, the `Sign` step models an Issuer signing a credential, sending the signature to
the requesting Holder, the Holder receiving the signature and storing it locally.

We make the simplifying assumption that each Holder can possess at most one credential signed by
each Issuer. This enables referring to credentials by the label of the Issuer that signed them.


<a id="orgb3a606d"></a>

## An example

Before describing each `TestStep` in detail, we first walk through the example in
[../../tests/data/JSON/TestSequences/LicenseSubscription/json_test_028_example_single_issuer_and_credential_in_accum_no_update.json](../../tests/data/JSON/TestSequences/LicenseSubscription/json_test_028_example_single_issuer_and_credential_in_accum_no_update.json)
(from [our IIW presentation](https://www.dropbox.com/preview/Presentations/IIW%20Oct%202024%20-%20VC%20and%20ZPK%20abstraction.pdf)).

Each `TestStep` in the JSON file has a `tag` field that identifies the kind of step, and a `contents`
field that provides its arguments.

The first step in our example is a `CreateIssuer` step, which establishes an Issuer (for signing credentials)
identified by the label given in the first argument, for a schema defined in the second.  In the example, we
create an Issuer with label `DMV` and a schema with five attributes, the last of which is an
accumulator member (`CTAccumulatorMember`), meaning that it is a field that will be used for set
membership (e.g., for revocation).

The second (`CreateAccumulators)` step creates and initializes an accumulator for each
`CTAccumulatorMember` field in the schema (only one in our example). `CreateAccumulators` is an
example of a utility function that uses, but is not directly supported by `PlatformAPI`; see comments
in [../../tests/vcp/test_framework/utility_functions.rs](../../tests/vcp/test_framework/utility_functions.rs).

The third (`SignCredential`) step, Issuer `DMV`, signs a credential for `Holder1`, specifying values for each of
the five attributes indicated by the schema specified when the `DMV` Issuer was created.

The fourth step (`AccumulatorAddRemove`) adds a "batch" of accumulator members (consisting of only
`Holder1`'s accumulator member in this case) to the accumulator associated with attribute 4 for `DMV`,
and also removes a "batch" of accumulator members (which is empty in this case).  Furthermore, for
each accumulator member added to the accumulator, a new `AccumulatorMembershipWitness` is created and associated with the
specified Holder's credential for the specified Issuer (if the specified Issuer has not been
created, or if no credential has been signed by that Issuer for a specified Holder, then an error
will be generated).  At this stage, because one batch has been applied to the accumulator since it
was created, the new witness is valid for `BatchSeqNo` `1`, which will be important when we
come to request proving membership in the accumulator (see the `InAccum` step below).

The fifth step (`Reveal`) says that `Holder1` should reveal attributes `0` and `3` from its credential signed
by `DMV`. Note that this is simply adding to the requirements that will be used when
creating a proof later.

Similarly, the sixth step (`InAccum`) says that `Holder1` should prove that its accumulator member is a
member of the accumulator associated with attribute `4` at `BatchSeqNo` `1`.

Finally, the seventh step (`CreateAndVerifyProof`) attempts to create a proof satisfying all of the
requirements established for `Holder1` so far in the test, and to then verify that proof. The
`TestExpectation` is specified to be `BothSucceedNoWarning`. Therefore, the test will fail if either
creating or verifying the proof fails or issues a warning.  Apart from checking that a proof can be
created and verified, the `CreateAndVerifyProof` step verifies that the revealed attributes are the same
as the one signed in the relevant credential, and (in examples involving decryption) that the
decrypted values match the original signed values.


<a id="org299b089"></a>

## TestSteps


<a id="orgcb83e6c"></a>

### CreateIssuer


<a id="org835f003"></a>

#### Effects

-   Creates new Issuer with associated `SignerData`


<a id="org1680fdc"></a>

#### Arguments

-   `IssuerLabel`: label to identify new Issuer
-   `[ ClaimType ]`: schema for new Issuer


<a id="org42f1ff3"></a>

#### API method(s) invoked

-   `create_signer_data`


<a id="orgefb0eaf"></a>

### CreateAccumulators


<a id="org0626e5d"></a>

#### Effects

-   Creates `AccumulatorData` for each `CTAccumulatorMember` attribute in specified Issuer's schema


<a id="orga0f30c8"></a>

#### Arguments

-   `IssuerLabel`


<a id="org51d4785"></a>

#### API method(s) invoked

-   `create_accumulator_data` (once for each created accumulator)


<a id="orgad6e16b"></a>

### SignCredential


<a id="org704c81c"></a>

#### Effects

-   Creates new credential (`SignatureAndRelatedData`) signed by specified Issuer with specified
    `DataValue` s for specified `Holder` ("related data" includes `DataValue` s signed and an empty map
    that will be used to store `AccumulatorMembershipWitness` es when they are created by an
    `AccumulatorAddRemove` step).  If the fourth argument is provided, the value of the identified
    attribute is replaced by the maximum value for which a range proof can be supported by the
    underlying ZKP library, plus the identified offset.


<a id="org09485a6"></a>

#### Arguments

-   `IssuerLabel`: label identifying previously created Issuer
-   `HolderLabel`: label identifying Holder
-   `[ DataValue ]`: list of values to be signed, one for each attribute of Issuer's schema
-   `Option<ReplaceValueWithMaximumPlus>`: if provided, identifies an attribute index
    `attrIdxToReplaceWithMaxSupported` and an offset `plusOffset`.  Argument used only for
    testing that the underlying ZKP library's `get_range_proof_max_value` API function returns an
    accurate value.


<a id="org3c6edf1"></a>

#### API method(s) invoked

-   `sign`


<a id="orgb5e3579"></a>

### AccumulatorAddRemove


<a id="org84293ac"></a>

#### Effects

-   Add some `DataValue` s to and remove some `DataValue` s from accumulator associated with specified
    Issuer and attribute.
-   Each `DataValue` added generates an `AccumulatorMembershipWitness` for the new accumulator value,
    which is stored in the `SignatureAndRelatedData` associated with specified Holder and the
    `AccumlatorBatchSeqNo` of this batch of additions and removals.  This information can be used by
    subsequent `UpdateAccumulatorWitness` and `CreateAndVerify` steps.
-   Stores "update information" associated with updating `Accumulatormembershipwitness` es
    from previous `AccumulatorBatchSeqNo` to new one,for use by subsequent `UpdateAccumulatorWitness` steps


<a id="org3f8a9bc"></a>

#### Arguments

-   `IssuerLabel`
-   `CredAttrIndex`: attribute index identifying relevant accumulator associated with specified Issuer
-   `Map HolderLabel DataValue`: `DataValue` s to be added to specified accumulator and Holders to
    receive respective generated witnesses
-   `[ DataValue ]`: `DataValue` s to be removed from specified accumulator


<a id="org80013f7"></a>

#### API method(s) invoked

-   `accumulator_add_remove`


<a id="org07dc8e9"></a>

### UpdateAccumulatorWitness


<a id="orgef1230b"></a>

#### Effects

-   Attempts to ensure that specified Holder has an `AccumulatorMembershipWitness` for accumulator
    identified by specified Issuer and attribute index.
-   This is possible only if
    -   a) specified Holder already has an `AccumulatorMembershipWitness` for identified accumulator for
        an `AccumulatorBatchSeqNo` that is at most the target `AccumulatorBatchSeqNo`, and
    -   b) there have been sufficient `AccumulatorAddRemove` steps performed that "update information"
        has been stored to enable updating to specified `AccumulatorBatchSeqNo`.
-   An error is generated if these conditions do not hold.
-   When successful, generates and stores `AccumulatorMembershipWitness` for each `AccumlatorBatchSeqNo`
    between the largest `AccumlatorBatchSeqNo` less than the target `AccumulatorBatchSeqNo` for which
    specified Holder already has an `AccumulatorMembershipWitness`.


<a id="orge08ceae"></a>

#### Arguments

-   `HolderLabel`
-   `IssuerLabel`
-   `CredAttrIndex`
-   `AccumulatorBatchSeqNo`: target `AccumulatorBatchSeqNo` to ensure specified Holder


<a id="orgf31a1b1"></a>

#### Comments

-   Currently, a Holder will always have an `AccumulatorMembershipWitness` for every
    `AccumlatorBatchSeqNo` from the one at which its `AccumulatorMembershipWitness` was added and the
    highest `AccumlatorBatchSeqNo` to which it has ever updated.
-   In practice, Holders would likely
    discard `AccumulatorMembershipWitness` es considered "too old".  The test framework does not
    currently support such "garbage collection".
-   If it did, Holders could always regenerate discarded `AccumulatorMembershipWitness` es **provided**
    they retain one with `AccumlatorBatchSeqNo` at or before any future target.  If not, they would
    have to request a new `AccumulatorMembershipWitness` from the relevant Revocation Manager; the test
    framework also does not currently support this.


<a id="orged8e484"></a>

#### API method(s) invoked

-   `update_accumulator_witness`, potentially multiple times as described above


<a id="org18ddeb9"></a>

### Reveal


<a id="orgf4beeeb"></a>

#### Effects

-   adds to requirements for subsequent `CreateAndVerifyProof` steps for specified Holder,
    requiring that it reveals attributes with specified indexes from its credential
    signed by specified Issuer
-   generates error if:
    -   specified Holder or Issuer does not exist, or
    -   no credential has been signed for specified Holder by specified Issuer, or
    -   any of specified attribute indexes is out of range established by Issuer's schema


<a id="org2f418af"></a>

#### Arguments

-   `HolderLabel`
-   `IssuerLabel`
-   `[ CredAttrIndex ]`: list of indexes for attributes to be revealed


<a id="org89a1011"></a>

#### API method(s) invoked

-   none


<a id="org26e76f5"></a>

### InRange


<a id="org763927e"></a>

#### Effects

-   adds to requirements for subsequent `CreateAndVerifyProof` steps for specified Holder,
    requiring that it proves that specified attribute in a credential signed by specified Issuer
    for specified Holder is within range specified by minimum and maximum values
-   note that there is no step for creating a `RangeProvingKey` because one is automatically
    created when an `InRange` step is first encountered, and the same one is used for any subsequent
    `InRange` requirements
-   If the sixth argument is provided, the range's upper bound is replaced by the specified offset plus
    the maximum value for which range proofs are supported by the underlying ZKP libary, as determined by
    calling its `get_range_proof_max_value` API function.


<a id="orgbe627de"></a>

#### Arguments

-   `HolderLabel`
-   `IssuerLabel`
-   `CredAttrIndex`
-   `i64`: the minimum value in the range
-   `i64`: the maximum value in the range
-   `Option<ReplaceUpperBoundWithMaxSupportedPlusOffset>`: if provided, specifies a replacement value
    for the range's upper bound in terms of an offset from the maximum value for which range proofs
    are supported by the underlying ZKP libary.  Argument used only for testing that the
    underlying ZKP library's `get_range_proof_max_value` API function returns an accurate value.


<a id="org517fc45"></a>

#### Comments

-   Step does **not** generate an error if specified attribute is out of range, because we want to be
    able to test that `CreateAndVerifyProof` does not succeed in this case


<a id="org81a7bbc"></a>

#### API method(s) invoked

-   none


<a id="org0113f8a"></a>

### InAccum


<a id="org1bbf707"></a>

#### Effects

-   adds to requirements for subsequent `CreateAndVerifyProof` steps for specified Holder,
    requiring that it proves that specified attribute in a credential signed by specified Issuer
    for specified Holder is in the accumulator associated with specified Issuer and CredAttrIndex,
    as of specified `AccumulatorBatchSeqNo`


<a id="org02f638c"></a>

#### Arguments

-   `HolderLabel`
-   `IssuerLabel`
-   `CredAttrIndex`
-   `AccumulatorBatchSeqNo`: the "batch number" for which the proof is required; enables requiring
    proof of membership in accumulator for older or newer accumulator versions


<a id="org712e212"></a>

#### API method(s) invoked

-   none


<a id="org1020ea5"></a>

### Equality


<a id="org18079fc"></a>

#### Effects

-   adds to requirements for subsequent `CreateAndVerifyProof` steps for specified Holder,
    requiring that it proves that specified attribute in a credential signed by specified Issuer is
    equal to each attribute specified in each "other" credentials (identified by specified Issuer)


<a id="orgbb4dddc"></a>

#### Arguments

-   `HolderLabel`
-   `IssuerLabel`: identifies Issuer who signed a credential
-   `CredAttrIndex`: identifies an attribute in that credential
-   `[(IssuerLabel, CredAttrIndex)]`: a list of attributes in other credentials required to be equal
    to specified attribute


<a id="org141034b"></a>

#### Comments

-   It would have been cleaner to specify the equivalence class of `(Issuer,CredAttrIndex)` pairs,
    rather than singling on of them out
-   Step does **not** generate an error if specified attributes are not equal, because we want to be
    able to test that `CreateAndVerifyProof` does not succeed in this case


<a id="org2359f9a"></a>

#### API method(s) invoked

-   none


<a id="org036b498"></a>

### CreateAndVerifyProof


<a id="org5a79a0f"></a>

#### Effects

-   Attempts to create and then verify a proof satisfying all requirements added previously for
    specified Holder, and checks that the outcome is consistent with specified `CreateVerifyExpectation`.
-   An error is generated if specified Holder cannot satisfy previously added requirements because,
    for example, specified Holder does not have a credential signed by an Issuer for a previously
    added requirement, does not have an `AccumulatorMembershipWitness` for a required
    `AccumlatorBatchSeqNo`, etc.
-   note that, if previous steps include `Decrypt` requirements for specified Holder, subsequent
    `CreateAndVerifyProof` steps model an `Authority` verifying a proof created by specified Holder,
    rather than a generic Verifier; this is because the decryption requires `AuthoritySecretData` for
    each attribute to be decrypted.  If there are decryption requirements for multiple Authorities,
    the step models Verifier having `AuthoritySecretData` for all of them.  While this is not
    particularly realistic, it is useful for testing generality.


<a id="org267f07f"></a>

#### Arguments

-   `HolderLabel`
-   `CreateVerifyExpectation`: expected outcome for attempt to create and then verify a proof
    consistent with established requirement.  Possible values are currently:
    -   `BothSucceedNoWarnings`: expects both proof creation and proof verification to succeed and
        issue no warnings.  In this case, revealed and decrypted values are checked to ensure that
        they are for exactly the requested attributes and furthermore that the values are equal to
        those signed in specified credentials.
    -   `CreateProofFails`: requires that proof creation fails
    -   `VerifyProofFails`: requires that proof creation succeeds and then verification fails
    -   `CreateOrVerifyFails`: requires that, either proof creation fails, or it succeeds but
        verification of the generated proof fails.  This expectation is sometimes useful when it is
        required that a proof is not successfully created and then verified, but it does not matter
        which step fails.  In some cases, some underlying ZKP libraries fail to generate a
        proof, while others generate a proof that does not verify successfully.  This
        `CreateVerifyExpectation` is useful in such cases.


<a id="org6c2dcdd"></a>

#### API method(s) invoked

-   `create_proof`
-   `verify_proof`


<a id="org802d95b"></a>

### CreateAuthority

-   Creates new Authority with associated `AuthorityData`


<a id="org2e89c71"></a>

#### Arguments

-   `AuthorityLabel`: label to identify new Authority


<a id="orgce987ce"></a>

#### API method(s) invoked

-   `create_authority_data`


<a id="orgc173bd7"></a>

### EncryptFor


<a id="orgf47fde2"></a>

#### Effects

-   adds to requirements for subsequent `CreateAndVerifyProof` steps for specified Holder,
    requiring that it encrypts (for specified Authority) specified attribute from credential
    signed by specified Issuer


<a id="orge41524d"></a>

#### Arguments

-   `HolderLabel`
-   `IssuerLabel`
-   `CredAttrIndex`:
-   `AuthorityLabel`: label identifying `Authority` for whom specified attribute is to be encrypted


<a id="org23cef87"></a>

#### API method(s) invoked

-   none


<a id="orgf3b5ed1"></a>

### Decrypt


<a id="org07d2ec3"></a>

#### Effects

-   adds to requirements for subsequent `CreateAndVerifyProof` steps for specified Holder,
    requiring that specified attribute from credential signed by specified Issuer is decrypted


<a id="org090376c"></a>

#### Arguments

-   `HolderLabel`
-   `IssuerLabel`
-   `CredAttrIndex`
-   `AuthorityLabel`: label identifying `Authority` to decrypt specified attribute


<a id="org7686eac"></a>

#### API method(s) invoked

-   none


<a id="orgab5eae8"></a>

### VerifyDecryption


<a id="org400e7e3"></a>

#### Effects

-   Verifies correct decryption for each `DecryptResponse` generated by most recent `CreateAndProof`
    step by specified Holder


<a id="org0684d5e"></a>

#### Arguments

-   `HolderLabel`


<a id="orgd7fa00d"></a>

#### API method(s) invoked

-   `verify_decryption`

<a id="org27b3cb4"></a>


<a id="org59490a8"></a>

## Overriding tests

Sometimes we want finer control over how specific tests are treated in combination with specific
underlying ZKP libraries.  This is supported by a per-library overrides file.  Thus, we have
on overrides file for each underlying library currently used:

-   [../../tests/data/JSON/TestSequences/LicenseSubscription/LibrarySpecificOverrides/AC2C.json](../../tests/data/JSON/TestSequences/LicenseSubscription/LibrarySpecificOverrides/AC2C.json)
-   [../../tests/data/JSON/TestSequences/LicenseSubscription/LibrarySpecificOverrides/DNC.json](../../tests/data/JSON/TestSequences/LicenseSubscription/LibrarySpecificOverrides/AC2C.json)

Each entry in these overrides file has:

-   a lookup label based on the test's `descr` field (see documentation in
    [../../generate-tests-from-json/src/lib.rs](../../generate-tests-from-json/src/lib.rs) for details)
-   an associated `contents` field, which explains the reason for the override
-   an associated `tag`, which determines whether the test is run and/or how its outcome is reflected in
    output.  Currently, possible values for the `tag` are `NotSoSlow`, `Fail` and `Skip`, as explained below

For a given test with a given underlying ZKP library, it could be that:

-   `NotSoSlow`: although the test has SLOW or SLOWSLOW in its name, we know that it is `NotSoSlow` with the specific
    underlying library, so we want to run it even when using, e.g., \`make test-skip-slow\` to skip slow
    tests.  The test is run, even if skipping tests with `SLOW` in their name (see below for examples).
-   `Fail`: the test is considered to `Fail`, e.g., because of a known bug in the ZKP library or
    because it does not yet support the functionality being tested.  It is reported as a failure in test output.
-   `Skip`: we want to `Skip` the test for some reason.  Such tests are shown in test output as `ignored`, displaying
    the reason from the overrides file, and are counted as ignored in test summaries.  An example
    is that the underlying ZKP library has some known issue that causes a panic or test failure,
    but we don't want to see it reported as a failure, e.g., because the issue is understood and will
    be addressed in future work, or because the issue is not related to the main purpose of the test.
    An example of the latter is if the underlying ZKP library panics when incorrectly used,
    and the purpose of the test is only to ensure that it does not enable a prover to create a proof
    that a verifier successfully verifies.

If tests are run directly using `cargo test`, then these tests that are overridden to `Fail` are
reported as failures.  To avoid confusion, such tests have `_overridden_to_fail` appended to their
names.  Furthermore, if running tests using any of:

-   `make test`,
-   `make test-skip-slow`, or
-   `make test-skip-slow-slow`

the `Makefile` is configured to exclude tests with `_overridden_to_fail` in their names, so overridden
tests are not reported as failures.

We would like to improve the override system.  In the meantime, it is documented in
[../../generate-tests-from-json/src/lib.rs](../../generate-tests-from-json/src/lib.rs).


<a id="org82e34ea"></a>

## Test framework files

Located in [../../tests/vcp/](../../tests/vcp/):

    data_for_tests.rs
    test_framework
        steps.rs                                : The main file of the testing framework.
                                                  Defines the TestSteps.
        tests
            framework_tests.rs                  : Rust code that tests the framework itself
    
        types.rs                                : types used by the test framework, in particular TestState
    
        utility_functions.rs                    : useful routines to compose common operations
        utils.rs
    
    zkp_backends
        ac2c
            run_json_test_framework_tests.rs    : Test the framework itself
                                                  with CryptoInterface instantiated with AC2C
                                                  using JSON tests located in
                                                  ./tests/data/JSON/TestSequences/TestingFramework
    
            run_json_zkp_functionality_tests.rs : Instantiates CryptoInterface with AC2C and runs the JSON tests located in
                                                  ./tests/data/JSON/TestSequences/LicenseSubscription
                                                  with overrides defined in
                                                 ./tests/data/JSON/TestSequences/LicenseSubscription/LibrarySpecificOverrides/AC2C.json
    
            run_zkp_functionality_tests.rs      : Instantiates CryptoInterface with AC2C and runs the tests
                                                  defined in zkp_functionality_tests/test_definitions.rs
        dnc
            run_json_test_framework_tests.rs    : Test the framework itself
                                                  with CryptoInterface instantiated with DNC
                                                  using JSON tests located in
                                                  ./tests/data/JSON/TestSequences/TestingFramework
    
            run_json_zkp_functionality_tests.rs : Instantiates CryptoInterface with DNC and runs the JSON tests located in
                                                  ./tests/data/JSON/TestSequences/LicenseSubscription
                                                  with overrides defined in
                                                 ./tests/data/JSON/TestSequences/LicenseSubscription/LibrarySpecificOverrides/DNC.json
    
    zkp_functionality_tests
        test_definitions.rs                     : ZKP functionality tests written in Rust (rather than JSON).

Note: the other tests located in [tests/vcp](../../tests/vcp) (various unit tests) can be ignored.


<a id="org3a2ac70"></a>

# The VCP architecture

The following diagram gives a high-level view of the VCP architecture.
It is shown using AC2C.  For DNC, the GENERAL part is identical but the DNC SPECIFIC part
has different paths (but essentially does the same work, additionally providing
\`specific_verify_decryption\`, which is not yet supported by AC2C).

                             SigsAnd         Credential       Shared    DataForVerifier DecryptReqs
                           RelatedData          Reqs  -->+<-- Params              |      |
                                |                        |                        |      |
                                |   +--------------------+--------------------+   |      |
                                v   v                                         v   v      v
                              create_proof                                    verify_proof          ----+
                                |   |                                         |   |      |              |
                                |   +-----> presentation_request_setup <------+   |      |              | GENERAL
                                |                        |                        |      |              |
                                |                        v                        |      |              |
                                |           resolved_proof_instructions           |      |              |
                                |                       and                       |      |              |
                                |              equality_requirements              |      |              |
                                |                        |                        |      |          ----+
                                |           +------------+----------+             |      |
                                v           v                       v             v      v
                         specific_prover_ac2c                       specific_verifier_ac2c          ----+
                                |           |                       |             |      |              |
                                |           +------------+----------+             |      |              |
                                v                        |                        |      |              |
    presentation_credentials_from                        |                        |      |              | SPECIFIC
                                |                        v                        |      x              |
                                +----------> presentation_schema_from <-----------+      x              |
                                |                                                 |      x              |
                                v                                                 v      x              |
                      Presentation::create                              Presentation::verify        ----+
                                |                                                 |
                                v                                                 v
                        DataForVerifier                                    DecryptResponse(s)

VCP is comprised of three main parts

-   API (defined by the `PlatformAPI` type in [./api.rs](./api.rs))
    -   functions available for various roles (e.g., Issuer, Holder, Verifier, &#x2026;)
-   general
    -   implementations of API functions that operate regardless of the underlying ZKP library
-   specific
    -   functions called from general that implement "primitive" features (e.g., sign, prove,
        verify) for a specific underlying ZKP library


<a id="org4a08daf"></a>

## General

A proof is created from

-   `SignatureAndRelatedData` : signature from an Issuer on a list of `DataValue`

-   `CredentialReqs` : the requirements for each credential
    (e.g., values in range, what values should be revealed, &#x2026;)
-   Shared Params : the values referenced from `CredentialReqs`

A proof is verified from

-   `CredentialReqs` and shared params
-   `DataForVerifier` : includes disclosed values and a proof (created by `create_proof`)
-   `DecryptReqs` : verifiable decryption requests

Both the general `create_proof` and `verify_proof` call `presentation_request_setup`.
That function transforms shared parameters and human-friendly `CredentialReqs` into machine-friendly
`resolved_proof_instructions` and `equality_requirements`.

Both the general `create_proof` and `verify_proof` then pass that info to "specific" versions of
create and verify.  The AC2C versions are shown in the above diagram.


<a id="orgf9ac069"></a>

## Specific

`specific_prover_ac2c` turns `SignatureAndRelatedData` into `anoncreds-v2-rs` "credentials"
(via `presentation_credentials_from`).

Both `specific_prover_ac2c` and `specific_verifier_ac2c` call `presentation_schema_from`
with `resolved_proof_instructions` and `equality_requirements` to create an
`anoncreds-v2-rs` presentation schema.

`specific_prover_ac2c` uses the `anoncreds-v2-rs` credentials and presentation schema to create a proof.
That proof is then converted to an opaque `Proof` and included in the `DataForVerifier` API type,
along with disclosed values.

`specific_verifier_ac2c` uses the `DataForVerifier` and the `anoncreds-v2-rs` presentation schema
to verify the proof.


<a id="orgeaaa7a2"></a>

# Guide to `src/vcp` code


<a id="org67d11d1"></a>

## Directory structure

VCP code resides in the [../../src/vcp/](../../src/vcp/) directory.

The top level directory contains:

    api.rs                                    : the main top-level PlatformApi
    
    api_utils.rs                              : connects a specific CryptoInterface to the PlatformApi

The directory structure for the interfaces used by `PlatformApi` is:

    interfaces
        crypto_interface.rs               : function types that a specific ZKP library must implement
    
        non_primitives.rs                 : function types for functions provided by VCP
        primitives
            types.rs                      : data declarations for data used by CryptoInterface functions
    
        primitives.rs                     : function types for the functions in CryptoInterface
    
        types.rs                          : data declarations for data used in PlatformApi and CryptoInterface

The directory structure for the "general" implementation is:

    impl
        catch_unwind_util.rs
        general
            presentation_request_setup.rs : translates proof requests to proof instructions and equality requirements
    
            proof.rs                      : general create_proof, verify_proof and verify_decryption functions
                                            that call specific ZKP library implementations of primitives
        json
            shared_params.rs              : utilities for working with shared parameters
            util.rs
        to_from_api.rs                    : definitions of functions to convert between API types and
                                            specific ZKP library implementation types
    
        types.rs                          : data declarations available for any specific implementation to use
        util.rs

The directory structure for the AC2C implementation of `CryptoInterface` is:

    zkp_backends
        ac2c
            accumulators.rs               : AC2C VB implementation of CryptoInterface accumulator primitives
    
            authority.rs                  : AC2C implementation of CryptoInterface authority primitives
    
            crypto_interface_ac2c.rs      : Provides the AC2C implementation of CryptoInterface
    
            presentation_request_setup.rs : Functions in this file are used by the following proof.rs file.
                                            Generate AC2C proof statements and equality statements
                                            from proof instructions (derived from proof requirements).
                                            Also, generate AC2C PresentationCredentials from signatures and witnesses
    
            proof.rs                      : AC2C implementations of specific_create_proof,
                                            specific_verify_proof functions (and in future, specific_verify_decryption,
                                            when AC2C supports it)
    
            range_proof.rs                : AC2C implementation of range proof operations
    
            signer.rs                     : AC2C implementations of "signer" (a.k.a Issuer)
                                            primitive functions (e.g., create keys, sign)
    
            to_from_api/*                 : functions to convert between API data types and AC2C data types

The directory structure for the DNC implementation of `CryptoInterface` is:

    zkp_backends
        dnc
            accumulators.rs               : DNC VB implementation of CryptoInterface accumulator primitives
    
            authority.rs                  : DNC implementation of CryptoInterface authority primitives
    
            crypto_interface_dnc.rs       : Provides the AC2C implementation of CryptoInterface
    
            generate_frs.rs               : Turns user values to be signed into "FR"s (i.e., field elements)
    
            in_memory_state.rs            : A non-production-ready "database" to hold state
                                            associated with an accumulator
    
            proof.rs                      : DNC implementations of specific_create_proof,
                                            specific_verify_proof and specific_verify_decryption functions
    
            range_proof.rs                : DNC implementation of range proof operations
    
            reversible_encoding.rs        : Used for verifiable encryption
    
            signer.rs                     : DNC implementations of "signer" (a.k.a Issuer)
                                            primitive functions (e.g., create keys, sign)
    
            to_from_api/*                 : functions to convert between API data types and DNC data types
    
            types.rs                      : Type aliases used in the DNC implementation

<a id="org1fbd53a"></a>


<a id="orgebca771"></a>

## Example of connecting a specific ZKP library to `PlatformApi`

In [./zkp_backends/ac2c/crypto_interface.rs](./zkp_backends/ac2c/crypto_interface.rs) the AC2C implementation initializes a `CryptoInterface`
([./interfaces/crypto_interface.rs](./interfaces/crypto_interface.rs)) struct with "pointers" to the AC2C implementation of
[./interfaces/primitives.rs](./interfaces/primitives.rs). That initialized struct is referenced as `CRYPTO_INTERFACE_AC2C`.

`CRYPTO_INTERFACE_AC2C` is passed to `implement_platform_api_using` (defined in [./api_utils.rs](./api_utils.rs))
to create an instance of `PlatformApi`.  Many of the primitives are directly assigned to `PlatformApi` fields.

The `specific_prover`, `specific_verifier`, `specific_verify_decryption` values are first passed to
the non-primitive, `create_proof`, `verify_proof`, and `verify_decryption` functions to create a higher-level
`PlatformAPI` function, which are then assigned to their associated fields.

An example of making this connection can be seen in the `run_json_test_ac2c` function in
[../../tests/vcp/zkp_functionality_tests/test_definitions.rs](../../tests/vcp/zkp_functionality_tests/test_definitions.rs).


<a id="orgeede47c"></a>

## Creating an Issuer's public and secret data (e.g., keys)

To prepare for signing credentials, an Issuer uses `create_signer_data` in `PlatformApi` ([./api.rs](./api.rs)).

The type of that function, `CreateSignerData`, is defined in [./interfaces/primitives.rs](./interfaces/primitives.rs).

It takes

-   a `Natural` (an RNG seed), and
-   a list of `ClaimType` (both defined in [./interfaces/types.rs](./interfaces/types.rs))
    -   this is the "schema" for credentials that will be issued and signed by the Issuer

Assuming the AC2C implementation of primitives are connected to `PlatformApi`,
as described in <a id="orgb6020b6"></a>,
then `create_signer_data` (in [./zkp_backends/ac2c/signer.rs](./zkp_backends/ac2c/signer.rs)) is invoked.

The `create_signer_data` implementation

-   creates an AC2C schema representation based on a list of VCP `ClaimType`
-   creates AC2C public and secret data (that includes public/secret keys)
-   returns VCP `SignerData`

`SignerData` ([./interfaces/types.rs](./interfaces/types.rs)) contains

-   `SignerSecretData`
    -   an opaque representation of the AC2C secret data
-   `SignerPublicData`
    -   an opaque representation of the AC2C public data
    -   a vector of `ClaimType` (i.e., the "schema")

An Issuer would securely store the private data and make the public data available.


<a id="org8e5d63a"></a>

## Issuer signing a credential

To sign credentials, an Issuer uses the `PlatformApi` ([./api.rs](./api.rs)) `sign` function
of type `Sign` ([./interfaces/primitives.rs](./interfaces/primitives.rs)).

It takes

-   a `Natural` (an RNG seed)
-   a list of `DataValue` ([./interfaces/types.rs](./interfaces/types.rs))
-   `SignerData` (from `create_signer_data` above)

The AC2C implementation of `sign` is in [./zkp_backends/ac2c/signer.rs](./zkp_backends/ac2c/signer.rs).

That `sign` implementation

-   converts each VCP `DataValue` to an AC2C claim
-   uses AC2C to sign the claims using the secret data from `SignerData`
-   returns a `Signature` (an opaque representation of an AC2C signature)


<a id="org91f8034"></a>

## Creating a proof

The general `create_proof` function ([./impl/general/proof.rs](./impl/general/proof.rs)) takes

-   proof requirements : `HashMap<CredentialLabel, CredentialReqs>`
    -   `CredentialLabel`
        -   an identifier used to refer to a credential for which a Prover must
            prove knowledge of a signature satisfying the associated `CredentialReqs`, as well as
            for establishing equalities between attributes
            in different credentials
    -   `CredentialReqs` ([./interfaces/types.rs](./interfaces/types.rs))
        -   what is required to be proved (e.g., reveal values, accumulator membership, &#x2026;)
-   shared parameters : `HashMap<SharedParamKey, SharedParamValue>`
    -   `SharedParamKey`
        -   an identifier used in `CredentialReqs` (above) to specify a value contained in shared parameters
    -   `SharedParamValue`
        -   a value, e.g., range min/max, Issuer public data
-   signatures, etc : `HashMap<CredentialLabel, SignatureAndRelatedData>`
    -   provides `SignatureAndRelatedData` for each credential referenced in proof requirements
    -   `SignatureAndRelatedData` contains
        -   `Signature`
            -   used to create a proof-of-knowledge
        -   list of `DataValue`
            -   the values that we used to create the signature
        -   `AccumulatorWitnesses`
            -   set membership witnesses for any accumulators in the requirements (could be none)
        -   `Option<Nonce>`
            -   An optional `Nonce` agreed between Prover and Verifier to avoid replay attacks

Using the above input, the general `create_proof` function

-   gets the values to reveal from the list of `DataValue`
-   transforms human-friendly `CredentialReqs` into machine-friendly "proof instructions" and equality requirements
    -   via `presentation_request_setup` ([./impl/general/presentation_request_setup.rs](./impl/general/presentation_request_setup.rs))
    -   the "proof instructions" returned by `presentation_request_setup` are of type `ProofInstructionGeneral<ResolvedDisclosure>`
    -   `ProofInstructionGeneral` identifies the credential and attribute for which a proof is required, and also the index of a "related" proof instruction, namely the proof instruction for the proof of knowledge of signature covering the relevant attribute
    -   There is one `ResolvedDisclosure` constructor for each type of proof supported:
        -   `CredentialResolved` (requires proof of knowledge of signature on a credential)
        -   `InAccumResolved`
        -   `InRangeResolved`
        -   `EncryptedForResolved`
    -   Each `ResolvedDisclosure` contains the parameters for the relevant proof, looked up from `SharedParams` using the `SharedParamKey` s included in `CredentialReqs`.  These parameters are in library-independent format.  Each ZKP backend knows how to translate these to their own data types and use them to construct the required proofs.
-   validates the `CredentialReqs` against schemas
-   calls the specific ZKP library function `specific_prover`, passing the proof instructions, equality requirements, signatures, etc.
    -   Each ZKP backend we have implemented specifies its own library-specific type of "proof instruction"; we call them `ProofInstructionGeneral<SupportedDisclosure>` in both cases, but this is not a requirement.

The AC2C `specific_prover` (named `specific_prover_ac2c` in [./zkp_backends/ac2c/proof.rs](./zkp_backends/ac2c/proof.rs)).

-   creates an AC2C `Presentation` (i.e., "proof") ([../presentation.rs](../presentation.rs))
-   wraps that proof in a VCP opaque data type
-   returns `DataForVerifier` that contains the VCP proof and any warnings


<a id="org47b9094"></a>

## Verifying a proof

Like the general `create_proof` function,
the general `verify_proof` function ([./impl/general/proof.rs](./impl/general/proof.rs)) takes

-   proof requirements : `HashMap<CredentialLabel, CredentialReqs>`
-   shared parameters : `HashMap<SharedParamKey, SharedParamValue>`
-   `Option<Nonce>`

It also takes:

-   data for verifier : `DataForVerifier` (produced by `create_proof)`.
-   decryption requests: `HashMap<String, HashMap<u64, HashMap<String, DecryptRequest>>>`

Note that AC2C does not yet support decryption, so if the decryption requests map is
not empty, verification fails.

After transforming `CredentialReqs` into proof instructions and equality requirements and
after validating those requirements against schemas it calls the `specific_verifier` function.

The AC2C `specific_verifier` (named `specific_verifier_ac2c` in [./zkp_backends/ac2c/proof.rs](./zkp_backends/ac2c/proof.rs))
converts the VCP information and data into formats used by AC2C, and then calls
the AC2C `Presentation:verify` to verify the proof.


<a id="orgd379f23"></a>

## Proofs with revealed values

Attributes whose values are to be revealed are specified in the `disclosed: Disclosed` field of `CredentialReqs`.

`Disclosed` ([./interfaces/types.rs](./interfaces/types.rs)) is a list of indices into the list of `DataValue` that were signed,
specifying which values should be disclosed.

Both the general `create_proof` and `verify_proof` functions ([./impl/general/proof.rs](./impl/general/proof.rs)) call
`presentation_request_setup` ([./impl/general/presentation_request_setup.rs](./impl/general/presentation_request_setup.rs)) that calls
`get_proof_instructions` to transform `CredentialReqs` into proof instructions.
For each credential request, the translation happens in `get_proof_instructions_for_cred`.

For revealed values, the `ProofInstructionGeneral` that gets returned is
`ResolvedDisclosure::CredentialResolvedWrapper(CredentialResolved`.  It contains

-   `SignerPublicData`
-   for each reveal value: a list of tuples : `(index, value, ClaimType)`

Both the general `create_proof` and `verify_proof` functions go on to call their specific variants,
in the AC2C case, `specific_prover_ac2c` and `specific_verifier_ac2c` ([./zkp_backends/ac2c/proof.rs](./zkp_backends/ac2c/proof.rs)).

The specific functions call `presentation_schema_from` which calls
`transform_instruction` ([./zkp_backends/ac2c/presentation_request_setup.rs](./zkp_backends/ac2c/presentation_request_setup.rs)) to
transform the `ProofInstructionGeneral<ResolvedDisclosure>` into a
`ProofInstructionGeneral<SupportedDisclosure>`.
That function returns a proof instruction that contains `SupportedDisclosure::SignatureAndReveal` that contains

-   an `anoncreds-v2-rs` `IssuerPublic`
-   `HashMap<CredAttrIndex, (DataValue, ClaimType)>`

`SupportedDisclosure` is then given to `generate_statements` ([./zkp_backends/ac2c/presentation_request_setup.rs](./zkp_backends/ac2c/presentation_request_setup.rs)).
For `SupportedDisclosure::SignatureAndReveal`, `generate_statements` creates an `anoncreds-v2-rs`
`SignatureStatement` containing

-   the disclosed information
-   a statement ID
-   `anoncreds-v2-rs` `IssuerPublic`

The `anoncreds-v2-rs` statements returned from `generate_statements` are given to
`anoncreds-v2-rs` `PresentationSchema::new_with_id`, which is then returned from
`presentation_schema_from`.

At this point `specific_prover_ac2c` calls `anoncreds-v2-rs` `Presentation::create` with

-   the `PresentationSchema`
-   `anoncreds-v2-rs` `IndexMap<CredentialLabel, PresentationCredential>`
    -   created by a call to `presentation_credentials_from` ([./zkp_backends/ac2c/proof.rs](./zkp_backends/ac2c/proof.rs))

That `anoncreds-v2-rs` `Presentation` (i.e., proof) is returned from `specific_prover_ac2c`.

In the `specific_verifier_ac2c` case, it calls `anoncreds-v2-rs` `Presentation::verify` with
the `PresentationSchema` to verify the proof.


<a id="org0c5f4ac"></a>

## Proofs with range proofs

Range proofs are requirements in the `in_range: InRange` field of `CredentialReqs`.

`InRange` ([./interfaces/types.rs](./interfaces/types.rs)) is a list of `InRangeInfo` that contain

-   an index specifying which value in the list of `DataValue` to be used
-   a `min_label` : a key into shared parameters; that key maps to the actual minimum value
-   a `max_label` : a key into shared parameters; that key maps to the actual maximum value
-   `proving_key_label` : a key into shared parameters; that key maps to an instance of  `RangeProofProvingKey`

For range proofs,
`ResolvedDisclosure::InRangeResolvedWrapper(InRangeResolved` is created. It contains

-   `min_val`     : looked up from shared parameters
-   `max_val`     : looked up from shared parameters
-   `proving_key` : looked up from shared parameters
-   (the index is also collected into the outer `ProofInstructionGeneral`)

The AC2C implementation then transforms that `ResolvedDisclosure` into
`SupportedDisclosure::RangeProof` that contains

-   the `anoncreds-v2-rs` range proving key
-   the min and max values
-   the index

`SupportedDisclosure::RangeProof`  is given to `generate_statements`
which creates two `anoncreds-v2-rs` statements:

-   `CommitmentStatement`
-   `RangeStatement`

Those statements are then used to create and verify proofs


<a id="org6fb487c"></a>

## Proofs with verifiable encryption

Verifiable encryption requirements are specified in the `encrypted_for: EncryptedFor` field of `CredentialReqs`.

`EncryptedFor` ([./interfaces/types.rs](./interfaces/types.rs)) is a list of `IndexAndLabel` that contain

-   an index specifying which value in the list of `DataValue` to be encrypted
-   a `label` : a key into shared parameters; that key maps to the public data that should be used for encryption.

For verifiable encryption,
`ResolvedDisclosure::EncryptedForResolvedWrapper(EncryptedForResolved)` is created. It contains

-   the API public data to be used for encryption

The AC2C implementation then transforms that `ResolvedDisclosure` into
`SupportedDisclosure::EncryptedFor` that contains

-   the `anoncreds-v2-rs` verifiable encryption public key

`SupportedDisclosure::EncryptedFor`  is given to `generate_statements`
which creates a `anoncreds-v2-rs` `VerifiableEncryptionStatement`

NOTE: AC2C does not yet support decryption.


<a id="orga7e495f"></a>

## Proofs with equalities between attributes

Equality requirements are specified in the `equal_to: EqualTo` field of `CredentialReqs`.

`EqualTo` ([./interfaces/types.rs](./interfaces/types.rs)) is a list of `EqInfo` that contain

-   `from_index` : an index specifying which value in the list of `DataValue` to be used in equality checking
-   `to_label`   : a label specifying a `CredentialReqs`
-   `to_index`   : index into the `DataValue` of the `to_label` credential to be used in equality checking

General `presentation_request_setup` calls `equality_reqs_from_pres_reqs_general` to create

-   `EqualityReqs = Vec<EqualityReq>`
-   `EqualityReq  = Vec<(CredentialLabel, CredAttrIndex)>`

where each `EqualityReq` is a list of pairs that point to values that should be equal.

`EqualityReqs` is given to `specific_prover`.  In the AC2C case, `specific_prover_ac2c` calls
`presentation_schema_from` ([./impl/zkp_backends/ac2c/presentation_request_setup.rs](./impl/zkp_backends/ac2c/presentation_request_setup.rs)) with those `EqualityReqs`.
`presentation_schema_from` pass those to `generate_equality_statements` to create a `anoncreds-v2-rs`
`EqualityStatement` for each equality.


<a id="org1f53a37"></a>

## Proofs with accumulators

Accumulator requirements are specified in the `in_accum: InAccum` field of `CredentialReqs`.

`InAccum` ([./interfaces/types.rs](./interfaces/types.rs)) is a list of `InAccumInfo` that contain

-   an index specifying which value in the list of `DataValue` represents an accumlator element
-   `public_data_label` : a key into shared parameters; that key maps to `AccumulatorPublicData`
-   `mem_prv_label`     : a key into shared parameters; that key maps to a `MembershipProvingKey`
-   `accumulator_label` : a key into shared parameters; that key maps to an `Accumulator`
-   `accumulator_seq_no_label` : a key into shared parameters; that key maps to the sequence number of the accumulator

For accumulators
`ResolvedDisclosure::InAccumResolvedWrapper(InAccumResolved` is created. It contains

-   the API values obtained from the keys in `InAccum`

The AC2C implementation then transforms that `ResolvedDisclosure` into
`SupportedDisclosure::InAccumProof` that contains

-   the `anoncreds-v2-rs` `vb20::PublicKey` for accumulators
-   the `anoncreds-v2-rs` `vb20::Accumulator` accumulator

`SupportedDisclosure::InAccumProof` is given to `generate_statements`
which creates a `anoncreds-v2-rs` `MembershipStatement`


<a id="org8c7cbc6"></a>

## Accumulator functions

There are functions for ([./api.rs](./api.rs), [./interfaces/primitives.rs](./interfaces/primitives.rs))

-   creating accumulators (and their associated keys)
-   creating accumulator elements from `DataValue`
-   adding and removing elements from accumulators and getting witnesses for those elements
-   updating existing witnesses after elements have been added to or removed from an accumulator

The AC2C versions are in [./zkp_backends/ac2c/accumulators.rs](./zkp_backends/ac2c/accumulators.rs).


// ------------------------------------------------------------------------------
use crate::vcp::{Error, SerdeJsonError, VCPResult};
use crate::vcp::interfaces::crypto_interface::*;
use crate::vcp::r#impl::ac2c::to_from_api::*;
use crate::vcp::r#impl::common::types::WarningsAndResult;
use crate::vcp::r#impl::to_from::*;
use crate::vcp::r#impl::util::*;
use crate::vcp::interfaces::primitives::types::*;
// ------------------------------------------------------------------------------
use crate::prelude::*;
use crate::prelude::vb20;
// ------------------------------------------------------------------------------
use blsful::{Bls12381G2Impl, PublicKey};
use blsful::inner_types::G1Projective;
use indexmap::*;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::ControlFlow;
use std::str::FromStr;
// ------------------------------------------------------------------------------

pub fn presentation_schema_from(
    prf_instrs: &[ProofInstructionGeneral<ResolvedDisclosure>],
    eqs: &EqualityReqs,
) -> VCPResult<WarningsAndResult<PresentationSchema>> {
    let WarningsAndResult {
        warnings: warns,
        result: supported_disclosures,
    } = transform_instructions(prf_instrs)?;
    let mut stmts = generate_statements(&supported_disclosures);
    let mut eq_stmts = generate_equality_statements(eqs);
    stmts.append(&mut eq_stmts);
    let ps = PresentationSchema::new_with_id(&stmts, "HARD_CODED_ID");
    let r = WarningsAndResult {
        warnings: warns,
        result: ps,
    };
    Ok(r)
}

// (Note that this commend comes directly from Haskell, so the names of things
// correspond to the original Haskell names)
//
// This is just for readability of internal code, needed because of a
// (temporary?) inconsistency between types in the Haskell APIs for DNC and
// AC2C. Potentially that could be addressed by changing AC2C's Haskell API,
// but pulling on this "thread" would expose an issue that the same type is used
//  also for StatementLabel and some other things, and conversion between these
// is all done in terms of ByteString.  Being consistent would require also
// defining, e.g., StatementLabelBS, and (because these are not wrapped in
// newtype), the compiler would not enforce consistency.  I don't think it's
// worthwile to do so for this purpose, so I think it's fine to keep them as
// ByteString, or potentially change them to Text for consistency with DNC's
// Haskell API, but that wouldn't address the "internal consistency" issue
// mentioned here.

type PresentationCredentialLabel = String;

pub fn presentation_credentials_from(
    sigs_and_related_data: &HashMap<CredentialLabel, SignatureAndRelatedData>,
) -> VCPResult<IndexMap<CredentialLabel, PresentationCredential>> {
    let mut pres_creds : IndexMap<PresentationCredentialLabel, PresentationCredential> = IndexMap::new();
    for (clbl, SignatureAndRelatedData { signature, values:_, accum_wits }) in sigs_and_related_data {
        let cb : CredentialBundle       = from_api(signature)?;
        let pc : PresentationCredential = cb.credential.into();
        pres_creds.insert(stmt_label_for(clbl), pc);
        for (aidx, wit) in accum_wits {
            let mw : vb20::MembershipWitness = from_api(wit)?;
            let wit_cred                     = mw.into();
            pres_creds.insert(membership_label_for(clbl, aidx), wit_cred);
        }
    }
    Ok(pres_creds)
}

pub fn attr_label_for_idx(i: CredAttrIndex) -> String {
    format!("{ATTR_PREFIX}{i}")
}

fn read_maybe_throw_on_error<F: FromStr>(
    s: &str,
    ec: impl Fn(String) -> Error,
    l: &[&str],
    desc: &str,
) -> VCPResult<F>
where
    F::Err: Debug,
{
    s.parse().map_err(|err| {
        ec(format!(
            "{}; failed to extract {desc} from {s}; {err:#?}",
            l.join("; ")
        ))
    })
}

fn has_expected_prefix_and_more<'a>(
    bs: &'a str,
    pref: &str,
    ec: impl Fn(String) -> Error,
    context: &str,
) -> VCPResult<&'a str> {
    let as_string: &'a str = bs;
    let pf_string = pref;
    bs.starts_with(pref).assert_or_else(|| {
        ec(format!(
            "{context}; {pf_string}; is not a prefix of; {as_string}"
        ))
    })?;
    let s: &'a str = &as_string[pf_string.len()..];
    (!s.is_empty()).assert_or_else(|| ec(format!("{context}; no suffix after prefix {pf_string}")));
    Ok(s)
}

pub fn idx_from_attr_label(bs: &CredentialLabel) -> VCPResult<CredAttrIndex> {
    let s = has_expected_prefix_and_more(bs, ATTR_PREFIX, Error::General, "idx_from_attr_label")?;
    read_maybe_throw_on_error(s, Error::General, &["idx_from_attr_label"], "CredAttrIndex")
}

pub fn cred_label_from_statement_id(bs: &str) -> VCPResult<CredentialLabel> {
    let s = has_expected_prefix_and_more(
        bs,
        STMT_PREFIX,
        Error::General,
        "cred_label_from_statement_id",
    )?;
    Ok(s.to_string())
}

// ------------------------------------------------------------------------------

static ATTR_PREFIX          : &str = "AttrPrefix-";
static ENCRYPTED_FOR_PREFIX : &str = "EncryptedForPrefix-";
static MEMBERSHIP_PREFIX    : &str = "MembershipPrefix-";
static STMT_PREFIX          : &str = "StmtIdPrefix-";

fn encrypted_for_label_for(c_lbl : &str, a_idx : &u64) -> String {
    format!("{MEMBERSHIP_PREFIX}{c_lbl}{a_idx}")
}

fn membership_label_for(c_lbl : &str, a_idx : &u64) -> String {
    format!("{MEMBERSHIP_PREFIX}{c_lbl}{a_idx}")
}

fn stmt_label_for(l: &str) -> String {
    format!("{STMT_PREFIX}{l}")
}

#[derive(Debug)]
enum SupportedDisclosure {
    RangeProof(Box<RangeProofCommitmentSetup>, u64, u64),
    SignatureAndReveal(Box<IssuerPublic>, Vec<u64>),
    InAccumProof(Box<vb20::PublicKey>, vb20::Accumulator),
    EncryptedFor(PublicKey<Bls12381G2Impl>)
}

type Validation<T> = Result<T, Warning>;
fn success<T>(t:T)    -> Validation<T> { Ok(t) }
fn fail<T>(w:Warning) -> Validation<T> { Err(w) }

fn transform_instruction(
    pig : &ProofInstructionGeneral<ResolvedDisclosure>
) -> VCPResult<Validation<ProofInstructionGeneral<SupportedDisclosure>>>
{
    match pig {
        ProofInstructionGeneral {
            cred_label       : c_lbl,
            attr_idx_general : a_idx,
            discl_general    : ResolvedDisclosure::CredentialResolvedWrapper(CredentialResolved
                                                         { issuer_public     : ip,
                                                           rev_idxs_and_vals : ridxvs }),
            related_pi_idx, }
        => {
            let iss_pub = from_api(&ip.signer_public_setup_data)?;
            Ok(success(ProofInstructionGeneral {
                cred_label       : c_lbl.clone(),
                attr_idx_general : *a_idx,
                discl_general    : SupportedDisclosure::SignatureAndReveal(Box::new(iss_pub),
                                                                           ridxvs.clone().into_keys().collect()),
                related_pi_idx: *related_pi_idx,
            }))
        },
        ProofInstructionGeneral {
            cred_label       : c_lbl,
            attr_idx_general : a_idx,
            discl_general    : ResolvedDisclosure::InRangeResolvedWrapper (InRangeResolved
                                                       { min_val     : min_v,
                                                         max_val     : max_v,
                                                         proving_key : prv_key_api }),
            related_pi_idx,
        }
        => {
            // println!("transform_instruction: prv_key_api: {:?}", prv_key_api);
            let prv_key = from_api(prv_key_api)?;
            // println!("transform_instruction: prv_key: {:?}", prv_key);
            Ok(success(ProofInstructionGeneral {
                cred_label       : c_lbl.clone(),
                attr_idx_general : *a_idx,
                discl_general    : SupportedDisclosure::RangeProof(Box::new(prv_key),
                                                                   *min_v, *max_v),
                related_pi_idx   : *related_pi_idx,
            }))
        },
        ProofInstructionGeneral {
            cred_label       : c_lbl,
            attr_idx_general : a_idx,
            discl_general    : ResolvedDisclosure::InAccumResolvedWrapper (InAccumResolved
                                                                           { public_data : pd,
                                                                             mem_prv     : _,
                                                                             accumulator : acc,
                                                                             seq_num     : _}),
            related_pi_idx,
        }
        => {
            Ok(success(ProofInstructionGeneral {
                cred_label       : c_lbl.clone(),
                attr_idx_general : *a_idx,
                discl_general    : SupportedDisclosure::InAccumProof(Box::new(from_api(pd)?),
                                                                     from_api(acc)?),
                related_pi_idx   : *related_pi_idx,
            }))
        }
        ProofInstructionGeneral {
            cred_label       : c_lbl,
            attr_idx_general : a_idx,
            discl_general    : ResolvedDisclosure::EncryptedForResolvedWrapper(EncryptedForResolved(apd)),
            related_pi_idx,
        } => {
            let AuthorityPublicData(authority_as_issuer) = apd;
            let IssuerPublic { verifiable_encryption_key, .. } = from_api(&SignerPublicSetupData(authority_as_issuer.clone()))?;
            Ok(success(ProofInstructionGeneral {
                cred_label       : c_lbl.clone(),
                attr_idx_general : *a_idx,
                discl_general    : SupportedDisclosure::EncryptedFor(verifiable_encryption_key),
                related_pi_idx   : *related_pi_idx,
            }))
        }
    }
}

fn transform_instructions(
    prf_instrs: &[ProofInstructionGeneral<ResolvedDisclosure>],
) -> VCPResult<WarningsAndResult<Vec<ProofInstructionGeneral<SupportedDisclosure>>>> {
    let (warnings0, instrs): (
        Vec<Warning>,
        Vec<ProofInstructionGeneral<SupportedDisclosure>>,
    ) = prf_instrs
        .iter()
        .map(transform_instruction)
        .try_partition(|res| {
            res.map(|v| match v {
                Err(warn) => PartitionItem::Left(warn),
                Ok(prf_instr) => PartitionItem::Right(prf_instr),
            })
        })?;
    Ok(WarningsAndResult {
        warnings: warnings0,
        result: instrs,
    })
}

fn generate_statements(
    discls: &[ProofInstructionGeneral<SupportedDisclosure>],
) -> Vec<Statements> {
    discls
        .iter()
        .map(
            |ProofInstructionGeneral {
                 cred_label: c_lbl,
                 attr_idx_general: a_idx,
                 discl_general,
                 ..
             }|
             -> Vec<Statements> {
                match discl_general {
                    SupportedDisclosure::SignatureAndReveal(issuer_pub, idxs) => {
                        let mut disclosed = BTreeSet::<String>::new();
                        idxs.iter().for_each(|x| { disclosed.insert(attr_label_for_idx(*x)); });
                        Vec::from([<Statements>::from(SignatureStatement {
                                disclosed,
                                id : stmt_label_for(c_lbl),
                                issuer : *issuer_pub.clone(),
                        })])
                    }
                    SupportedDisclosure::RangeProof(commitment_setup, min_v, max_v) => {
                        let RangeProofCommitmentSetup {
                            message_generator: msg_gen,
                            blinder_generator: blinder_gen,
                        } = **commitment_setup;
                        let sig_stmt_id = stmt_label_for(c_lbl);
                        let commitment_stmnt_id = id_for("CommitmentStatement", c_lbl, a_idx);
                        let commitment_statement = <Statements>::from(CommitmentStatement {
                                id : commitment_stmnt_id.clone(),
                                reference_id : sig_stmt_id.clone(),
                                message_generator : msg_gen,
                                blinder_generator : blinder_gen,
                                claim : *a_idx as usize,
                            });
                        let rng_stmt_id = id_for("RangeStatement", c_lbl, a_idx);
                        let range_statement = <Statements>::from(RangeStatement {
                            id : rng_stmt_id,
                            reference_id : commitment_stmnt_id,
                            signature_id : sig_stmt_id,
                            lower : Some(*min_v as isize),
                            upper : Some(*max_v as isize),
                            claim : *a_idx as usize,
                        });
                        Vec::from([range_statement, commitment_statement])
                    }
                    SupportedDisclosure::InAccumProof(pk, acc) => {
                        let sig_stmt_id          = stmt_label_for(c_lbl);
                        let mem_stmt_id          = membership_label_for(c_lbl, a_idx);
                        let membership_statement = <Statements>::from(MembershipStatement {
                            id               : mem_stmt_id,
                            reference_id     : sig_stmt_id,
                            accumulator      : *acc,
                            verification_key : **pk,
                            claim            : *a_idx as usize,
                        });
                        Vec::from([membership_statement])
                    },
                    SupportedDisclosure::EncryptedFor(public_key) => {
                        let sig_stmt_id          = stmt_label_for(c_lbl);
                        let mem_stmt_id          = encrypted_for_label_for(c_lbl, a_idx);
                        let encryption_statement = <Statements>::from(VerifiableEncryptionStatement {
                            // NOTE: It seems that G1Projective::GENERATOR is always used, so we
                            // hard code it here, but in principle there could be different
                            // generators that would have to be stored alongside the public key
                            message_generator: G1Projective::GENERATOR,
                            encryption_key   : *public_key,
                            id               : mem_stmt_id,
                            reference_id     : sig_stmt_id,
                            claim            : *a_idx as usize,
                        });
                        Vec::from([encryption_statement])
                    }
                }
            },
        )
        .collect_concat()
}

fn id_for(label: &str, clbl : &str, aidx : &u64) -> String {
    [label, clbl, "-", &aidx.to_string()].concat()
}


fn generate_equality_statements(eq_reqs: &[EqualityReq]) -> Vec<Statements> {
    eq_reqs
        .iter()
        .map(|er| {
            // ID must be the same for the same equalities, so Prover and
            // Verifier can independently produce PresentationSchema without
            // breaking proofs, and it must be different for different
            // equalities.
            let eq_stmt_id = format!("{:?}", {
                let mut er = er.clone();
                er.sort();
                er
            });
            <Statements>::from(EqualityStatement {
                id: eq_stmt_id,
                ref_id_claim_index: er
                    .iter()
                    .map(|(k, v)| (stmt_label_for(k), *v as usize))
                    .collect(),
            })
        })
        .collect()
}

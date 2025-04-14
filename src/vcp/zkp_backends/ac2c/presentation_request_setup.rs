// ------------------------------------------------------------------------------
use crate::vcp::{Error, SerdeJsonError, VCPResult};
use crate::vcp::r#impl::types::*;
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::r#impl::util::*;
use crate::vcp::interfaces::crypto_interface::*;
use crate::vcp::interfaces::primitives::types::*;
use crate::vcp::zkp_backends::ac2c::to_from_api::range_proof_to_from_api::*;
// ------------------------------------------------------------------------------
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
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

pub fn presentation_schema_from<S: ShortGroupSignatureScheme>(
    prf_instrs: &[ProofInstructionGeneral<ResolvedDisclosure>],
    eqs: &EqualityReqs,
) -> VCPResult<WarningsAndResult<PresentationSchema<S>>> {
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

pub fn presentation_credentials_from<S: ShortGroupSignatureScheme>(
    sigs_and_related_data: &HashMap<CredentialLabel, SignatureAndRelatedData>,
) -> VCPResult<IndexMap<CredentialLabel, PresentationCredential<S>>> {
    let mut pres_creds : IndexMap<PresentationCredentialLabel, PresentationCredential<S>> = IndexMap::new();
    for (clbl, SignatureAndRelatedData { signature, values:_, accumulator_witnesses }) in sigs_and_related_data {
        let cb : CredentialBundle<S>       = from_api(signature)?;
        let pc : PresentationCredential<S> = cb.credential.into();
        pres_creds.insert(stmt_label_for(clbl), pc);
        for (aidx, wit) in accumulator_witnesses {
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
enum SupportedDisclosure<S: ShortGroupSignatureScheme> {
    RangeProof(Box<RangeProofCommitmentSetup>, u64, u64),
    SignatureAndReveal(Box<IssuerPublic<S>>, Vec<u64>),
    InAccumProof(Box<vb20::PublicKey>, vb20::Accumulator),
    EncryptedFor(PublicKey<Bls12381G2Impl>)
}

fn transform_instruction<S: ShortGroupSignatureScheme>(
    pig : &ProofInstructionGeneral<ResolvedDisclosure>
) -> VCPResult<Validation<ProofInstructionGeneral<SupportedDisclosure<S>>>>
{
    match pig {

        ProofInstructionGeneral {
            cred_label, attr_idx_general, related_pi_idx,
            discl_general : ResolvedDisclosure::CredentialResolvedWrapper
                (CredentialResolved { issuer_public, rev_idxs_and_vals }),
        } => {
            let iss_pub = from_api(&issuer_public.signer_public_setup_data)?;
            Ok(success(ProofInstructionGeneral {
                cred_label       : cred_label.clone(),
                attr_idx_general : *attr_idx_general,
                related_pi_idx   : *related_pi_idx,
                discl_general    : SupportedDisclosure::SignatureAndReveal
                    (Box::new(iss_pub),
                     rev_idxs_and_vals.clone().into_keys().collect())}))
        },

        ProofInstructionGeneral {
            cred_label, attr_idx_general, related_pi_idx,
            discl_general : ResolvedDisclosure::InRangeResolvedWrapper
                (InRangeResolved { min_val, max_val, proving_key }),
        }
        => {
            let prv_key = from_api(proving_key)?;
            Ok(success(ProofInstructionGeneral {
                cred_label       : cred_label.clone(),
                attr_idx_general : *attr_idx_general,
                related_pi_idx   : *related_pi_idx,
                discl_general    : SupportedDisclosure::RangeProof
                    (Box::new(prv_key), *min_val, *max_val)}))
        },

        ProofInstructionGeneral {
            cred_label, attr_idx_general, related_pi_idx,
            discl_general : ResolvedDisclosure::InAccumResolvedWrapper
                (InAccumResolved { public_data, mem_prv, accumulator, seq_num}),
        }
        => {
            Ok(success(ProofInstructionGeneral {
                cred_label       : cred_label.clone(),
                attr_idx_general : *attr_idx_general,
                related_pi_idx   : *related_pi_idx,
                discl_general    : SupportedDisclosure::InAccumProof
                    (Box::new(from_api(public_data)?),
                     from_api(accumulator)?),
            }))
        }

        ProofInstructionGeneral {
            cred_label, attr_idx_general, related_pi_idx,
            discl_general : ResolvedDisclosure::EncryptedForResolvedWrapper
                (EncryptedForResolved { auth_pub_spk, auth_pub_data })
        } => {
            let AuthorityPublicData(authority_as_issuer) = auth_pub_data;
            let IssuerPublic::<S> { verifiable_encryption_key, .. } =
                from_api(&SignerPublicSetupData(authority_as_issuer.clone()))?;
            Ok(success(ProofInstructionGeneral {
                cred_label       : cred_label.clone(),
                attr_idx_general : *attr_idx_general,
                related_pi_idx   : *related_pi_idx,
                discl_general    : SupportedDisclosure::EncryptedFor
                    (verifiable_encryption_key)}))
        }
    }
}

fn transform_instructions<S: ShortGroupSignatureScheme>(
    prf_instrs: &[ProofInstructionGeneral<ResolvedDisclosure>],
) -> VCPResult<WarningsAndResult<Vec<ProofInstructionGeneral<SupportedDisclosure<S>>>>> {
    let (warnings0, instrs): (
        Vec<Warning>,
        Vec<ProofInstructionGeneral<SupportedDisclosure<S>>>,
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

fn generate_statements<S: ShortGroupSignatureScheme>(
    discls: &[ProofInstructionGeneral<SupportedDisclosure<S>>],
) -> Vec<Statements<S>> {
    discls
        .iter()
        .map(
            |ProofInstructionGeneral {
                 cred_label: c_lbl,
                 attr_idx_general: a_idx,
                 discl_general,
                 ..
             }|
             -> Vec<Statements<S>> {
                match discl_general {
                    SupportedDisclosure::SignatureAndReveal(issuer_pub, idxs) => {
                        let mut disclosed = BTreeSet::<String>::new();
                        idxs.iter().for_each(|x| { disclosed.insert(attr_label_for_idx(*x)); });
                        Vec::from([<Statements<S>>::from(SignatureStatement {
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
                        let commitment_statement = <Statements<S>>::from(CommitmentStatement {
                                id : commitment_stmnt_id.clone(),
                                reference_id : sig_stmt_id.clone(),
                                message_generator : msg_gen,
                                blinder_generator : blinder_gen,
                                claim : *a_idx as usize,
                            });
                        let rng_stmt_id = id_for("RangeStatement", c_lbl, a_idx);
                        let range_statement = <Statements<S>>::from(RangeStatement {
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
                        let membership_statement = <Statements<S>>::from(MembershipStatement {
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
                        let encryption_statement = <Statements<S>>::from(VerifiableEncryptionStatement {
                            // NOTE: It seems that G1Projective::GENERATOR is always used, so we
                            // hard code it here, but in principle there could be different
                            // generators that would have to be stored alongside the public key
                            message_generator        : G1Projective::GENERATOR,
                            encryption_key           : *public_key,
                            id                       : mem_stmt_id,
                            reference_id             : sig_stmt_id,
                            claim                    : *a_idx as usize,
                            allow_message_decryption : true,
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


fn generate_equality_statements<S: ShortGroupSignatureScheme>(
    eq_reqs: &[EqualityReq]) -> Vec<Statements<S>>
{
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
            <Statements<S>>::from(EqualityStatement {
                id: eq_stmt_id,
                ref_id_claim_index: er
                    .iter()
                    .map(|(k, v)| (stmt_label_for(k), *v as usize))
                    .collect(),
            })
        })
        .collect()
}

// ------------------------------------------------------------------------------
pub use crate::vcp::interfaces::types::*;
// ------------------------------------------------------------------------------
pub use std::collections::BTreeMap;
pub use std::collections::hash_map::HashMap;
pub use std::rc::Rc;
// ------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InAccumResolved {
    pub public_data : AccumulatorPublicData,
    pub mem_prv     : MembershipProvingKey,
    pub accumulator : Accumulator,
    pub seq_num     : AccumulatorBatchSeqNo
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InRangeResolved {
    pub min_val     : u64,
    pub max_val     : u64,
    pub proving_key : RangeProofProvingKey,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct EncryptedForResolved {
    pub auth_pub_spk  : SharedParamKey,
    pub auth_pub_data : AuthorityPublicData,
}

impl std::fmt::Debug for EncryptedForResolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("EncryptedForResolved")
            .field(
                &(format!(
                    "AuthorityPublicData with for key {}",
                    self.auth_pub_spk,
                )),
            )
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialResolved {
    pub issuer_public     : SignerPublicData,
    pub rev_idxs_and_vals : HashMap<CredAttrIndex, (DataValue, ClaimType)>,
}

impl PartialOrd for CredentialResolved {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CredentialResolved {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.issuer_public.cmp(&other.issuer_public) {
            std::cmp::Ordering::Less => std::cmp::Ordering::Less,
            std::cmp::Ordering::Greater => std::cmp::Ordering::Greater,
            std::cmp::Ordering::Equal => {
                let self_riavs = &self.rev_idxs_and_vals.iter().collect::<BTreeMap<_, _>>();
                let other_riavs = &other.rev_idxs_and_vals.iter().collect::<BTreeMap<_, _>>();
                self_riavs.cmp(other_riavs)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ResolvedDisclosure {
    CredentialResolvedWrapper   (CredentialResolved),
    InAccumResolvedWrapper      (InAccumResolved),
    InRangeResolvedWrapper      (InRangeResolved),
    EncryptedForResolvedWrapper (EncryptedForResolved),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RelatedIndex(pub u64);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ProofInstructionGeneral<T> {
    pub cred_label       : CredentialLabel,
    pub attr_idx_general : CredAttrIndex,
    pub related_pi_idx   : RelatedIndex,
    pub discl_general    : T,
}

pub type EqualityReq  = Vec<(CredentialLabel, CredAttrIndex)>;
pub type EqualityReqs = Vec<EqualityReq>;

#[derive(Debug, PartialEq)]
pub struct WarningsAndProof {
    pub warnings : Vec<Warning>,
    pub proof    : Proof,
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ForProverOrVerifier {
    ForProver,
    ForVerifier,
}

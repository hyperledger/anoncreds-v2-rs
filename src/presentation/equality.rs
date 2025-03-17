use super::*;
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::statement::{EqualityStatement, Statement};
use crate::{error::Error, CredxResult};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

pub(crate) struct EqualityBuilder<'a> {
    reference_statement: &'a EqualityStatement,
}

impl<S: ShortGroupSignatureScheme> PresentationBuilder<S> for EqualityBuilder<'_> {
    fn gen_proof(self, _challenge: Scalar) -> PresentationProofs<S> {
        EqualityProof {
            id: self.reference_statement.id(),
        }
        .into()
    }
}

impl<'a> EqualityBuilder<'a> {
    pub fn commit<S: ShortGroupSignatureScheme>(
        reference_statement: &'a EqualityStatement,
        reference_id_credential: &IndexMap<String, PresentationCredential<S>>,
    ) -> CredxResult<Self> {
        let mut scalars = Vec::new();
        for (id, claim_index) in &reference_statement.ref_id_claim_index {
            match reference_id_credential.get(id) {
                None => {
                    return Err(Error::InvalidPresentationData(format!(
                        "equality statement with id '{}' references a non-existent credential '{}'",
                        reference_statement.id, id
                    )))
                }
                Some(cred) => {
                    if let PresentationCredential::Signature(c) = cred {
                        let sc = c.claims[*claim_index].to_scalar();
                        scalars.push(sc);
                    }
                }
            }
        }
        let mut res = true;
        for i in 0..scalars.len() - 1 {
            res &= scalars[i] == scalars[i + 1];
        }
        if !res {
            return Err(Error::InvalidClaimData(
                "equality statement - claims are not all the same",
            ));
        }
        Ok(Self {
            reference_statement,
        })
    }
}

/// An equality proof for checking message equality
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EqualityProof {
    /// The statement identifier
    pub id: String,
}

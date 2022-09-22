use super::*;
use crate::credential::CredentialBundle;
use crate::statement::{EqualityStatement, Statement};
use crate::{error::Error, CredxResult};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

pub(crate) struct EqualityBuilder<'a> {
    reference_statement: &'a EqualityStatement,
}

impl<'a> PresentationBuilder for EqualityBuilder<'a> {
    fn gen_proof(self, _challenge: Scalar) -> PresentationProofs {
        PresentationProofs::Equality(EqualityProof {
            id: self.reference_statement.id(),
            reference_id_claim_index: self.reference_statement.ref_id_claim_index.clone(),
        })
    }
}

impl<'a> EqualityBuilder<'a> {
    pub fn commit(
        reference_statement: &'a EqualityStatement,
        reference_id_credential: &BTreeMap<String, CredentialBundle>,
    ) -> CredxResult<Self> {
        let mut scalars = Vec::new();
        for (id, claim_index) in &reference_statement.ref_id_claim_index {
            match reference_id_credential.get(id) {
                None => return Err(Error::InvalidPresentationData),
                Some(cred) => {
                    let sc = cred.credential.claims[*claim_index].to_scalar();
                    scalars.push(sc);
                }
            }
        }
        let mut res = true;
        for i in 0..scalars.len() - 1 {
            res &= scalars[i] == scalars[i + 1];
        }
        if !res {
            return Err(Error::InvalidClaimData);
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
    /// The reference id to claim index
    pub reference_id_claim_index: BTreeMap<String, usize>,
}

impl PresentationProof for EqualityProof {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn get_proof_contribution(
        &self,
        _challenge: Scalar,
        _schema: &PresentationSchema,
        _transcript: &mut Transcript,
    ) {
    }

    fn verify(&self, _schema: &PresentationSchema) -> CredxResult<()> {
        Ok(())
    }
}

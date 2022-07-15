use super::{
    Statement, StatementType,
};
use crate::issuer::IssuerPublic;


/// A PS signature statement
#[derive(Clone, Debug)]
pub struct SignatureStatement {
    /// The labels for the disclosed claims
    pub disclosed: Vec<String>,
    /// The statement id
    pub id: String,
    /// The issuer information
    pub issuer: IssuerPublic,
}

impl Statement for SignatureStatement {
    type Value = SignatureStatement;

    /// Get the specific struct value
    fn value(&self) -> Self {
        self.clone()
    }

    /// Return this statement unique identifier
    fn id(&self) -> String {
        self.id.clone()
    }

    /// Get the statement type
    fn r#type(&self) -> StatementType {
        StatementType::PS
    }

    /// Any statements that this statement references
    fn reference_ids(&self) -> Vec<String> {
        Vec::with_capacity(0)
    }
}
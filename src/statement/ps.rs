use yeti::knox::ps::Signature;

/// A PS signature statement
#[derive(Clone, Debug)]
pub struct PsSignatureStatement {
    /// The statement id
    pub id: String,
    /// The statement signature
    pub signature: Signature,
}

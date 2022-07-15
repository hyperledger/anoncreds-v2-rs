mod equality;
mod signature;
mod r#type;

pub use equality::*;
pub use signature::*;
pub use r#type::*;

/// Statement methods
pub trait Statement {
    type Value;

    /// Get the specific struct value
    fn value(&self) -> Self::Value;
    /// Return this statement unique identifier
    fn id(&self) -> String;
    /// Get the statement type
    fn r#type(&self) -> StatementType;
    /// Any statements that this statement references
    fn reference_ids(&self) -> Vec<String>;
}
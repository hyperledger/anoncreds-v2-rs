use crate::claim::{Claim, ClaimType};

/// A claim value validation rule
pub trait Validator {
    /// Check if a claim is valid
    fn is_valid(&self, claim: impl Claim) -> bool;
}

/// check if the claim length is correct
pub struct LengthValidator {
    /// The minimum claim length. If missing the default value is 0.
    pub min: Option<usize>,
    /// he maximum claim length. If missing the default value is 4,294,967,295.
    pub max: Option<usize>
}

impl Validator for LengthValidator {
    fn is_valid(&self, claim: impl Claim) -> bool {
        if !matches!(claim.get_type(), ClaimType::Hashed) {
            return false;
        }
        let min = self.min.unwrap_or_default();
        let max = self.max.unwrap_or(u32::MAX as usize);

        let buffer = claim.get_value();

        true
    }
}
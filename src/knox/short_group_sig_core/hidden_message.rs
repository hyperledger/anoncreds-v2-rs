use super::super::ecc_group::ScalarOps;

use ff::PrimeField;

/// Two types of hidden messages
#[derive(Copy, Clone, Debug)]
pub enum HiddenMessage<S>
where
    S: PrimeField + ScalarOps<Scalar = S>,
{
    /// Indicates the message is hidden and no other work is involved
    ///     so a blinding factor will be generated specific to this proof
    ProofSpecificBlinding(S),
    /// Indicates the message is hidden but it is involved with other proofs
    ///     like boundchecks, set memberships or inequalities, so the blinding factor
    ///     is provided from an external source.
    ExternalBlinding(S, S),
}

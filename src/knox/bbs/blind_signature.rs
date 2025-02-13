use super::{PublicKey, SecretKey, Signature};
use crate::error::Error;
use crate::knox::short_group_sig_core::short_group_traits::BlindSignature as BlindSignatureTrait;
use crate::CredxResult;
use blsful::inner_types::{Field, G1Projective, Scalar};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct BlindSignature(pub(crate) Signature);

impl BlindSignatureTrait for BlindSignature {
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn new(
        commitment: G1Projective,
        sk: &SecretKey,
        msgs: &[(usize, Scalar)],
    ) -> CredxResult<Self> {
        if sk.is_invalid() {
            return Err(Error::InvalidSigningOperation);
        }
        let max_idx = msgs
            .iter()
            .map(|(idx, _)| *idx)
            .max()
            .ok_or(Error::General("No messages"))?;
        if max_idx >= sk.max_messages {
            return Err(Error::General("Invalid message index"));
        }
        let expanded_pub_key = PublicKey::from(sk);
        let domain = super::signature::domain_calculation(&expanded_pub_key);
        let (points, scalars): (Vec<G1Projective>, Vec<Scalar>) = msgs
            .iter()
            .map(|(i, m)| (expanded_pub_key.y[*i], *m))
            .unzip();

        let e = super::signature::compute_e(sk, &scalars, domain);

        let ske = (sk.x + e).invert();
        if ske.is_none().into() {
            // only fails if sk + e is zero
            return Err(Error::General("Invalid signature"));
        }

        let b =
            G1Projective::GENERATOR + commitment + G1Projective::sum_of_products(&points, &scalars);

        let a = b * ske.expect("a valid scalar");

        Ok(Self(Signature { a, e }))
    }

    fn to_unblinded(self, _blinding: Scalar) -> Signature {
        self.0
    }
}

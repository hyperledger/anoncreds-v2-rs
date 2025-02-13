use blsful::inner_types::G1Projective;
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use sha2::Sha256;
use std::num::NonZeroUsize;

/// The message generators used for signing and proofs
#[derive(Debug, Clone)]
pub struct MessageGenerators(pub(crate) Vec<G1Projective>);

impl MessageGenerators {
    /// Create a new set of message generators
    pub fn new(count: NonZeroUsize) -> Self {
        Self::with_api_id(count, None)
    }

    /// Create a new set of message generators using a specific API ID
    pub fn with_api_id(count: NonZeroUsize, api_id: Option<&[u8]>) -> Self {
        const SEED_DST: &[u8] = b"SIG_GENERATOR_SEED_";
        const GENERATOR_DST: &[u8] = b"SIG_GENERATOR_DST_";
        const GENERATOR_SEED: &[u8] = b"SIG_GENERATOR_SEED_";

        let seed_dst = api_id
            .unwrap_or(&[])
            .iter()
            .chain(SEED_DST)
            .copied()
            .collect::<Vec<u8>>();
        let generator_seed = api_id
            .unwrap_or(&[])
            .iter()
            .chain(GENERATOR_SEED)
            .copied()
            .collect::<Vec<u8>>();
        let generator_dst = api_id
            .unwrap_or(&[])
            .iter()
            .chain(GENERATOR_DST)
            .copied()
            .collect::<Vec<u8>>();

        let count = count.get();
        let mut generators = Vec::with_capacity(count);

        let binding = [seed_dst.as_slice()];
        let mut v = [0u8; 40];
        let mut v_expander =
            ExpandMsgXmd::<Sha256>::expand_message(&[&generator_seed], &binding, 32)
                .expect("Failed to expand message");
        v_expander.fill_bytes(&mut v[..32]);

        let mut inner_v = [0u8; 32];
        for i in 0..count {
            v[32..].copy_from_slice(&(i as u64).to_be_bytes());
            let mut inner_v_expander = ExpandMsgXmd::<Sha256>::expand_message(&[&v], &binding, 32)
                .expect("Failed to expand message");
            inner_v_expander.fill_bytes(&mut inner_v);
            let g_i = G1Projective::hash::<ExpandMsgXmd<Sha256>>(&inner_v, &generator_dst);
            generators.push(g_i);
        }

        Self(generators)
    }
}

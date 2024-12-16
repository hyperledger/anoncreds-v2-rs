use super::{BlindSignatureContext, PokSignature, PublicKey, Signature};
use crate::knox::short_group_sig_core::short_group_traits::ProofOfSignatureKnowledgeContribution;
use crate::knox::short_group_sig_core::*;
use crate::CredxResult;
use blsful::inner_types::{G1Affine, G1Projective, Scalar};
use elliptic_curve::{group::Curve, Field};
use merlin::Transcript;
use rand_core::*;

/// A Prover is whoever receives signatures or uses them to generate proofs.
/// Provided are methods for 2PC where some are only known to the prover and a blind signature
/// is created, unblinding signatures, verifying signatures, and creating signature proofs of knowledge
/// with selective disclosure proofs
pub struct Prover;

impl Prover {
    /// Create the structures need to send to an issuer to complete a blinded signature
    /// `messages` is an index to message map where the index corresponds to the index in `generators`
    pub fn new_blind_signature_context(
        messages: &[(usize, Scalar)],
        public_key: &PublicKey,
        nonce: Scalar,
        mut rng: impl RngCore + CryptoRng,
    ) -> CredxResult<(BlindSignatureContext, Scalar)> {
        let mut points = Vec::new();
        let mut secrets = Vec::new();
        let mut committing = ProofCommittedBuilder::<G1Projective, G1Affine, Scalar>::new(
            G1Projective::sum_of_products,
        );

        for (i, m) in messages {
            if *i > public_key.y.len() {
                return Err(crate::error::Error::General("invalid blind signing"));
            }
            secrets.push(*m);
            points.push(public_key.y_blinds[*i]);
            committing.commit_random(public_key.y_blinds[*i], &mut rng);
        }

        let blinding = Scalar::random(&mut rng);
        secrets.push(blinding);
        points.push(G1Projective::GENERATOR);
        committing.commit_random(G1Projective::GENERATOR, &mut rng);

        let mut transcript = Transcript::new(b"new blind signature");
        let commitment = G1Projective::sum_of_products(points.as_ref(), secrets.as_ref());
        committing.add_challenge_contribution(b"random commitment", &mut transcript);
        transcript.append_message(
            b"blind commitment",
            commitment.to_affine().to_compressed().as_ref(),
        );
        transcript.append_message(b"nonce", nonce.to_be_bytes().as_ref());
        let mut res = [0u8; 64];
        transcript.challenge_bytes(b"blind signature context challenge", &mut res);
        let challenge = Scalar::from_bytes_wide(&res);
        let proofs = committing.generate_proof(challenge, secrets.as_slice())?;
        Ok((
            BlindSignatureContext {
                commitment,
                challenge,
                proofs,
            },
            blinding,
        ))
    }

    /// Create a new signature proof of knowledge and selective disclosure proof
    /// from a verifier's request
    pub fn commit_signature_pok(
        signature: Signature,
        public_key: &PublicKey,
        messages: &[ProofMessage<Scalar>],
        rng: impl RngCore + CryptoRng,
    ) -> CredxResult<PokSignature> {
        PokSignature::commit(signature, public_key, messages, rng)
    }
}

#[test]
fn blind_signature_context_test() {
    use super::super::ecc_group::ScalarOps;
    use super::*;
    use rand_core::*;

    let mut rng = OsRng;

    let (pk, sk) = Issuer::new_keys(4, &mut rng).unwrap();
    let nonce = Scalar::random(&mut rng);

    // try with zero, just means a blinded signature but issuer knows all messages
    let blind_messages = [];

    let res = Prover::new_blind_signature_context(&blind_messages[..], &pk, nonce, &mut rng);
    assert!(res.is_ok());

    let (ctx, blinding) = res.unwrap();

    let messages = [
        (0, Scalar::from_hash(b"firstname")),
        (1, Scalar::from_hash(b"lastname")),
        (2, Scalar::from_hash(b"age")),
        (3, Scalar::from_hash(b"allowed")),
    ];
    let res = Issuer::blind_sign(&ctx, &sk, &messages[..], nonce);
    assert!(res.is_ok());
    let blind_signature = res.unwrap();
    let signature = blind_signature.to_unblinded(blinding);

    let msgs = [messages[0].1, messages[1].1, messages[2].1, messages[3].1];

    let res = signature.verify(&pk, msgs.as_ref());
    assert_eq!(res.unwrap_u8(), 1);
}

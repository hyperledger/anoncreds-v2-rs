use super::{
    accumulator::{Accumulator, Element},
    generate_fr, hash_to_g1,
    key::PublicKey,
    witness::{MembershipWitness, NonMembershipWitness},
    SALT,
};
use crate::knox::short_group_sig_core::ProofMessage;
use signature_bls::bls12_381_plus::{G1Projective, G2Projective, Gt, Scalar};

use group::{Curve, GroupEncoding};
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use crate::knox::accumulator::vb20::Error;

/// Section 8 in <https://eprint.iacr.org/2020/777>
/// setup calls for four distinct generators in G1
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProofParams {
    /// Parameter X
    pub x: G1Projective,
    /// Parameter Y
    pub y: G1Projective,
    /// Parameter Z
    pub z: G1Projective,
    /// Parameter K
    pub k: G1Projective,
}

impl core::fmt::Display for ProofParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ProofParams {{ x: {:?}, y: {:?}, z: {:?}, k: {:?} }}",
            self.x.to_bytes(),
            self.y.to_bytes(),
            self.z.to_bytes(),
            self.k.to_bytes()
        )
    }
}

impl ProofParams {
    /// Create a new set of proof parameters
    pub fn new(pk: PublicKey, entropy: Option<&[u8]>) -> Self {
        const PREFIX: [u8; 32] = [
            0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
            0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
            0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
        ];
        let mut data = Vec::new();
        data.extend_from_slice(&PREFIX);
        data.extend_from_slice(entropy.unwrap_or(&[]));
        data.extend_from_slice(&pk.to_bytes());

        let z = hash_to_g1(data.as_slice());

        data[0] = 0xFE;
        let y = hash_to_g1(data.as_slice());

        data[0] = 0xFD;
        let x = hash_to_g1(data.as_slice());

        data[0] = 0xFC;
        let k = hash_to_g1(data.as_slice());
        Self { k, x, y, z }
    }

    /// Add these proof params to the transcript
    pub fn add_to_transcript(&self, transcript: &mut Transcript) {
        transcript.append_message(b"Proof Param K", self.k.to_bytes().as_ref());
        transcript.append_message(b"Proof Param X", self.x.to_bytes().as_ref());
        transcript.append_message(b"Proof Param Y", self.y.to_bytes().as_ref());
        transcript.append_message(b"Proof Param Z", self.z.to_bytes().as_ref());
    }
}

/// The commit or blinding step for generating a ZKP
/// The next step is to call `get_bytes_for_challenge`
/// to create the fiat shamir heuristic
#[derive(Debug, Copy, Clone)]
pub struct MembershipProofCommitting {
    e_c: G1Projective,
    t_sigma: G1Projective,
    t_rho: G1Projective,
    delta_sigma: Scalar,
    delta_rho: Scalar,
    blinding_factor: Scalar,
    r_sigma: Scalar,
    r_rho: Scalar,
    r_delta_sigma: Scalar,
    r_delta_rho: Scalar,
    sigma: Scalar,
    rho: Scalar,
    cap_r_sigma: G1Projective,
    cap_r_rho: G1Projective,
    cap_r_delta_sigma: G1Projective,
    cap_r_delta_rho: G1Projective,
    cap_r_e: Gt,
    witness_value: Scalar,
}

impl MembershipProofCommitting {
    /// Create a new membership proof committing phase
    pub fn new(
        y: ProofMessage<Scalar>,
        witness: MembershipWitness,
        proof_params: ProofParams,
        pubkey: PublicKey,
    ) -> Self {
        let message = y.get_message();
        let mut rng = rand_core::OsRng;
        // Randomly select σ, ρ
        let sigma = generate_fr(SALT, None, &mut rng);
        let rho = generate_fr(SALT, None, &mut rng);

        // E_C = C + (σ + ρ)Z
        let e_c = proof_params.z * (sigma + rho) + witness.0;

        // T_σ = σX
        let t_sigma = proof_params.x * sigma;

        // T_ρ = ρY
        let t_rho = proof_params.y * rho;

        // δ_σ = yσ
        let delta_sigma = message * sigma;

        // δ_ρ = yρ
        let delta_rho = message * rho;

        // Randomly pick r_σ,r_ρ,r_δσ,r_δρ
        // r_y is either generated randomly or supplied in case this proof is used to
        // bind to an external proof
        let r_y = y.get_blinder(&mut rng).unwrap();
        let r_sigma = generate_fr(SALT, None, &mut rng);
        let r_rho = generate_fr(SALT, None, &mut rng);
        let r_delta_sigma = generate_fr(SALT, None, &mut rng);
        let r_delta_rho = generate_fr(SALT, None, &mut rng);

        // R_σ = r_σ X
        let cap_r_sigma = proof_params.x * r_sigma;

        // R_ρ = ρY
        let cap_r_rho = proof_params.y * r_rho;

        // R_δσ = r_y T_σ - r_δσ X
        let cap_r_delta_sigma = cap_r(&[t_sigma, -proof_params.x], &[r_y, r_delta_sigma]);

        // R_δρ = r_y T_ρ - r_δρ Y
        let cap_r_delta_rho = cap_r(&[t_rho, -proof_params.y], &[r_y, r_delta_rho]);

        // R_E = e(E_C, P~)^r_y
        let g2 = G2Projective::GENERATOR;

        // R_E *= e(Z, P~)^-r_δσ - r_δρ
        let exp = -(r_delta_sigma + r_delta_rho);

        // Optimize one less pairing by computing
        // R_E = e(E_C^r_y + Z^{-r_δσ - r_δρ}, P~)
        let mut lhs = e_c * r_y;
        let z = proof_params.z * exp;
        lhs += z;
        let mut cap_r_e = pair(lhs, g2);

        // R_E *= e(Z, Q~)^-r_σ - r_ρ
        let exp = -(r_sigma + r_rho);
        cap_r_e += pairing(proof_params.z, pubkey.0, exp);

        Self {
            e_c,
            t_sigma,
            t_rho,
            delta_sigma,
            delta_rho,
            blinding_factor: r_y,
            r_sigma,
            r_rho,
            r_delta_sigma,
            r_delta_rho,
            sigma,
            rho,
            cap_r_e,
            cap_r_sigma,
            cap_r_rho,
            cap_r_delta_sigma,
            cap_r_delta_rho,
            witness_value: message,
        }
    }

    /// Return bytes that need to be hashed for generating challenge.
    ///
    /// V || Ec || T_sigma || T_rho || R_E || R_sigma || R_rho || R_delta_sigma || R_delta_rho
    pub fn get_bytes_for_challenge(&self, transcript: &mut Transcript) {
        transcript.append_message(b"Ec", self.e_c.to_bytes().as_ref());
        transcript.append_message(b"T_sigma", self.t_sigma.to_bytes().as_ref());
        transcript.append_message(b"T_rho", self.t_rho.to_bytes().as_ref());
        transcript.append_message(b"R_E", self.cap_r_e.to_bytes().as_ref());
        transcript.append_message(b"R_sigma", self.cap_r_sigma.to_bytes().as_ref());
        transcript.append_message(b"R_rho", self.cap_r_rho.to_bytes().as_ref());
        transcript.append_message(b"R_delta_sigma", self.cap_r_delta_sigma.to_bytes().as_ref());
        transcript.append_message(b"R_delta_rho", self.cap_r_delta_rho.to_bytes().as_ref());
    }

    /// Given the challenge value, compute the s values for Fiat-Shamir and return the actual
    /// proof to be sent to the verifier
    pub fn gen_proof(&self, challenge_hash: Element) -> MembershipProof {
        let challenge_hash = challenge_hash.0;
        // s_y = r_y - cy
        let s_y = schnorr(self.blinding_factor, self.witness_value, challenge_hash);
        // s_σ = r_σ - cσ
        let s_sigma = schnorr(self.r_sigma, self.sigma, challenge_hash);
        // s_ρ = r_ρ - cρ
        let s_rho = schnorr(self.r_rho, self.rho, challenge_hash);
        // s_δσ = rδσ - cδ_σ
        let s_delta_sigma = schnorr(self.r_delta_sigma, self.delta_sigma, challenge_hash);
        // s_δρ = rδρ - cδ_ρ
        let s_delta_rho = schnorr(self.r_delta_rho, self.delta_rho, challenge_hash);
        MembershipProof {
            e_c: self.e_c,
            t_sigma: self.t_sigma,
            t_rho: self.t_rho,
            s_y,
            s_sigma,
            s_rho,
            s_delta_sigma,
            s_delta_rho,
        }
    }
}

/// A ZKP membership proof
#[derive(Debug, Default, Copy, Clone, Deserialize, Serialize)]
pub struct MembershipProof {
    e_c: G1Projective,
    t_sigma: G1Projective,
    t_rho: G1Projective,
    s_sigma: Scalar,
    s_rho: Scalar,
    s_delta_sigma: Scalar,
    s_delta_rho: Scalar,
    s_y: Scalar,
}

impl core::fmt::Display for MembershipProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MembershipProof {{ e_c: {}, t_sigma: {}, t_rho: {}, s_sigma: {}, s_rho: {}, s_delta_sigma: {}, s_delta_rho: {}, s_y: {} }}",
        self.e_c, self.t_sigma, self.t_rho, self.s_sigma, self.s_rho, self.s_delta_sigma, self.s_delta_rho, self.s_y)
    }
}

impl MembershipProof {
    /// The size of the proof in bytes
    pub const BYTES: usize = 304;

    /// Generate the structure that can be used in the challenge hash
    /// returns a struct to avoid recomputing
    pub fn finalize(
        &self,
        accumulator: Accumulator,
        proof_params: ProofParams,
        pubkey: PublicKey,
        challenge_hash: Element,
    ) -> MembershipProofFinal {
        let challenge_hash = challenge_hash.0;
        // R_σ = s_δ X - c T_σ
        let cap_r_sigma = cap_r(
            &[proof_params.x, -self.t_sigma],
            &[self.s_sigma, challenge_hash],
        );

        // R_ρ = s_ρ Y - c T_ρ
        let cap_r_rho = cap_r(
            &[proof_params.y, -self.t_rho],
            &[self.s_rho, challenge_hash],
        );

        // R_δσ =  s_y T_σ - s_δσ X
        let cap_r_delta_sigma = cap_r(
            &[self.t_sigma, -proof_params.x],
            &[self.s_y, self.s_delta_sigma],
        );

        // R_δρ =  s_y T_ρ - s_δρ Y
        let cap_r_delta_rho = cap_r(
            &[self.t_rho, -proof_params.y],
            &[self.s_y, self.s_delta_rho],
        );

        let g2 = G2Projective::GENERATOR;

        // We can eliminate three pairings by combining
        // e(E_C, P~)^s_y * e(Z, P~)^-(s_delta_sigma + s_delta_rho) * e(V, P~)^-c
        // to
        // e(E_C^s_y + Z^-(s_delta_sigma + s_delta_rho) + V^-c, P~)
        // and
        // e(Z, Q~)^-(s_sigma + s_rho) * e(E_C, Q~)^c
        // to
        // e(Z^-(s_sigma + s_rho) + E_C^c, Q~)

        // e(E_C, P~)^s_y
        let mut lhs = self.e_c * self.s_y;

        // e(Z, P~)^-(s_delta_sigma + s_delta_rho)
        let mut exp = -(self.s_delta_sigma + self.s_delta_rho);
        let mut rhs = proof_params.z * exp;
        lhs += rhs;

        // e(V, P~)^-c
        exp = -challenge_hash;
        rhs = accumulator.0 * exp;
        lhs += rhs;
        let mut cap_r_e = pair(lhs, g2);

        // e(Z, Q~)^-(s_sigma + s_rho)
        exp = -(self.s_sigma + self.s_rho);
        lhs = proof_params.z * exp;

        // e(E_C, Q~)^c
        rhs = self.e_c * challenge_hash;
        lhs += rhs;
        cap_r_e += pair(lhs, pubkey.0);

        MembershipProofFinal {
            e_c: self.e_c,
            t_sigma: self.t_sigma,
            t_rho: self.t_rho,
            cap_r_e,
            cap_r_sigma,
            cap_r_rho,
            cap_r_delta_sigma,
            cap_r_delta_rho,
        }
    }

    /// Get the byte representation of the proof
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut res = [0u8; Self::BYTES];
        let output = serde_bare::to_vec(self).unwrap();
        res.copy_from_slice(&output);
        res
    }

    /// Convert a byte representation to a proof
    pub fn from_bytes(input: &[u8; Self::BYTES]) -> Result<Self, Error> {
        serde_bare::from_slice(input).map_err(|e| Error::from_msg(1, &e.to_string()))
    }
}

/// The computed values after running MembershipProof.finalize
#[derive(Debug, Copy, Clone)]
pub struct MembershipProofFinal {
    e_c: G1Projective,
    t_sigma: G1Projective,
    t_rho: G1Projective,
    cap_r_e: Gt,
    cap_r_sigma: G1Projective,
    cap_r_rho: G1Projective,
    cap_r_delta_sigma: G1Projective,
    cap_r_delta_rho: G1Projective,
}

impl MembershipProofFinal {
    /// V || Ec || T_sigma || T_rho || R_E || R_sigma || R_rho || R_delta_sigma || R_delta_rho
    pub fn get_bytes_for_challenge(&self, transcript: &mut Transcript) {
        transcript.append_message(b"Ec", self.e_c.to_bytes().as_ref());
        transcript.append_message(b"T_sigma", self.t_sigma.to_bytes().as_ref());
        transcript.append_message(b"T_rho", self.t_rho.to_bytes().as_ref());
        transcript.append_message(b"R_E", self.cap_r_e.to_bytes().as_ref());
        transcript.append_message(b"R_sigma", self.cap_r_sigma.to_bytes().as_ref());
        transcript.append_message(b"R_rho", self.cap_r_rho.to_bytes().as_ref());
        transcript.append_message(b"R_delta_sigma", self.cap_r_delta_sigma.to_bytes().as_ref());
        transcript.append_message(b"R_delta_rho", self.cap_r_delta_rho.to_bytes().as_ref());
    }
}

/// The commit or blinding step for generating a ZKP
/// The next step is to call `get_bytes_for_challenge`
/// to create the fiat shamir heuristic
#[derive(Debug, Copy, Clone)]
pub struct NonMembershipProofCommitting {
    e_c: G1Projective,
    e_d: G1Projective,
    e_dm1: G1Projective,
    t_sigma: G1Projective,
    t_rho: G1Projective,
    delta_sigma: Scalar,
    delta_rho: Scalar,
    blinding_factor: Scalar,
    r_u: Scalar,
    r_v: Scalar,
    r_w: Scalar,
    r_sigma: Scalar,
    r_rho: Scalar,
    r_delta_sigma: Scalar,
    r_delta_rho: Scalar,
    sigma: Scalar,
    rho: Scalar,
    tau: Scalar,
    pi: Scalar,
    cap_r_a: G1Projective,
    cap_r_b: G1Projective,
    cap_r_sigma: G1Projective,
    cap_r_rho: G1Projective,
    cap_r_delta_sigma: G1Projective,
    cap_r_delta_rho: G1Projective,
    cap_r_e: Gt,
    witness_d: Scalar,
    witness_value: Scalar,
}

impl NonMembershipProofCommitting {
    /// Create a new nonmembership proof committing phase
    pub fn new(
        y: Element,
        witness: NonMembershipWitness,
        proof_params: ProofParams,
        pubkey: PublicKey,
        blinding_factor: Option<Element>,
    ) -> Self {
        let mut rng = rand_core::OsRng;
        // Randomly pick r_σ,r_ρ,r_δσ,r_δρ

        // Randomly select σ, ρ
        let sigma = generate_fr(SALT, None, &mut rng);
        let rho = generate_fr(SALT, None, &mut rng);

        // E_C = C + (σ + ρ)Z
        let e_c = proof_params.z * (sigma + rho) + witness.c;

        // T_σ = σX
        let t_sigma = proof_params.x * sigma;

        // T_ρ = ρY
        let t_rho = proof_params.y * rho;

        // δ_σ = yσ
        let delta_sigma = y.0 * sigma;

        // δ_ρ = yρ
        let delta_rho = y.0 * rho;

        // Randomly pick r_σ,r_ρ,r_δσ,r_δρ
        // r_y is either generated randomly or supplied in case this proof is used to
        // bind to an external proof
        let r_y = blinding_factor
            .map(|bf| bf.into())
            .unwrap_or_else(|| generate_fr(SALT, None, &mut rng));
        let r_sigma = generate_fr(SALT, None, &mut rng);
        let r_rho = generate_fr(SALT, None, &mut rng);
        let r_delta_sigma = generate_fr(SALT, None, &mut rng);
        let r_delta_rho = generate_fr(SALT, None, &mut rng);

        // R_σ = r_σ X
        let cap_r_sigma = proof_params.x * r_sigma;

        // R_ρ = ρY
        let cap_r_rho = proof_params.y * r_rho;

        // R_δσ = r_y T_σ - r_δσ X
        let cap_r_delta_sigma = cap_r(&[t_sigma, -proof_params.x], &[r_y, r_delta_sigma]);

        // R_δρ = r_y T_ρ - r_δρ Y
        let cap_r_delta_rho = cap_r(&[t_rho, -proof_params.y], &[r_y, r_delta_rho]);

        // Randomly pick \tau, \pi
        let tau = generate_fr(SALT, None, &mut rng);
        let pi = generate_fr(SALT, None, &mut rng);

        // E_d = d P + \tau K
        let e_d = cap_r(
            &[G1Projective::GENERATOR, proof_params.k],
            &[witness.d, tau],
        );

        // E_{d^{-1}} = d^{-1}P + \pi K
        let e_dm1 = cap_r(
            &[G1Projective::GENERATOR, proof_params.k],
            &[witness.d.invert().unwrap(), pi],
        );

        // Randomly pick r_u,r_v,r_w
        let r_u = generate_fr(SALT, None, &mut rng);
        let r_v = generate_fr(SALT, None, &mut rng);
        let r_w = generate_fr(SALT, None, &mut rng);

        // R_A = r_u P + r_v K
        let cap_r_a = cap_r(&[G1Projective::GENERATOR, proof_params.k], &[r_u, r_v]);

        // R_B = r_u E_d^{-1} + r_w K
        let cap_r_b = cap_r(&[e_dm1, proof_params.k], &[r_u, r_w]);

        // R_E = e(E_C, P~)^r_y
        let g2 = G2Projective::GENERATOR;

        // R_E *= e(Z, P~)^-r_δσ - r_δρ
        let mut exp = -(r_delta_sigma + r_delta_rho);

        // Optimize one less pairing by computing
        // R_E = e(E_C^r_y + Z^{-r_δσ - r_δρ}, P~)
        let mut lhs = e_c * r_y;
        let z = proof_params.z * exp;
        lhs += z;

        // R_E *= e(K, P~)^-r_v
        let k = proof_params.k * -r_v;
        lhs += k;

        let mut cap_r_e = pair(lhs, g2);

        // R_E *= e(Z, Q~)^-r_σ - r_ρ
        exp = -(r_sigma + r_rho);
        cap_r_e += pairing(proof_params.z, pubkey.0, exp);

        Self {
            e_c,
            e_d,
            e_dm1,
            t_sigma,
            t_rho,
            delta_sigma,
            delta_rho,
            blinding_factor: r_y,
            sigma,
            rho,
            tau,
            pi,
            r_u,
            r_v,
            r_w,
            r_sigma,
            r_rho,
            r_delta_sigma,
            r_delta_rho,
            cap_r_a,
            cap_r_b,
            cap_r_e,
            cap_r_delta_rho,
            cap_r_delta_sigma,
            cap_r_rho,
            cap_r_sigma,
            witness_d: witness.d,
            witness_value: y.0,
        }
    }

    /// Return bytes that need to be hashed for generating challenge.
    ///
    /// V || Ec || Ed || Ed^{-1] || T_sigma || T_rho || R_A || R_B || R_E || R_sigma || R_rho || R_delta_sigma || R_delta_rho
    pub fn get_bytes_for_challenge(&self, accumulator: Accumulator, transcript: &mut Transcript) {
        transcript.append_message(b"Accumulator", accumulator.0.to_bytes().as_ref());
        transcript.append_message(b"Ec", self.e_c.to_bytes().as_ref());
        transcript.append_message(b"Ed", self.e_d.to_bytes().as_ref());
        transcript.append_message(b"Edm1", self.e_dm1.to_bytes().as_ref());
        transcript.append_message(b"T_sigma", self.t_sigma.to_bytes().as_ref());
        transcript.append_message(b"T_rho", self.t_rho.to_bytes().as_ref());
        transcript.append_message(b"R_E", self.cap_r_e.to_bytes().as_ref());
        transcript.append_message(b"R_A", self.cap_r_a.to_bytes().as_ref());
        transcript.append_message(b"R_B", self.cap_r_b.to_bytes().as_ref());
        transcript.append_message(b"R_sigma", self.cap_r_sigma.to_bytes().as_ref());
        transcript.append_message(b"R_rho", self.cap_r_rho.to_bytes().as_ref());
        transcript.append_message(b"R_delta_sigma", self.cap_r_delta_sigma.to_bytes().as_ref());
        transcript.append_message(b"R_delta_rho", self.cap_r_delta_rho.to_bytes().as_ref());
    }

    /// Given the challenge value, compute the s values for Fiat-Shamir and return the actual
    /// proof to be sent to the verifier
    pub fn gen_proof(&self, challenge_hash: Element) -> NonMembershipProof {
        // s_y = r_y - cy
        let s_y = schnorr(self.blinding_factor, self.witness_value, challenge_hash.0);
        // s_σ = r_σ - cσ
        let s_sigma = schnorr(self.r_sigma, self.sigma, challenge_hash.0);
        // s_ρ = r_ρ - cρ
        let s_rho = schnorr(self.r_rho, self.rho, challenge_hash.0);
        // s_δσ = rδσ - cδ_σ
        let s_delta_sigma = schnorr(self.r_delta_sigma, self.delta_sigma, challenge_hash.0);
        // s_δρ = rδρ - cδ_ρ
        let s_delta_rho = schnorr(self.r_delta_rho, self.delta_rho, challenge_hash.0);
        // s_u = r_u + c d
        let s_u = schnorr(self.r_u, self.witness_d, challenge_hash.0);
        // s_v = r_v + c tau
        let s_v = schnorr(self.r_v, self.tau, challenge_hash.0);
        // s_w = r_w - c d pi
        let pi = -(self.pi * self.witness_d);
        let s_w = schnorr(self.r_w, pi, challenge_hash.0);

        NonMembershipProof {
            e_c: self.e_c,
            e_d: self.e_d,
            e_dm1: self.e_dm1,
            t_sigma: self.t_sigma,
            t_rho: self.t_rho,
            s_sigma,
            s_rho,
            s_delta_sigma,
            s_delta_rho,
            s_y,
            s_u,
            s_v,
            s_w,
        }
    }
}

/// A ZKP non-membership proof
#[derive(Debug, Default, Copy, Clone)]
pub struct NonMembershipProof {
    e_c: G1Projective,
    e_d: G1Projective,
    e_dm1: G1Projective,
    t_sigma: G1Projective,
    t_rho: G1Projective,
    s_sigma: Scalar,
    s_rho: Scalar,
    s_delta_sigma: Scalar,
    s_delta_rho: Scalar,
    s_u: Scalar,
    s_v: Scalar,
    s_w: Scalar,
    s_y: Scalar,
}

impl NonMembershipProof {
    /// Generate the structure that can be used in the challenge hash
    /// returns a struct to avoid recomputing
    pub fn finalize(
        &self,
        accumulator: Accumulator,
        proof_params: ProofParams,
        pubkey: PublicKey,
        challenge_hash: Element,
    ) -> NonMembershipProofFinal {
        // R_σ = s_δ X - c T_σ
        let cap_r_sigma = cap_r(
            &[proof_params.x, -self.t_sigma],
            &[self.s_sigma, challenge_hash.0],
        );

        // R_ρ = s_ρ Y - c T_ρ
        let cap_r_rho = cap_r(
            &[proof_params.y, -self.t_rho],
            &[self.s_rho, challenge_hash.0],
        );

        // R_δσ =  s_y T_σ - s_δσ X
        let cap_r_delta_sigma = cap_r(
            &[self.t_sigma, -proof_params.x],
            &[self.s_y, self.s_delta_sigma],
        );

        // R_δρ =  s_y T_ρ - s_δρ Y
        let cap_r_delta_rho = cap_r(
            &[self.t_rho, -proof_params.y],
            &[self.s_y, self.s_delta_rho],
        );

        let g2 = G2Projective::GENERATOR;

        // We can eliminate multiple pairings by combining
        // e(E_C, P~)^s_y * e(Z, P~)^-(s_delta_sigma + s_delta_rho) * e(V, P~)^-c * e(K, P~)^-s_v * e(Ed, P~)^c
        // to
        // e(E_C^s_y + Z^-(s_delta_sigma + s_delta_rho) + V^-c - s_v K + c E_d, P~)
        // and
        // e(Z, Q~)^-(s_sigma + s_rho) * e(E_C, Q~)^c
        // to
        // e(Z^-(s_sigma + s_rho) + E_C^c, Q~)

        // e(E_C, P~)^s_y
        let mut lhs = self.e_c * self.s_y;

        // e(Z, P~)^-(s_delta_sigma + s_delta_rho)
        let mut exp = -(self.s_delta_sigma + self.s_delta_rho);
        let mut rhs = proof_params.z * exp;
        lhs += rhs;

        // e(V, P~)^-c
        exp = -challenge_hash.0;
        rhs = accumulator.0 * exp;
        lhs += rhs;

        //e(K, P~)^-s_v
        exp = -self.s_v;
        rhs = proof_params.k * exp;
        lhs += rhs;

        // e(Ed, P~)^c
        exp = challenge_hash.0;
        rhs = self.e_d * exp;
        lhs += rhs;
        let mut cap_r_e = pair(lhs, g2);

        // e(Z, Q~)^-(s_sigma + s_rho)
        exp = -(self.s_sigma + self.s_rho);
        lhs = proof_params.z * exp;

        // e(E_C, Q~)^c
        rhs = self.e_c * challenge_hash.0;
        lhs += rhs;
        cap_r_e += pair(lhs, pubkey.0);

        let g1 = G1Projective::GENERATOR;

        // R_A = s_u P + s_v K - c E_d
        let cap_r_a = cap_r(
            &[g1, proof_params.k, self.e_d],
            &[self.s_u, self.s_v, -challenge_hash.0],
        );

        // R_B = s_w K + s_u E_d^-1 - c P
        let cap_r_b = cap_r(
            &[proof_params.k, self.e_dm1, g1],
            &[self.s_w, self.s_u, -challenge_hash.0],
        );

        NonMembershipProofFinal {
            e_c: self.e_c,
            e_d: self.e_d,
            e_dm1: self.e_dm1,
            t_sigma: self.t_sigma,
            t_rho: self.t_rho,
            cap_r_a,
            cap_r_b,
            cap_r_e,
            cap_r_sigma,
            cap_r_rho,
            cap_r_delta_sigma,
            cap_r_delta_rho,
        }
    }
}

impl core::fmt::Display for NonMembershipProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NonMembershipProof {{ e_c: {}, e_d: {}, e_dm1: {}, t_sigma: {}, t_rho: {}, s_sigma: {}, s_rho: {}, s_delta_sigma: {}, s_delta_rho: {}, s_u: {}, s_v: {}, s_w: {}, s_y: {} }}",
               self.e_c, self.e_d, self.e_dm1, self.t_sigma, self.t_rho, self.s_sigma, self.s_rho, self.s_delta_sigma, self.s_delta_rho, self.s_u, self.s_v, self.s_w, self.s_y)
    }
}

/// The computed values after running NonMembershipProof.finalize
#[derive(Debug, Copy, Clone)]
pub struct NonMembershipProofFinal {
    e_c: G1Projective,
    e_d: G1Projective,
    e_dm1: G1Projective,
    t_sigma: G1Projective,
    t_rho: G1Projective,
    cap_r_a: G1Projective,
    cap_r_b: G1Projective,
    cap_r_e: Gt,
    cap_r_sigma: G1Projective,
    cap_r_rho: G1Projective,
    cap_r_delta_sigma: G1Projective,
    cap_r_delta_rho: G1Projective,
}

impl NonMembershipProofFinal {
    /// V || Ec || E_d || E_d^-1 || T_sigma || T_rho || R_A || R_B || R_E || R_sigma || R_rho || R_delta_sigma || R_delta_rho
    pub fn get_bytes_for_challenge(&self, accumulator: Accumulator, transcript: &mut Transcript) {
        transcript.append_message(b"Accumulator", accumulator.0.to_bytes().as_ref());
        transcript.append_message(b"Ec", self.e_c.to_bytes().as_ref());
        transcript.append_message(b"Ed", self.e_d.to_bytes().as_ref());
        transcript.append_message(b"Edm1", self.e_dm1.to_bytes().as_ref());
        transcript.append_message(b"T_sigma", self.t_sigma.to_bytes().as_ref());
        transcript.append_message(b"T_rho", self.t_rho.to_bytes().as_ref());
        transcript.append_message(b"R_E", self.cap_r_e.to_bytes().as_ref());
        transcript.append_message(b"R_A", self.cap_r_a.to_bytes().as_ref());
        transcript.append_message(b"R_B", self.cap_r_b.to_bytes().as_ref());
        transcript.append_message(b"R_sigma", self.cap_r_sigma.to_bytes().as_ref());
        transcript.append_message(b"R_rho", self.cap_r_rho.to_bytes().as_ref());
        transcript.append_message(b"R_delta_sigma", self.cap_r_delta_sigma.to_bytes().as_ref());
        transcript.append_message(b"R_delta_rho", self.cap_r_delta_rho.to_bytes().as_ref());
    }
}

fn cap_r(bases: &[G1Projective], scalars: &[Scalar]) -> G1Projective {
    G1Projective::sum_of_products(bases, scalars)
}

fn pair(g1: G1Projective, g2: G2Projective) -> Gt {
    signature_bls::bls12_381_plus::pairing(&g1.to_affine(), &g2.to_affine())
}

fn pairing(g1: G1Projective, g2: G2Projective, exp: Scalar) -> Gt {
    let base = g1 * exp;
    signature_bls::bls12_381_plus::pairing(&base.to_affine(), &g2.to_affine())
}

fn schnorr(r: Scalar, v: Scalar, challenge: Scalar) -> Scalar {
    v * challenge + r
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::knox::short_group_sig_core::HiddenMessage;

    #[test]
    fn serde_round_trip() {
        let sk = SecretKey::new(None);
        let pk = PublicKey::from(&sk);
        let params = ProofParams::new(pk, None);

        let res = serde_bare::to_vec(&params);
        assert!(res.is_ok());
        let params2: ProofParams = serde_bare::from_slice(&res.unwrap()).unwrap();
        assert_eq!(params, params2);
    }

    #[test]
    fn basic_membership_proof() {
        let sk = SecretKey::new(None);
        let pk = PublicKey::from(&sk);
        let y = Element::hash(b"basic_membership_proof");
        let msg = ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(y.0));
        let acc = Accumulator::with_elements(&sk, &[y]);
        let proof_params = ProofParams::new(pk, None);

        let mw = MembershipWitness::new(y, acc, &sk);
        let mpc = MembershipProofCommitting::new(msg, mw, proof_params, pk);

        let mut transcript = Transcript::new(b"basic_membership_proof");
        transcript.append_message(b"Public Key", &pk.to_bytes());
        transcript.append_message(b"Accumulator", &acc.to_bytes());
        proof_params.add_to_transcript(&mut transcript);
        mpc.get_bytes_for_challenge(&mut transcript);

        let challenge = Element::from_transcript(b"challenge", &mut transcript);
        let proof = mpc.gen_proof(challenge);
        let final_proof = proof.finalize(acc, proof_params, pk, challenge);

        let mut transcript = Transcript::new(b"basic_membership_proof");
        transcript.append_message(b"Public Key", &pk.to_bytes());
        transcript.append_message(b"Accumulator", &acc.to_bytes());
        proof_params.add_to_transcript(&mut transcript);
        final_proof.get_bytes_for_challenge(&mut transcript);

        let challenge2 = Element::from_transcript(b"challenge", &mut transcript);
        assert_eq!(challenge, challenge2);
    }

    #[test]
    fn basic_nonmembership_proof() {
        let mut rng = get_rng();
        let sk = SecretKey::new(None);
        let pk = PublicKey::from(&sk);
        let proof_params = ProofParams::new(pk, None);
        let blinding_factor = Some(Element::from(generate_fr(
            SALT,
            Some(b"basic_nonmembership_proof_blinding_factor"),
            &mut rng,
        )));
        let elements = [
            Element::hash(b"1"),
            Element::hash(b"2"),
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
        ];
        let acc = Accumulator::with_elements(&sk, &elements);
        let y = Element::hash(b"basic_nonmembership_proof");

        let nmw = NonMembershipWitness::new(y, &elements, &sk).unwrap();

        let nmpc = NonMembershipProofCommitting::new(y, nmw, proof_params, pk, blinding_factor);
        let mut transcript = Transcript::new(b"basic_nonmembership_proof");
        nmpc.get_bytes_for_challenge(acc, &mut transcript);
        let challenge = Element::from_transcript(b"challenge", &mut transcript);

        let proof = nmpc.gen_proof(challenge);
        let final_proof = proof.finalize(acc, proof_params, pk, challenge);

        let mut transcript = Transcript::new(b"basic_nonmembership_proof");
        final_proof.get_bytes_for_challenge(acc, &mut transcript);
        let challenge2 = Element::from_transcript(b"challenge", &mut transcript);

        assert_eq!(challenge, challenge2);
    }

    #[test]
    fn growing_accumulator() {
        use core::convert::TryFrom;

        let mut rng = get_rng();
        let sk = SecretKey::try_from(&[
            83, 88, 211, 208, 98, 73, 80, 160, 247, 119, 30, 138, 197, 40, 149, 84, 224, 194, 132,
            99, 42, 220, 247, 225, 118, 194, 100, 61, 247, 72, 186, 15,
        ])
        .unwrap();
        let pk = PublicKey::try_from(&[
            168, 83, 108, 197, 136, 167, 236, 76, 60, 181, 29, 189, 41, 15, 208, 225, 77, 81, 119,
            249, 194, 58, 100, 196, 98, 244, 8, 97, 204, 251, 189, 248, 238, 95, 150, 54, 54, 127,
            66, 188, 162, 128, 79, 60, 156, 222, 235, 28, 4, 95, 12, 179, 243, 26, 97, 173, 200,
            160, 200, 111, 69, 201, 189, 253, 31, 18, 212, 249, 81, 167, 39, 151, 160, 64, 27, 230,
            226, 58, 15, 175, 209, 166, 225, 205, 178, 42, 19, 204, 66, 30, 36, 197, 228, 54, 69,
            194,
        ])
        .unwrap();
        let proof_params: ProofParams = serde_bare::from_slice(&[
            137, 163, 2, 225, 231, 88, 50, 201, 244, 21, 220, 3, 217, 153, 224, 136, 41, 211, 94,
            149, 93, 72, 159, 205, 42, 127, 58, 196, 21, 156, 19, 116, 47, 226, 132, 36, 54, 148,
            225, 237, 73, 159, 26, 5, 69, 163, 113, 79, 177, 24, 18, 229, 113, 76, 130, 213, 70,
            216, 41, 209, 57, 61, 94, 190, 75, 81, 84, 103, 103, 49, 83, 146, 233, 9, 33, 79, 205,
            201, 193, 85, 205, 104, 126, 213, 125, 70, 108, 243, 118, 182, 54, 200, 208, 223, 4,
            138, 164, 154, 166, 2, 232, 165, 211, 111, 105, 86, 156, 56, 47, 224, 204, 59, 235,
            217, 166, 24, 217, 131, 126, 90, 7, 248, 79, 254, 24, 175, 88, 70, 31, 178, 89, 68,
            199, 110, 18, 207, 41, 238, 47, 224, 98, 58, 92, 81, 164, 11, 10, 26, 227, 183, 218,
            83, 99, 7, 190, 245, 126, 133, 186, 64, 31, 250, 218, 172, 105, 201, 65, 184, 87, 185,
            163, 167, 117, 26, 218, 50, 167, 21, 80, 24, 90, 113, 197, 189, 88, 17, 155, 33, 222,
            96, 33, 144,
        ])
        .unwrap();
        let blinding_factor = Some(Element::from(generate_fr(
            SALT,
            Some(b"basic_nonmembership_proof_blinding_factor"),
            &mut rng,
        )));

        let elements = [
            Element::hash(b"1"),
            Element::hash(b"2"),
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
        ];
        let mut acc = Accumulator::with_elements(&sk, &elements);
        let y = Element::hash(b"growing_accumulator");
        let nmw = NonMembershipWitness::new(y, &elements, &sk).unwrap();

        acc.add_assign(&sk, Element::hash(b"6"));

        let nmpc = NonMembershipProofCommitting::new(y, nmw, proof_params, pk, blinding_factor);
        let mut transcript = Transcript::new(b"growing_accumulator");
        nmpc.get_bytes_for_challenge(acc, &mut transcript);
        let challenge = Element::from_transcript(b"challenge", &mut transcript);

        let proof = nmpc.gen_proof(challenge);
        let final_proof = proof.finalize(acc, proof_params, pk, challenge);
        let mut transcript = Transcript::new(b"growing_accumulator");
        final_proof.get_bytes_for_challenge(acc, &mut transcript);
        let challenge2 = Element::from_transcript(b"challenge", &mut transcript);

        assert_ne!(challenge, challenge2);
    }
}

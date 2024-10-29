// ------------------------------------------------------------------------------
use credx::vcp::VCPResult;
use credx::vcp::r#impl::to_from::*;
// ------------------------------------------------------------------------------
use bulletproofs::{inner_types::*, BulletproofGens, PedersenGens, RangeProof};
use merlin::Transcript;
// ------------------------------------------------------------------------------
use rand::thread_rng;
use base64::prelude::*;
// ------------------------------------------------------------------------------

// from https://github.com/cryptidtech/bulletproofs : src/range_proof/mod.rs
fn create_range_proof() -> (BulletproofGens,
                            PedersenGens,
                            usize,
                            RangeProof,
                            bulletproofs::inner_types::G1Projective)
 {
    let bp_gens               = BulletproofGens::new(64, 1);
    let pc_gens               = PedersenGens::default();
    let secret_value          = 1037578891u64;
    let blinding              = Scalar::random(&mut thread_rng());
    let mut prover_transcript = Transcript::new(b"doctest example");
    let value                 = 32;
    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &blinding,
        value,
    ).expect("A real program could handle errors");

    (bp_gens, pc_gens, value, proof, committed_value)
}

fn verify_proof(bp_gens : BulletproofGens,
                pc_gens : PedersenGens,
                value : usize,
                proof : RangeProof,
                committed_value : G1Projective)
{
    let mut verifier_transcript = Transcript::new(b"doctest example");
    assert!(
        proof
            .verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_value, value)
            .is_ok()
    );
}

// This test is ignored because it fails due to an apparent serialisation bug in bulletproofs (see
// next test, which is identical except that it uses cbor instead of json for serialisation
#[ignore]
#[test]
fn range_proof_round_trip_json_serialization_json() -> Result<(),serde_json::Error> {
    let (_,_,_,r,_)     = create_range_proof();
    let s_json          = serde_json::to_vec(&r).unwrap();
    let _d : RangeProof = serde_json::from_slice(&s_json)?;
    Ok(())
}

#[test]
fn range_proof_round_trip_json_serialization_cbor() -> Result<(),serde_cbor::Error> {
    let (b,p,v,r,c)     = create_range_proof();
    let s_cbor          = serde_cbor::to_vec(&r).unwrap();
    let d : RangeProof  = serde_cbor::from_slice(&s_cbor)?;
    verify_proof(b,p,v,d,c);
    Ok(())
}

#[test]
fn range_proof_round_trip_json_base64_serialization() -> Result<(),serde_cbor::Error> {
    let (b,p,v,r,c)     = create_range_proof();
    let s_cbor          = serde_cbor::to_vec(&r).unwrap();
    let s_str           = BASE64_STANDARD.encode(s_cbor);
    let s_cbor_1        = BASE64_STANDARD.decode(s_str).unwrap();
    let d : RangeProof  = serde_cbor::from_slice(&s_cbor_1)?;
    verify_proof(b,p,v,d,c);
    Ok(())
}

#[test]
fn range_proof_round_trip_opaque_cbor() -> VCPResult<()> {
    let (b,p,v,r,c)     = create_range_proof();
    let cbor            = to_opaque_cbor(&r)?;
    let d :RangeProof   = from_opaque_cbor(cbor.as_str())?;
    verify_proof(b,p,v,d,c);
    Ok(())
}

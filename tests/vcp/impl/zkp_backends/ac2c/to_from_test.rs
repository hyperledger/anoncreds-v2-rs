// ------------------------------------------------------------------------------
use credx::vcp;
use credx::vcp::r#impl::common::to_from_api::*;
use credx::vcp::r#impl::zkp_backends::ac2c::signer::*;
use credx::vcp::r#impl::zkp_backends::ac2c::to_from_api::range_proof_to_from_api::*;
use credx::vcp::types::*;
// ------------------------------------------------------------------------------
use crate::vcp::data_for_tests as td;
// ------------------------------------------------------------------------------
use credx::prelude::{CredentialSchema,Issuer,IssuerPublic};
// ------------------------------------------------------------------------------

#[allow(unused_variables)]
#[test]
fn to_from_test() -> Result<(),vcp::Error> {
    let sdcts = &td::D_CTS;
    // println!("create_signer_data: sdcts: {:?}", sdcts.to_vec());
    let schema_claims = create_schema_claims(sdcts)?;
    let cred_schema   = CredentialSchema::new(
        Some("fake label"),
        Some("fake description"),
        &[],
        &schema_claims).map_err(|e| vcp::convert_to_crypto_library_error("AC2C", "to_from_test", e))?;
    let (issuer_public, issuer_secret) = Issuer::new(&cred_schema);
    // println!("issuer_public: {:?}", issuer_public);
    // println!("issuer_secret: {:?}", issuer_secret);

    let x = to_api((issuer_public, sdcts.to_vec()))?;
    // println!("to_api((issuer_public, sdcts.to_vec())): {:?}", x);

    let y = to_api(issuer_secret)?;
    // println!("to_api(issuer_secret): {:?}", y);

    let sd = SignerData::new(x,y);
    // println!("SignerData: {:?}", sd);

    let SignerData { signer_public_data, signer_secret_data } = sd;
    // println!("signer_public_data : {:?}", signer_public_data);
    // println!("signer_secret_data : {:?}", signer_secret_data);

    let (s, sdcts) : (IssuerPublic, Vec<ClaimType>) = from_api(&signer_public_data)?;
    // println!("from_api(*signer_public_data): s: {:?}", s);
    // println!("from_api(*signer_public_data): sdcts: {:?}", sdcts);

    let (issuer_public, issuer_secret) = Issuer::new(&cred_schema);
    let x   = to_api((issuer_public, sdcts.to_vec()))?;
    let z1  : Issuer = from_api(&signer_secret_data)?;
    let z2  = to_api(z1)?;
    let sd2 = SignerData::new(x,z2);
    //println!("{:#?}", sd2);

    let rpk_str = "eyJtZXNzYWdlX2dlbmVyYXRvciI6ImI4ZDk2NDlkMjJlYzc3N2UyZTQ0OTAxYzAwODU4NmQxZjEwMWRhNjE5ZmUyMDM2ZWRhMjZhNzFmMDFiMjdlZjllNzRiMzZiNTFmMmRkMTM0MDZlOTNmZTAwZGUxZmVlOSIsImJsaW5kZXJfZ2VuZXJhdG9yIjoiOTZmYmQzYWY2OTFkODIzYThhYmZmMzhjZTdmMjQ1NjYxODdiODkwZjU0MTdkYTNmNmE5N2MyYTc3MjE3MmNlNmVlNzI1NjdjZmNhZjBkYWFlMTJjZGY3N2RlNDc1MTFjIn0=";
    let rpk_str_x = from_opaque(rpk_str)?;
    assert_eq!(rpk_str_x, "{\"message_generator\":\"b8d9649d22ec777e2e44901c008586d1f101da619fe2036eda26a71f01b27ef9e74b36b51f2dd13406e93fe00de1fee9\",\"blinder_generator\":\"96fbd3af691d823a8abff38ce7f24566187b890f5417da3f6a97c2a772172ce6ee72567cfcaf0daae12cdf77de47511c\"}");
    //println!("XXXXXXXXXXXX rpk_str_x: {:?}", rpk_str_x);

    let rpk = RangeProofProvingKey(rpk_str.to_string());
    let xxx : RangeProofCommitmentSetup = from_api(&rpk)?;
    //println!("YYYYYYYYYYYY rpk_str_x: {:?}", xxx);

    Ok(())
}

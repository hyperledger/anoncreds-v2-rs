// ------------------------------------------------------------------------------
use credx::vcp::VCPResult;
use credx::vcp::api;
use credx::vcp::r#impl::to_from::*;
use credx::vcp::r#impl::ac2c::accumulator::*;
use credx::vcp::r#impl::json::util::*;
use credx::vcp::interfaces::types::*;
// ------------------------------------------------------------------------------
use credx::prelude::vb20;
// ------------------------------------------------------------------------------

const PRINT_ENABLED : bool = false;

#[test]
fn accumulator_serialization() -> VCPResult<()> {
    let CreateAccumulatorResponse {
        new_accum_data  : AccumulatorData { public_data : api_public, secret_data : _},
        new_accum_value : api_acc
    } = create_accumulator_data()(0)?;
    if PRINT_ENABLED { println!("api_public {:?}", api_public) };
    if PRINT_ENABLED { println!("api_acc {:?}", api_acc) };

    let ac2c_pk : vb20::PublicKey   = from_api(&api_public)?;
    if PRINT_ENABLED { println!("ac2c_pk {:?}", ac2c_pk) };

    let ac2c_acc : vb20::Accumulator = from_api(&api_acc)?;
    if PRINT_ENABLED { println!("ac2c_ac {:?}", ac2c_acc) };

    let api_acc_ett = encode_to_text(&api_acc)?;
    if PRINT_ENABLED { println!("api_acc_ett {:?}", api_acc_ett) };
    let api_acc_dft : api::Accumulator = decode_from_text("api_acc_ett", &api_acc_ett)?;
    if PRINT_ENABLED { println!("api_acc_dft {:?}", api_acc_dft) };

    let ac2c_acc_prime : vb20::Accumulator = from_api(&api_acc_dft)?;
    if PRINT_ENABLED { println!("ac2c_acc_prime {:?}", ac2c_acc_prime) };

    assert_eq!(ac2c_acc, ac2c_acc_prime);

    Ok(())
}



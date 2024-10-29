// ------------------------------------------------------------------------------
use credx::vcp::VCPResult;
use credx::vcp::Error;
use credx::vcp::UnexpectedError;
use credx::vcp::r#impl::catch_unwind_util::*;
use credx::get_location_and_backtrace_on_panic;
// ------------------------------------------------------------------------------
use indexmap::IndexMap;
use std;
// ------------------------------------------------------------------------------

const PRINT_ENABLED : bool = false;

// This function models the behavior of VCP functions that
// - return a VCPResult (i.e., either Ok or Err).
// - or panics in different ways (for example, an underlying library panics)

fn foo(i : i32) -> VCPResult<i32>
{
    match i
    {
        -4 => {
            let m: IndexMap<i32,i32> = IndexMap::new();
            Ok(m[1])
        }
        -3 => std::panic::panic_any(3.1459),
        -2 => std::panic::panic_any(-2),
        -1 => panic!("no good {:?}", -1),
        0  => Ok(0),
        x  => Err(Error::General(format!("{:?}", x))),
    }
}

// This function is to show that the macro works with different types of fuctions.
fn bar(i : i32, f : f32, s : &str) -> VCPResult<(i32, f32, &str)> {  Ok((i, f, s)) }

#[test]
fn catch_unwind_test() -> VCPResult<()> {
    // the line number is available, but not tested to make the test more stable
    const LOCATION_STRING : &str =
        "fn: \"vcp_test::vcp::impl::catch_unwind_test::foo\", file: \"./tests/vcp/impl/catch_unwind_test.rs\", line:";

    let x = get_location_and_backtrace_on_panic!(bar(1, 2.2, "bar"));
    if PRINT_ENABLED { println!(" 1 {:?}", x) };
    assert_eq!(x, Ok((1, 2.2, "bar")));

    let x = get_location_and_backtrace_on_panic!(foo(1));
    if PRINT_ENABLED { println!(" 1 {:?}", x) };
    assert_eq!(x, Err(Error::General("1".to_string())));

    let x = get_location_and_backtrace_on_panic!(foo(0));
    if PRINT_ENABLED { println!(" 0 {:?}", x) };
    assert_eq!(x, Ok(0));

    let x = get_location_and_backtrace_on_panic!(foo(-1));
    if PRINT_ENABLED { println!("-1 {:?}", x) };
    match x {
        Err(Error::UnexpectedError(UnexpectedError { reason, backtrace })) => {
            assert_eq!(reason, "no good -1".to_string());
            let bt = format!("{:?}", backtrace);
            if PRINT_ENABLED { println!("{:?}", bt) };
            // the line number is available, but not tested to make the test more stable
            assert!(bt.contains(LOCATION_STRING));
        },
        e => assert_eq!(format!("{:?} is not as expected", e), "")
    }

    let x = get_location_and_backtrace_on_panic!(foo(-2));
    if PRINT_ENABLED { println!("-2 {:?}", x) };
    match x {
        Err(Error::UnexpectedError(UnexpectedError { reason, backtrace })) => {
            assert_eq!(reason, "-2".to_string());
            let bt = format!("{:?}", backtrace);
            if PRINT_ENABLED { println!("{:?}", bt) };
            // the line number is available, but not tested to make the test more stable
            assert!(bt.contains(LOCATION_STRING));
        },
        e => assert_eq!(format!("{:?} is not as expected", e), "")
    }

    let x = get_location_and_backtrace_on_panic!(foo(-3));
    if PRINT_ENABLED { println!("-3 {:?}", x) };

    // Depending on compiler version, output is something like
    // "Err(Error::FileError(TypeId { t: 8711759054683223602271599665973969982 } \"&dyn core::any::Any + core::marker::Send\" Any { .. }"
    // Look at parts inside to avoid dependence on compiler version.
    match x {
        Err(Error::UnexpectedError(UnexpectedError { reason, backtrace })) => {
            assert!(reason.contains("TypeId"));
            assert!(reason.contains("&dyn core::any::Any + core::marker::Send"));
            let bt = format!("{:?}", backtrace);
            if PRINT_ENABLED { println!("{:?}", bt) };
            assert!(bt.contains(LOCATION_STRING));
        },
        e => assert_eq!(format!("{:?} is not as expected", e), "")
    }

    let x = get_location_and_backtrace_on_panic!(foo(-4));
    if PRINT_ENABLED { println!("-4 {:?}", x) };
    match x {
        Err(Error::UnexpectedError(UnexpectedError { reason, backtrace })) => {
            assert_eq!(reason, "IndexMap: index out of bounds");
            let bt = format!("{:?}", backtrace);
            if PRINT_ENABLED { println!("{:?}", bt) };
            assert!(bt.contains(LOCATION_STRING));
            assert!(bt.contains("indexmap::map::IndexMap<K,V,S>"));
        },
        e => assert_eq!(format!("{:?} is not as expected", e), "")
    }

    Ok(())
}


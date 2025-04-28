use std::collections::HashMap;
use credx::vcp::Error;

use credx::vcp::r#impl::util::*;

#[test]
pub fn insert_throw_if_present_2_lvl_test() {
    let mut m1 = HashMap::<&str,HashMap::<&str,usize>>::new();
    insert_throw_if_present_2_lvl(&"A",&"a",1, &mut m1, Error::General, &[])
        .expect("insert to succeed");
    insert_throw_if_present_2_lvl(&"A",&"a",1, &mut m1, Error::General, &[])
        .expect_err("second insert should have failed");
    insert_throw_if_present_2_lvl(&"A",&"b",1, &mut m1, Error::General, &[])
        .expect("insert to succeed");
    insert_throw_if_present_2_lvl(&"B",&"a",1, &mut m1, Error::General, &[])
        .expect("insert to succeed");
}

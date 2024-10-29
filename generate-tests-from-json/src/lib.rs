extern crate proc_macro;
use proc_macro as pm1;
extern crate proc_macro2;
use proc_macro2 as pm2;
extern crate quote;
use quote::quote;
extern crate serde;
use serde::Deserialize;
extern crate serde_json;
use std::fs;
use std::collections::HashMap;

/// Summary: for each file in `<dir_path>`, generate a test function with the
/// body `<test_runner>(<file_path>)`, where <test_runner> is the name of a function
/// that loads a test from <file_path> and runs it.
///
/// `input` should have the form:
/// ```ignore
/// <test_runner>, <dir_path>, <override_path>
/// ```
/// where:
/// <test_runner> is the name of a function of type `impl Fn(&str)` that
///   can load a JSON file and run the test it represents,
/// <dir_path> is a directory path for JSON test files, and
/// <override_path> is a path to a file containing any library-specific overrides
/// to use.
///
/// If the filename contains 'expected_to_fail',
///   add #[should_panic] to test.
/// If the filename contains 'slow' or 'SLOW',
///   ensure test is ignored if the ignore_slow feature is enabled.
/// If the filename contains 'slowslow' or 'SLOWSLOW',
///   ensure test is ignored if either ignore_slow or ignore_slow_slow feature is enabled.
///
/// Running, ignoring slow and slowslow tests
///
///      Consider the following test files:
///
///      - json_test_014_slow_verifies_with_small_range_below_signed_value.json
///      - json_test_015_slow_verifies_with_small_range_above_signed_value.json
///      - json_test_017_slowslow_encrypt_and_decrypt_one_attribute_no_verification_yet.json
///      - json_test_018_slowslow_encrypt_and_decrypt_one_attribute_and_verify.json
///
///      If the specified override file contains no overrides, then:
///
///      $ cargo test vcp::r#impl::general::proof_system::direct::tests -- --test-threads=1
///
///      test vcp::r#impl::general::proof_system::direct::tests::test_014_slow_verifies_with_small_range_below_signed_value ... ok
///      test vcp::r#impl::general::proof_system::direct::tests::test_015_slow_verifies_with_small_range_above_signed_value ... ok
///      test vcp::r#impl::general::proof_system::direct::tests::test_017_slowslow_encrypt_and_decrypt_one_attribute_no_verification_yet ... FAILED
///      test vcp::r#impl::general::proof_system::direct::tests::test_018_slowslow_encrypt_and_decrypt_one_attribute_and_verify ... FAILED
///
///      The failures are currently expected.  Note that all four tests ran.
///
///      $ cargo test --features=ignore_slow vcp::r#impl::general::proof_system::direct::tests -- --test-threads=1
///
///      test vcp::r#impl::general::proof_system::direct::tests::test_014_slow_verifies_with_small_range_below_signed_value ... ignored
///      test vcp::r#impl::general::proof_system::direct::tests::test_015_slow_verifies_with_small_range_above_signed_value ... ignored
///      test vcp::r#impl::general::proof_system::direct::tests::test_017_slowslow_encrypt_and_decrypt_one_attribute_no_verification_yet ... ignored
///      test vcp::r#impl::general::proof_system::direct::tests::test_018_slowslow_encrypt_and_decrypt_one_attribute_and_verify ... ignored
///
///      All tests with 'slow' are ignored
///
///      $ cargo test --features=ignore_slow_slow vcp::r#impl::general::proof_system::direct::tests -- --test-threads=1
///
///      test vcp::r#impl::general::proof_system::direct::tests::test_014_slow_verifies_with_small_range_below_signed_value ... ok
///      test vcp::r#impl::general::proof_system::direct::tests::test_015_slow_verifies_with_small_range_above_signed_value ... ok
///      test vcp::r#impl::general::proof_system::direct::tests::test_017_slowslow_encrypt_and_decrypt_one_attribute_no_verification_yet ... ignored
///      test vcp::r#impl::general::proof_system::direct::tests::test_018_slowslow_encrypt_and_decrypt_one_attribute_and_verify ... ignored
///
///      Only tests with 'slowslow' are ignored
///
///      Looking up overrides
///
///      The override_path argument specifies the location of a JSON file that represents a map from
///      "distilled" test labels to overrides.  Both test names and keys in the JSON overrides file
///      are distilled in order to reduce sensitivity of the lookup to details such as instances of
///      "slow", "slowslow" (lower and upper case), double underscores, etc.
///
///      Overrides
///
///      Possible overrides are:
///      - NotSoSlow: Run the test even if its name contains "slow" or "slowslow" and one of the ignore_slow* features is enabled
///      - Skip(reason): Skip the test and display the reason
///      - Fail(reason): Fail the test and include the reason in the failure output
///
///      TODO: revisit "slowness" handling; replace NotSoSlow with (something like) Slowness(n), and enable skipping all tests
///      with greater than a specified "slowness"
///
///      Override examples:
///
///      Suppose the specified override file contains
///        {"014_verifies_with_small_range_below_signed_value": {"tag": "NotSoSlow"}}
///
///      $ cargo test --features=ignore_slow vcp::r#impl::general::proof_system::direct::tests -- --test-threads=1
///
///      test vcp::r#impl::general::proof_system::direct::tests::test_014_verifies_with_small_range_below_signed_value ... ok
///      test vcp::r#impl::general::proof_system::direct::tests::test_015_slow_verifies_with_small_range_above_signed_value ... ignored
///      test vcp::r#impl::general::proof_system::direct::tests::test_017_slowslow_encrypt_and_decrypt_one_attribute_no_verification_yet ... ignored
///      test vcp::r#impl::general::proof_system::direct::tests::test_018_slowslow_encrypt_and_decrypt_one_attribute_and_verify ... ignored
///
///      Same as before, except test 014 is no longer labeled as 'slow', and is no longer ignored
///
///      Suppose AC2C-overrides.json contains:
///
///      {"014_verifies_with_small_range_below_signed_value": {"tag": "Fail", "contents": "don't run this test because of some deficiency in the library"},
///       "015_verifies_with_small_range_above_signed_value": {"tag": "Skip", "contents": "can't run this test for some external reason"}}
///
///      $ make test
///
///      test vcp::r#impl::general::proof_system::direct::tests::test_014_slow_verifies_with_small_range_below_signed_value ... FAILED
///      test vcp::r#impl::general::proof_system::direct::tests::test_015_slow_verifies_with_small_range_above_signed_value ... ignored, can't run this test for some external reason
///
///      ---- vcp::r#impl::general::proof_system::direct::tests::test_014_slow_verifies_with_small_range_below_signed_value stdout ----
///      thread 'vcp::r#impl::general::proof_system::direct::tests::test_014_slow_verifies_with_small_range_below_signed_value' panicked at
///             'don't run this test because of some deficiency in the library', tests/vcp/impl/general/proof_system/direct.rs:69:5
///
///      About override labels
///
///      To make it easier to override tests and avoid adverse interactions with SLOW annotations,
///      key values in the overrides file and (file)names of tests are preprocessed before matching:
///      - all instances of slow or SLOW are removed
///      - a required prefix like json_test_012_ is removed from test file names

#[proc_macro]
pub fn map_test_over_dir(input: pm1::TokenStream) -> pm1::TokenStream {
    // for a running example, suppose:
    //   input = `run_func "my/target/dir" "my/target/dir/overrides.json"`,
    //   the directory `my/target/dir` contains files:
    //     `json_test_001_my_file_1.txt`, `json_test_002_my_file_2.txt`, `json_test_003_my_file_expected_to_fail_3.txt`,
    //     `json_test_004_my/target/dir/my_file_slow_4.txt`, and `json_test_005_my_file_slowslow_5.txt`, and
    //   the file `my/target/dir/overrides.json` contains a JSON representation of a LibrarySpecificTestHandlers
    //
    // Target output for normal filenames:
    //
    //      #[test]
    //      fn test_001_my_file_1() {
    //        run_func("my/target/dir/json_test_001_my_file_1.txt")
    //      }
    //
    //      #[test]
    //      fn test_002_my_file_2() {
    //        run_func("my/target/dir/json_test_002_my_file_2.txt")
    //      }
    //
    // - or, if my/target/dir/overrides.json contains {"002_my_file_2", Fail("failure reason")},:
    //
    //      #[test]
    //      fn test_002_my_file_2() {
    //        panic!("failure reason")
    //      }
    //
    // - or, if my/target/dir/overrides.json contains {"002_my_file_2", Skip("reason for skipping")},:
    //
    //      #[ignore = "reason for skipping"]
    //      fn test_002_my_file_2() {}
    //
    // Target output for test from file with `expected_to_fail` in the name:
    //
    //      #[test]
    //      #[should_panic]
    //      fn test_003_my_file_slow_3() {
    //        run_func("my/target/dir/my_file_expected_to_fail_3.txt")
    //      }
    //
    // Target output for test from file with `slow` but not `slowslow` in the name:
    //
    //      #[test]
    //      #[cfg_attr(feature = "ignore_slow", ignore)]
    //      fn test_004_my_file_slow_4() {
    //        run_func("my/target/dir/my_file_slow_4.txt")
    //      }
    //
    // Target output for test from file with `slowslow` in the name:
    //
    //      #[test]
    //      #[cfg_attr(any(feature = "ignore_slow", feature = "ignore_slow_slow"),ignore)]
    //      fn test_005_my_file_slowslow_5() {
    //        run_func("my/target/dir/my_file_slowslow_5.txt")
    //      }

    let input: pm2::TokenStream = input.into();
    let input_tokens = input.into_iter().collect::<Vec<_>>();
    let (test_runner, dir_path_lit, override_fn_lit) = match &input_tokens[..] {
        [pm2::TokenTree::Ident(test_runner),
         pm2::TokenTree::Punct(sep1),
         pm2::TokenTree::Literal(dir_path_lit),
         pm2::TokenTree::Punct(sep2),
         pm2::TokenTree::Literal(override_fn_lit)
        ]
            if sep1.as_char() == ',' && sep2.as_char() == ',' =>
        {
            (test_runner, dir_path_lit, override_fn_lit)
        }
        _ => panic!("invalid input; should be of the form `<test_runner>, \"<dir_path>\"`"),
    };
    // running example continued:
    //   test_runner = `run_func`
    //   dir_path_lit = `"my/target/dir"`
    //   override_fn_lit = `my/target/dir/overrides.json`

    // load overrides and "distills" keys so lookups don't fail due to differences in "slow" annotations
    let override_file_name = override_fn_lit.to_string().replace("\"", "");
    let overrides: LibrarySpecificTestHandlers = {
        if override_file_name == "" {
            HashMap::new()
        } else {
            let f_in = fs::File::open(override_file_name.clone())
                .map_err(|e| panic!("Error opening {override_file_name}: {}", e.to_string())).unwrap();
            serde_json::from_reader::<_,LibrarySpecificTestHandlers>(f_in)
                .unwrap()
                .into_iter()
                .map(|(k,v)| (k.distill_test_name(), v))
                .collect()
        }
    };

    // get all filenames in the specified test directory (ignore subdirectories)
    let dir_path = dir_path_lit.to_string().replace("\"", "");
    // running example continued:
    //   dir_path = "my/target/dir"
    let dir:Vec<fs::DirEntry> = fs::read_dir(dir_path)
        .unwrap()
        .into_iter()
        .filter (|r| r.is_ok())
        .map    (|r| r.unwrap())
        .filter (|r| !((*r).path().is_dir()))
        .collect();

    // output for each test file
    let mut output = pm2::TokenStream::new();
    for dir_entry in dir {
        // get filename and derive test name
        let file_name = &dir_entry.file_name();
        let file_basename = file_name
            .to_str()
            .unwrap()
            .split_once(".")
            .unwrap()
            .0
            .replace("\"", "")
            .remove_expected_prefix()
            .unwrap();
        let mut test_name = file_basename.clone();
        // "distill" name and lookup override, if any
        let lookup_str = file_basename.distill_test_name().to_string();
        let r#override = overrides.get(&lookup_str);
        // remove "slow" from test_name if override is NotSoSlow
        if r#override == Some(&TestHandler::NotSoSlow) {
           test_name = lookup_str;
        }
        // prepend "test_": a valid identifier cannot start with a digit
        test_name = "test_".to_string() + &test_name;
        // compute file path literal to be used for the test
        let file_path = dir_entry.path().to_str().unwrap().to_owned();
        let file_path_lit = pm2::TokenTree::Literal(pm2::Literal::string(&file_path));
        // running example continued:
        //    first iteration:
        //      file_name = "my_file_1.txt"
        //      file_basename = "my_file_1"
        //      file_path = "my/target/dir/my_file_1.txt"
        //   second iteration:
        //      file_name = "my_file_2.txt"
        //      file_basename = "my_file_2"
        //      file_path = "my/target/dir/my_file_2.txt"
        //   ...

        // declare test and attributes for expected_to_fail tests
        let mut ts: pm2::TokenStream = quote! {
            #[test]
        };
        let test_name_as_string = test_name.to_string();
        if test_name_as_string.contains("expected_to_fail") {
            ts.extend(quote! {
                #[should_panic]
            })
        }
        // configure attributes to enable ignoring slow tests
        if test_name_as_string.clone().is_slow() {
            ts.extend(quote! {
                #[cfg_attr(feature = "ignore_slow", ignore)]
            })
        }
        if test_name_as_string.is_slow_slow() {
            ts.extend(quote! {
                #[cfg_attr(any(feature = "ignore_slow", feature = "ignore_slow_slow"),ignore)]
            })
        }
        // compute test_name
        let test_name_id = pm2::Ident::new(&test_name, pm2::Span::call_site());
        // generate output for the test itself, taking override (if any) into account
        match r#override {
            Some(TestHandler::NotSoSlow) | None =>
                ts.extend(quote!{
                    fn #test_name_id() {
                        #test_runner(#file_path_lit)
                    }
                }),
            Some(TestHandler::Fail(s)) => {
                let err_str = pm2::Literal::string(s);
                let test_name_id =
                    pm2::Ident::new(&(test_name + "_overridden_to_fail"), pm2::Span::call_site());
                ts.extend(quote!{
                    fn #test_name_id() {
                        panic!(#err_str)
                    }
                })},
            Some(TestHandler::Skip(s)) => {
                let skip_str = pm2::Literal::string(s);
                ts.extend(quote! {
                    #[ignore = #skip_str]
                    fn #test_name_id() {}
                })}
        }
        output.extend(ts);
    }
    output.into()
}

// Ideally we would export this here to avoid DRY fail with
// tests/vcp/impl/general/proof_system/utils.rs, but proc-macro crate types "currently" cannot do so
type TestLabel = String;
type LibrarySpecificTestHandlers = HashMap<TestLabel, TestHandler>;

#[derive(Clone,Debug,PartialEq,Deserialize)]
#[serde(content = "contents", tag = "tag")]
enum TestHandler {
    Skip(String),  // String contains reason for skipping, shown in test output
    Fail(String),  // String shows reason for failing, shown in failure explanation in test output
    NotSoSlow,
}

trait StringExt where Self: Sized {
    fn remove_expected_prefix(self) -> Result<Self,Box<String>>;
    fn remove_slow(self) -> Self;
    fn is_slow(self) -> bool;
    fn is_slow_slow(self) -> bool;
    fn remove_double_underscores(self) -> Self;
    fn distill_test_name(self) -> Self;
}

impl StringExt for String {
    fn remove_expected_prefix(self) -> Result<Self,Box<String>> {
        if let Some(rest) = self.strip_prefix("json_test_") {
            let (num,rest2) = rest.split_at(NUM_DIGITS_FOR_JSON_TEST_IDS);
            if !num.chars().all(|c| char::is_digit(c,10)) {
                return Err(Box::new(format!("{NUM_DIGITS_FOR_JSON_TEST_IDS}-digit test id not found after \"json_test_\" in {self}")));
            };
            match rest2.strip_prefix("_") {
                Some(_) => Ok(rest.to_string()),
                None    => return Err(Box::new(format!("expected underscore after \"json_test_nnn\" not found in {self}")))
            }
        } else {
            return Err(Box::new(format!("expected test filename prefix \"json_test_\" not found in {self}")));
        }
    }
    fn remove_slow(self) -> String {
        self.replace("slow","").replace("SLOW","")
    }
    fn is_slow(self) -> bool {
        (self.contains("slow") || self.contains("SLOW")) && !(self.is_slow_slow())
    }
    fn is_slow_slow(self) -> bool {
        self.contains("slowslow") || self.contains("SLOWSLOW")
    }
    fn remove_double_underscores(self) -> String {
        let x = self.clone().replace("__","_");
        if x == self {
            return x;
        };
        x.remove_double_underscores()
    }
    fn distill_test_name(self) -> String {
        self.remove_slow().remove_double_underscores()
    }
}


const NUM_DIGITS_FOR_JSON_TEST_IDS: usize = 3;

// NOTE: run tests like this:
// $ cd generate-tests-from-json
// $ cargo test
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_expected_prefix_happy() {
        assert_eq!("json_test_012_therest".to_string().remove_expected_prefix(),
                   Ok("012_therest".to_string()));
    }
    #[test]
    fn test_remove_expected_prefix_short() {
        let Err(res) = "short".to_string().remove_expected_prefix()
        else {
            panic!("should have reported missing prefix");
        };
        assert!(res.contains("expected test filename prefix") &&
                res.contains("json_test_") &&
                res.contains("not found in"))
    }
    #[test]
    fn test_remove_expected_prefix_not_digits() {
        let Err(res) = "json_test_12c".to_string().remove_expected_prefix()
        else {
            panic!("should have reported {}-digit id missing", NUM_DIGITS_FOR_JSON_TEST_IDS);
        };
        assert!(res.contains(&format!("{}-digit test id not found after", NUM_DIGITS_FOR_JSON_TEST_IDS)) &&
                res.contains("json_test_"))
    }
    #[test]
    fn test_remove_expected_prefix_missing_underscore() {
        let Err(res) = "json_test_123rest".to_string().remove_expected_prefix()
        else {
            panic!("should have reported missing underscore");
        };
        assert!(res.contains("expected underscore after") &&
                res.contains("json_test_nnn"))
    }
    #[test]
    fn test_remove_double_underscore() {
        assert_eq!("xyz".to_string().remove_double_underscores(), "xyz");
        assert_eq!("_x_yz".to_string().remove_double_underscores(), "_x_yz");
        assert_eq!("x_y__z".to_string().remove_double_underscores(), "x_y_z");
        assert_eq!("x_y___z".to_string().remove_double_underscores(), "x_y_z");
    }
}

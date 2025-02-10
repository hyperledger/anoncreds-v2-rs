// ------------------------------------------------------------------------------
use credx::vcp::interfaces::types::*;
// ------------------------------------------------------------------------------

// Tests for serialization of API types.
// We want to ensure
// - the serialization matches our Haskell implementations serialization (modulo field order)
// - particularly sum types.

#[test]
fn sum_types() -> Result<(),serde_json::Error> {
    let cts   = [ClaimType::CTText, ClaimType::CTInt].to_vec();
    let cts_s = serde_json::to_string(&cts)?;
    assert_eq!(cts_s, "[\"CTText\",\"CTInt\"]");

    let dvi   = DataValue::DVInt(3);
    let dvi_s = serde_json::to_string(&dvi)?;
    assert_eq!(dvi_s, "{\"tag\":\"DVInt\",\"contents\":3}");

    let sp    = SharedParamValue::SPVOne(dvi);
    let sp_s  = serde_json::to_string(&sp)?;
    assert_eq!(sp_s, "{\"tag\":\"SPVOne\",\"contents\":{\"tag\":\"DVInt\",\"contents\":3}}");

    let vs  : Vec<DataValue> = serde_json::from_str(values())?;
    // println!("vs {:?}", vs);
    let vs_s = serde_json::to_string(&vs)?;
    // the reason these are NOT equals is because
    // Haskell puts "contents" first
    // Rust puts "tag" first
    assert_ne!(remove_whitespace(&vs_s), remove_whitespace(values()));
    let vs1 : Vec<DataValue> = serde_json::from_str(&vs_s)?;
    // But what is created from either tag order is equal.
    assert_eq!(vs, vs1);

    let rpw : Warning = serde_json::from_str(reveal_privacy_warning())?;
    // println!("rpw {:?}", rpw);
    let rpw_s = serde_json::to_string(&rpw)?;
    assert_ne!(remove_whitespace(&rpw_s), remove_whitespace(reveal_privacy_warning()));
    let rpw1 : Warning = serde_json::from_str(&rpw_s)?;
    assert_eq!(rpw, rpw1);

    // --------------------------------------------------

    Ok(())
}

#[test]
pub fn round_trip() -> Result<(),serde_json::Error> {

    // --------------------------------------------------

    let spd2 : SignerPublicData = serde_json::from_str(signer_data())?;
    // println!("spd2 {:?}", spd2);
    let spd2_s = serde_json::to_string(&spd2)?;
    assert_eq!(remove_whitespace(&spd2_s), remove_whitespace(signer_data()));

    // --------------------------------------------------

    let dlrq : CredentialReqs = serde_json::from_str(dl_reqs())?;
    // println!("dlrq {:?}", dlrq);
    let dlrq_s = serde_json::to_string(&dlrq)?;
    // Haskell and Rust emit the same virtual JSON, but in different orders.
    assert_ne!(remove_whitespace(&dlrq_s), remove_whitespace(signer_data()));
    let dlrq2 : CredentialReqs = serde_json::from_str(&dlrq_s)?;
    assert_eq!(dlrq, dlrq2);

    // --------------------------------------------------

    let spvo : SharedParamValue = serde_json::from_str(spvone())?;
    // println!("spvo {:?}", spvo);
    match &spvo {
        SharedParamValue::SPVOne(o) => match o {
            DataValue::DVText(t) => {
                // println!("YES {:?}", t);
                let x : SignerPublicData = serde_json::from_str(t)?;
                // println!("YES {:?}", x);
                assert_eq!(x.signer_public_setup_data, SignerPublicSetupData("5LDYxXSJd".to_string()));
                let spvo_s = serde_json::to_string(&spvo)?;
                // not equal but equivalent
                assert_ne!(remove_whitespace(&spvo_s), remove_whitespace(spvone()));
                let spvo2 : SharedParamValue = serde_json::from_str(&spvo_s)?;
                assert_eq!(spvo, spvo2);
            }
            x => { panic!("expected 'DataValue::DVText(_)' but got {:?}", x); }
        },
        x => { panic!("expected 'SharedParamValue::SPVOne(_)' but got {:?}", x); }
    }

    // --------------------------------------------------

    Ok(())
}

// ------------------------------------------------------------------------------
// This data was generated from the JSON serialization of the internal Haskell prototype.
// In some cases it was editted (whitespace added) for readability.
// Commit: ? (this was done a while back and the commit was not noted.  In the future commits will be specified.)

fn reveal_privacy_warning() -> &'static str {
    r#"{"contents":["cl",0,"xxx"],"tag":"RevealPrivacyWarning"}"#
}

fn signer_data() -> &'static str {
    r#"{
        "signerPublicSetupData": "WyJ7XCJnMVwiOlsxMzcsNjcsOTcsMjUxLDE1LDM0LDE5MCwyNTUsNDEsNDEsNSwyMDQsMjEyLDEzMCwwLDg4LDIzOSwxMTEsMTE2LDkyLDU2LDEzMiwxMDEsMTEsMTU3LDE4OSw3OSwxOTUsODEsMTcxLDE0MiwxMTUsMTIsNDAsMTcyLDE0OCwyLDIzLDg1LDk4LDg0LDU5LDAsMTc5LDkxLDMwLDEyLDEzMV0sXCJnMlwiOlsxMjksMTgsNTcsMTQ0LDIwNSwxMjQsNzAsMTUsMjE2LDY4LDg4LDI1NCwyNTUsMTgzLDIxMywxMTksMjAzLDMwLDE1Nyw1NCwyMzIsMjA0LDEzNywyMzIsMTQwLDE3NiwyMSw4MywzMCwxOTAsMjQ4LDc3LDE1NiwxMDQsMTEyLDc0LDYwLDM1LDIwNiwyMjYsMTk3LDk2LDgwLDE2MiwxNDgsNTQsMTQ5LDEzOCwxOCw4MSw1MSwxMDQsODQsMTMsMTQzLDE2NCw0Miw2OSw4MiwxOCw3MSwyMDIsMTM3LDk2LDExNSwxOTAsMjQ5LDIxMCwyNSwxNDEsMTYwLDkyLDcwLDE2NiwxNjAsNTUsMTM5LDg1LDIwLDQsMjI0LDE1MiwxMjQsMTcxLDIyOCwxNTksMTA1LDQ0LDUsMzEsMjQxLDE1NiwxNDUsNzQsNzIsMjQyXSxcImhfMFwiOlsxNzcsNzksMTcwLDE4OSwxOTcsMTQyLDUsMjI2LDEzMywxNTcsMTg4LDE0Nyw4Miw3LDIzMywxODksMTE5LDE1NiwxMjQsNzcsOTUsMTY4LDEzLDkwLDg1LDAsMTEsOTMsMTk0LDY0LDEwNCwxNzIsMTksMzAsMjQ3LDk2LDE2MiwxMDgsNCwxMjgsMTE4LDYyLDIwNSwxMTQsMjIyLDMzLDI5LDU3XSxcImhcIjpbWzE0MSwxNjQsNTYsMjMzLDY0LDM1LDc4LDIwMiwxMDQsMTIyLDUyLDE1LDE4LDI0OSwzNiwxNTQsMTQ2LDEwOCwxMzAsMTY4LDI0MywxMjQsNTAsODksMjAwLDM0LDIyMSwyNDksMTQyLDI0NSwxNjksMjM3LDk5LDE0NSw1Niw0LDI5LDIyMSwxODIsMTMsMTkzLDI5LDEsMTcxLDU3LDExNiw4OCwyMjldLFsxODQsMTU0LDI0NywxMjYsMTI5LDEwLDY3LDE5Niw0NiwzOSwyNTAsMjM5LDIwNywxMDgsMTIyLDE4MSwwLDE0MCwyNywxNjQsMjI1LDE0MCwyMzUsMjEyLDE1MSwyNDIsMTcyLDYwLDIwMywzMywxNDgsNjEsNDYsMTIsMjM3LDIxNywxMTgsMTEzLDMyLDExLDEwOSwxMzIsMTM4LDE3NCwyNTQsMjI5LDMsMTI0XSxbMTYwLDc1LDE0MCwxMTMsNTIsMTE0LDE4MCwxNjAsMjI0LDkyLDc3LDIwMiwxOTAsMjE1LDY1LDE3MiwxNCw4MywzNywxMiwxMTMsMTE0LDU0LDE0MiwxNjUsNzEsMjU1LDIzLDMyLDE0MywyNDUsMTc3LDkzLDEwOSwxMDMsMTM1LDQ5LDY5LDU4LDE1OCwyNSw4Miw2OSwxNTYsMzYsNjksMTg5LDEzNV0sWzE0MCw2LDUzLDY4LDU3LDU5LDEyLDE3NCwxODEsNjksMjI0LDIwNSw2MSw5OCwyNDUsOTQsNTMsMjEzLDE2MywxNzksMjAwLDIxNSwyNDksMjQsMjMxLDEwNywzMywyLDI0NSwyMTcsMTkxLDIxOSwyMTYsMTE2LDQzLDIzOSwyMDMsMTIxLDk0LDE0LDExNiwyOSwxNTcsMTIsMjAyLDExLDIxOCw2OV0sWzE3MiwxMjgsMjI3LDEwNywxNTIsNzQsMjQ1LDY4LDE1NCwyMjIsMTM1LDIwNCwxMzYsNjUsNTksMTk0LDkyLDIwMSw5NywxMzksMTc0LDE1OSwxMTUsMTg3LDEyMSwxODgsNjYsMTAxLDMsMjQ5LDM1LDEwMiwyMCw3OSw1NywyMjYsODEsMjIxLDE4NSw3MywxMzksMTQ2LDIzOSwyNDIsMTAzLDI1MiwxODcsMTgwXV19IiwiWzE3MSw2NSwxNDgsMjAzLDI1MCwxODcsMTQyLDE0OSwxNTcsMTgzLDQzLDE3Nyw5MCw0NiwxNDUsMTkwLDE3OCwxNDAsMTcyLDIyNCwyMDYsNzMsMjEsMTI3LDQxLDM0LDU4LDIyNSwxNDIsNzMsMjEyLDI1NCwyMzUsMjEsMTI4LDE4NiwxMDksNjAsMjQ5LDEsMTI2LDE5LDM5LDEyMCwzMCwxNzUsMSwxNDAsMTYsMTk3LDg0LDY1LDk2LDE1OCw2MSwyMDEsMjAxLDE2MCwxMDYsMTY2LDE1MywyMzQsNDUsMTgyLDYxLDg0LDI0OSwxMTYsNywxOTQsNDcsMTUsMjA0LDIyNiwxMDIsNTAsOTYsMTI2LDI1LDE5Myw4OSwyMDEsMTg3LDIyNCwxMzQsMjQ4LDY4LDIxNCw5MywxMjQsNTEsNzIsNDEsMjcsMjE5LDYxXSJd",
        "signerPublicSchema"   : ["CTText", "CTInt", "CTInt", "CTAccumulatorMember", "CTEncryptableText"]
       }"#
}

fn values() -> &'static str {
    r#"[{"contents": "brown",       "tag": "DVText"},
        {"contents": 37000,         "tag": "DVInt"},
        {"contents": 181,           "tag": "DVInt"},
        {"contents": "abcdef",      "tag": "DVText"},
        {"contents": "123-45-6789", "tag": "DVText"}]"#

}

fn dl_reqs() -> &'static str {
    r#"{"disclosed"   :[0],
        "encryptedFor":[{"index":4,"label":"SCOTUS"}],
        "equalTo"     :[{"fromIndex":4,"toIndex":1,
                         "toLabel":"MonthlySubscription1.0SignerPublicData"}],
        "inAccum"     :[],
        "inRange"     :[{"index":1,"maxLabel":"daysBornAfterJan_1_1900MAX",
                          "minLabel":"daysBornAfterJan_1_1900MIN","rangeProvingKeyLabel":"rangeProvingKey"}],
        "notInAccum"  :[],
        "signerLabel" :"DriverLicense1.0SignerPublicData"}"#
}

fn spvone() -> &'static str {
    r#"{"contents":{"contents":"{\"signerPublicSchema\":[\"CTText\",\"CTInt\",\"CTInt\",\"CTAccumulatorMember\",\"CTEncryptableText\"],\"signerPublicSetupData\":\"5LDYxXSJd\"}","tag":"DVText"},"tag":"SPVOne"}"#
}

// ------------------------------------------------------------------------------
// utilities

pub fn remove_whitespace(s: &str) -> String {
    let s = s.trim();
    let mut collapsed = String::new();
    for c in s.chars() {
        if collapsed.chars().last().is_some() {
            if c.is_whitespace() {
                continue;
            } else {
                collapsed.push(c);
            }
        } else {
            collapsed.push(c);
        }
    }
    collapsed
}

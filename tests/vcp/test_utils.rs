use credx::str_vec_from;
use credx::vcp::r#impl::util::ic_semi;
use credx::vcp::Error;

pub fn missing_case_insensitive (
    msg: &str, t: String, l: Vec<String>
) -> Option<Error> {
    use missing_case_insensitive_support::desensitize;
    let missing: Vec<_> = l.iter()
        .filter(|x| {!desensitize(t.clone())
                     .contains(&desensitize(x.to_string()))})
        .collect();
    if missing.is_empty() {
        None
    } else {
        Some(Error::General(ic_semi(&str_vec_from!(msg, t,
            "expected to contain all of",
            format!("{l:?}"),
            "but lacks", format!("{missing:?}")
        ))))
    }
}

// For syntactic convenience when all expected strings are constants
pub fn missing_case_insensitive_const (
    msg: &str, t: String, l: &[&str]
) -> Option<Error> {
    missing_case_insensitive(msg, t, l.iter().map(|x| x.to_string()).collect())
}


mod missing_case_insensitive_support {
    pub fn desensitize(s : String) -> String {
        s.chars().filter(|x| *x != '_').collect::<String>()
            .chars().map(|c| c.to_lowercase().collect::<String>()).collect()
    }
}

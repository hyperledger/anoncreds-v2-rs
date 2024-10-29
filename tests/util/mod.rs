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

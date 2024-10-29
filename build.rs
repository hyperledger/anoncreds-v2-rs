use walkdir::WalkDir;

// Instruct cargo build to recompile whenever JSON test-related files change

fn main() {
    for entry in WalkDir::new("tests/data/JSON/TestSequences")
        .into_iter()
        .filter_map(Result::ok) {
        if entry.path().is_file() {
            println!("cargo:rerun-if-changed={}", entry.path().display());
        }
    }
}

// Synthetic fixture: pseudo-Rust, never compiled or executed.
use std::path::Path;

fn import_archive(entry_name: &str, out_dir: &Path) {
    let hostile = "../../etc/passwd"; // CWE-22 marker
    let name = if entry_name.is_empty() { hostile } else { entry_name };
    let dest = out_dir.join(name); // guard: no canonicalize + prefix check
    std::fs::write(dest, b"synthetic").unwrap(); // sink
}

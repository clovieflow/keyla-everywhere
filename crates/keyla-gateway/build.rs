//! Embeds the built dashboard so a packaged binary serves the console without
//! a `dist/` directory next to it. When the dashboard has not been built yet,
//! the generated table is empty and the runtime falls back to `DASHBOARD_DIST`.

use std::io::Write;
use std::path::{Path, PathBuf};

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let dist = manifest.join("../../dist/dashboard");
    println!("cargo:rerun-if-changed=../../dist/dashboard");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default());
    let target = out_dir.join("embedded_assets.rs");
    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    collect(&dist, &dist, &mut entries);
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut file = std::fs::File::create(&target).expect("create embedded asset table");
    writeln!(file, "pub static EMBEDDED_ASSETS: &[(&str, &[u8])] = &[").unwrap();
    for (name, path) in &entries {
        writeln!(
            file,
            "    ({:?}, include_bytes!({:?})),",
            name,
            path.to_string_lossy()
        )
        .unwrap();
    }
    writeln!(file, "];").unwrap();
}

fn collect(root: &Path, current: &Path, entries: &mut Vec<(String, PathBuf)>) {
    let Ok(read) = std::fs::read_dir(current) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, entries);
        } else if let Ok(relative) = path.strip_prefix(root) {
            entries.push((relative.to_string_lossy().replace('\\', "/"), path.clone()));
        }
    }
}

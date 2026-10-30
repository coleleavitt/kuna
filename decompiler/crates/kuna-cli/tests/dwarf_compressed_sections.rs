//! Compressed DWARF sections are read, not skipped.
#![cfg(target_os = "linux")]

use crate::common;
use common::process;
use std::process::Command;

const SOURCE: &str = "static int counter;\nint bump(int k) { counter += k; return counter; }\n\
void _start(void) { for (;;) bump(1); }\n";

#[test]
fn compressed_debug_info_names_and_types_the_program() {
    if process::optional_output(Command::new("clang").arg("--version")).is_none() {
        return;
    }
    let root = common::scratch_file("dwarf-compressed", "dir");
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("sample.c");
    std::fs::write(&source, SOURCE).unwrap();
    for compression in ["-gz=zlib", "-gz=zstd"] {
        let binary = root.join(&compression[4..]);
        process::required_output(
            Command::new("clang")
                .args(["-O1", "-gdwarf-4", compression, "-ffreestanding", "-fno-pic", "-nostdlib"])
                .args(["-no-pie", "-fuse-ld=lld", "-Wl,--no-dynamic-linker", "-Wl,--discard-all"])
                .arg(&source)
                .arg("-o")
                .arg(&binary),
        );
        let (body, err, status) = common::run_kuna(&["decompile", binary.to_str().unwrap(), "bump"]);
        assert_eq!(status, 0, "{compression}: {err}");
        assert!(body.contains("int bump(int k)") && body.contains("counter"), "{compression}:\n{body}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

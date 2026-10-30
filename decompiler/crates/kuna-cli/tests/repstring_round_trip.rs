//! `repstring`: the memcpy/memset a `rep movs`/`rep stos` loop decompiles to
//! computes what the source computed, recompiled on the host.
use crate::common;
use std::process::Command;

fn emitted(option: &str) -> String {
    let (output, error, status) = common::run_kuna(&[
        "decompile-all",
        &common::fixture("repstring_x86_64"),
        "--json",
        "--option",
        "repstring",
        option,
    ]);
    assert_eq!(status, 0, "{error}");
    let document: serde_json::Value = serde_json::from_str(&output).unwrap();
    document["functions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap().to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn rep_string_loops_round_trip_as_memcpy_and_memset() {
    let body = emitted("on");
    assert!(!body.contains("while"), "a repeat loop survives:\n{body}");
    assert!(body.contains("builtin_memcpy(") && body.contains("builtin_memset("), "{body}");
    assert!(emitted("off").contains("while"), "off keeps the loops");
    let source = std::fs::read_to_string(common::fixture("repstring.c")).unwrap();
    let mut reference = source.replace("#include <string.h>", "");
    for f in ["copy_struct", "copy_n", "fill_n", "zero_rec", "copy_end"] {
        reference = reference.replace(&format!(" {f}("), &format!(" ref_{f}(")).replace(&format!("*{f}("), &format!("*ref_{f}("));
    }
    let program = format!(
        r#"
#include <string.h>
#define builtin_memcpy memcpy
#define builtin_memset memset
{reference}
{body}
int main(void) {{
  char a[128], b[128], src[128];
  for (int i = 0; i < 128; i++) src[i] = (char)(i * 7 + 3);
  for (unsigned long n = 0; n < 100; n += 9) {{
    memset(a, 1, sizeof a); memset(b, 1, sizeof b);
    copy_n(a, src, n); ref_copy_n(b, src, n);
    if (memcmp(a, b, sizeof a)) return 1;
    fill_n(a, (int)n - 50, n); ref_fill_n(b, (int)n - 50, n);
    if (memcmp(a, b, sizeof a)) return 2;
    if ((long)copy_end(a, src, n) - (long)a != (long)n || ref_copy_end(b, src, n) - b != (long)n) return 3;
    if (memcmp(a, b, sizeof a)) return 4;
  }}
  copy_struct((void *)a, (void *)src); ref_copy_struct((void *)b, (void *)src);
  zero_rec((void *)(a + 64)); ref_zero_rec((void *)(b + 64));
  return memcmp(a, b, sizeof a) ? 5 : 0;
}}
"#
    );
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("round_trip.c");
    std::fs::write(&path, &program).unwrap();
    let mut checked = 0;
    for cc in ["gcc", "clang"] {
        if Command::new(cc).arg("--version").output().is_err() {
            continue;
        }
        for opt in ["-O0", "-O2"] {
            let executable = root.path().join(format!("{cc}{opt}"));
            let built =
                Command::new(cc).args([opt, "-w"]).arg(&path).arg("-o").arg(&executable).output().unwrap();
            assert!(built.status.success(), "{}\n{program}", String::from_utf8_lossy(&built.stderr));
            let status = Command::new(&executable).status().unwrap();
            assert!(status.success(), "{cc} {opt}: {status}\n{body}");
            checked += 1;
        }
    }
    assert!(checked > 0, "a C compiler is required");
}

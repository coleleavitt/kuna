//! `repstring` and `copyrun`: the memcpy/memset a `rep movs`/`rep stos` loop
//! or an unrolled copy decompiles to computes what the source computed,
//! recompiled on the host.
use crate::common;
use std::process::Command;

fn emitted(option: &str) -> String {
    emitted_from("repstring_x86_64", "repstring", option)
}

fn emitted_from(fixture: &str, name: &str, option: &str) -> String {
    emitted_functions(fixture, name, option, None)
}

fn emitted_functions(fixture: &str, name: &str, option: &str, functions: Option<&str>) -> String {
    let path = common::fixture(fixture);
    let mut args = vec!["decompile-all", path.as_str(), "--json", "--option", name, option];
    if let Some(functions) = functions {
        args.extend(["--functions", functions]);
    }
    let (output, error, status) = common::run_kuna(&args);
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
    compile_and_run(&program, &body);
}

fn compile_and_run(program: &str, body: &str) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("round_trip.c");
    std::fs::write(&path, program).unwrap();
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

#[test]
fn unrolled_copies_round_trip_as_memcpy() {
    let all = emitted_from("copyrun_x86_64", "copyrun", "on");
    let off = emitted_from("copyrun_x86_64", "copyrun", "off");
    assert_eq!(all.matches("builtin_memcpy(").count(), 3, "{all}");
    assert!(!off.contains("builtin_memcpy("), "{off}");
    let body = emitted_functions("copyrun_x86_64", "copyrun", "on", Some("copy_struct,shift,copy31,small"));
    let program = format!(
        r#"
#include <string.h>
#define builtin_memcpy memcpy
typedef struct {{ unsigned long field_0x0, field_0x8; }} struct_0;
struct big {{ long a[8]; }};
struct pair {{ struct big first, second; }};
static void ref_copy_struct(struct big *d, const struct big *s) {{ *d = *s; }}
static void ref_shift(struct pair *p) {{ p->second = p->first; }}
static void ref_copy31(char *d, const char *s) {{ memcpy(d, s, 31); }}
{body}
int main(void) {{
  struct pair a, b;
  char s[64], x[64], y[64];
  for (int i = 0; i < 64; i++) {{ s[i] = (char)(i * 5 + 1); x[i] = y[i] = 0; }}
  memcpy(&a, s, 64); memcpy(&b, s, 64);
  copy_struct((void *)&a.second, (void *)s); ref_copy_struct(&b.second, (const struct big *)s);
  if (memcmp(&a, &b, sizeof a)) return 1;
  shift((void *)&a); ref_shift(&b);
  if (memcmp(&a, &b, sizeof a)) return 2;
  copy31((void *)x, (void *)s); ref_copy31(y, s);
  return memcmp(x, y, sizeof x) ? 3 : 0;
}}
"#
    );
    compile_and_run(&program, &body);
}

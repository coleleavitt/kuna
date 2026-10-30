# FID callee fixture

The fixture for `fidcallees` (`kuna-console/tests/verify_fid_callees.rs`).

| File | What |
|---|---|
| `lib.c` | `scale_a`, `scale_b`; `wrap_a`/`wrap_b`, the same instructions calling one each (one full hash, two names); `bump`, an 11-byte stub with no callee. |
| `main.c` | A libc-free `_start` that calls the wrappers and `bump`. |
| `lib.o` | **Vendored.** `lib.c` compiled (below). |
| `lib.fid` | **Vendored.** `kuna fid build lib.o` (format version 2, with callees). |
| `prog` | **Vendored.** `lib.o` + `main.o` linked without libc and stripped. `wrap_a` 0x401040, `wrap_b` 0x401060, `bump` 0x401080. |

## Build

```bash
CF="-O2 -ffreestanding -fno-stack-protector -fno-pic -fcf-protection=none"
gcc $CF -c lib.c -o lib.o
gcc $CF -c main.c -o main.o
gcc -nostdlib -static -no-pie -Wl,--build-id=none lib.o main.o -o prog.full
strip --strip-all -o prog prog.full
kuna fid build lib.o -o lib.fid --lang x86:LE:64:default --cspec gcc
```

#!/usr/bin/env python3
"""Build iokit_kext.macho: a tiny arm64 MH_KEXT_BUNDLE with two IOKit-style
classes for the `iokitclasses` pass.

Base (super: none) and Derived (super: Base) are registered by one
__mod_init_func initializer that calls an unnamed OSMetaClass constructor
with (&X::gMetaClass, "X", &Super::gMetaClass, size) and then stores the
X::MetaClass vtable into X::gMetaClass. Each class has a vtable
[0, 0, ~X, ~X, X::getMetaClass, m1, m2(, m3)] in __DATA_CONST,__const.
Derived overrides m2 and adds m3. Only meta_of_derived, Base::m1 and
Base::m2 have symbols. Pointers are plain absolute words (no fixups).

Run from this directory: python3 gen_iokit.py
"""
import struct

B = 0xFFFFFFF007A00000
TEXT, EXEC, CONST, DATA, LINKEDIT = 0x0, 0x4000, 0x5000, 0x6000, 0x7000
CSTRING = 0x3000

def u32(*v): return struct.pack("<" + "I" * len(v), *v)
def u64(*v): return struct.pack("<" + "Q" * len(v), *v)

def adrp(rd, pc, target):
    delta = ((B + target) >> 12) - ((B + pc) >> 12)
    return 0x90000000 | ((delta & 3) << 29) | (((delta >> 2) & 0x7FFFF) << 5) | rd
def add_lo(rd, rn, target): return 0x91000000 | ((target & 0xFFF) << 10) | (rn << 5) | rd
def bl(pc, target): return 0x94000000 | (((target - pc) // 4) & 0x3FFFFFF)
def movw(rd, imm): return 0x52800000 | (imm << 5) | rd

RET = 0xD65F03C0
names = {"Base": CSTRING, "Derived": CSTRING + 5}
BASE_META, DERIVED_META = DATA, DATA + 0x40

code = {}
pc = EXEC
def func(name, words):
    global pc
    code[name] = pc
    out = []
    for w in words:
        out.append(w(pc + 4 * len(out)) if callable(w) else w)
    blob[name] = out
    pc += 4 * len(out)
    pc = (pc + 15) & ~15
blob = {}

def addr_of(rd, target):
    return [lambda p, rd=rd, t=target: adrp(rd, p, t), add_lo(rd, rd, target)]

vt = {}  # filled after function addresses are known
CONST_BASE = CONST + 0x100
vt["Base"] = CONST_BASE
vt["Derived"] = CONST_BASE + 0x40
vt["BaseMeta"] = CONST_BASE + 0x90
vt["DerivedMeta"] = CONST_BASE + 0xC8

func("ctor", [RET])
init = [0xA9BF7BFD, 0xA9BF4FF4]
init += addr_of(19, BASE_META) + addr_of(1, names["Base"]) + [0xAA1F03E2, 0xAA1303E0, movw(3, 0x20)]
init += [lambda p: bl(p, code["ctor"])]
init += addr_of(16, vt["BaseMeta"] + 16)[:1] + [add_lo(16, 16, vt["BaseMeta"]), 0x91004210, 0xF9000010]
init += addr_of(19, DERIVED_META) + addr_of(1, names["Derived"]) + addr_of(2, BASE_META) + [0xAA1303E0, movw(3, 0x30)]
init += [lambda p: bl(p, code["ctor"])]
init += addr_of(16, vt["DerivedMeta"])[:1] + [add_lo(16, 16, vt["DerivedMeta"]), 0x91004210, 0xF9000270]
init += [0xA8C14FF4, 0xA8C17BFD, RET]
func("init", init)
func("Base_getMetaClass", addr_of(0, BASE_META) + [RET])
func("Derived_getMetaClass", addr_of(0, DERIVED_META) + [RET])
for n, v in [("Base_D1", 0), ("Base_D0", 0), ("Derived_D1", 0), ("Derived_D0", 0),
             ("Base_m1", 1), ("Base_m2", 2), ("Derived_m2", 3), ("Derived_m3", 4),
             ("BaseMeta_D1", 0), ("BaseMeta_D0", 0), ("BaseMeta_alloc", 5),
             ("DerivedMeta_D1", 0), ("DerivedMeta_D0", 0), ("DerivedMeta_alloc", 6), ("Meta_shared", 7)]:
    func(n, [movw(0, v), RET])
func("meta_of_derived", addr_of(0, DERIVED_META) + [RET])
text_end = pc

c = code
vtables = {
    "Base": ["Base_D1", "Base_D0", "Base_getMetaClass", "Base_m1", "Base_m2"],
    "Derived": ["Derived_D1", "Derived_D0", "Derived_getMetaClass", "Base_m1", "Derived_m2", "Derived_m3"],
    "BaseMeta": ["BaseMeta_D1", "BaseMeta_D0", "Meta_shared", "BaseMeta_alloc"],
    "DerivedMeta": ["DerivedMeta_D1", "DerivedMeta_D0", "Meta_shared", "DerivedMeta_alloc"],
}

strtab = b"\0"
stroff = {}
for n in [b"_meta_of_derived", b"__ZN4Base2m1Ev", b"__ZN4Base2m2Ev"]:
    stroff[n] = len(strtab)
    strtab += n + b"\0"
strtab = strtab.ljust((len(strtab) + 7) & ~7, b"\0")
syms = b"".join(u32(stroff[n]) + bytes([0x0F, 2]) + struct.pack("<H", 0) + u64(B + c[f])
                for n, f in [(b"_meta_of_derived", "meta_of_derived"), (b"__ZN4Base2m1Ev", "Base_m1"),
                             (b"__ZN4Base2m2Ev", "Base_m2")])
symoff, str_off = LINKEDIT, LINKEDIT + len(syms)
linkedit = syms + strtab

def section(seg, name, addr, size, flags=0):
    return name.ljust(16, b"\0") + seg.ljust(16, b"\0") + u64(B + addr, size) + u32(addr, 0, 0, 0, flags, 0, 0, 0)
def segment(name, addr, size, sections=(), prot=5):
    body = name.ljust(16, b"\0") + u64(B + addr, size, addr, size) + u32(prot, prot, len(sections), 0) + b"".join(sections)
    return u32(0x19, 8 + len(body)) + body

cmds = [
    segment(b"__TEXT", TEXT, 0x4000, [section(b"__TEXT", b"__cstring", CSTRING, 13, 0x2)]),
    segment(b"__TEXT_EXEC", EXEC, 0x1000, [section(b"__TEXT_EXEC", b"__text", EXEC, text_end - EXEC, 0x80000400)]),
    segment(b"__DATA_CONST", CONST, 0x1000, [section(b"__DATA_CONST", b"__mod_init_func", CONST, 8, 0x9),
                                              section(b"__DATA_CONST", b"__const", CONST_BASE, 0x100)], prot=1),
    segment(b"__DATA", DATA, 0x1000, [section(b"__DATA", b"__data", DATA, 0x80)], prot=3),
    segment(b"__LINKEDIT", LINKEDIT, len(linkedit), prot=1),
    u32(0x2, 24, symoff, 3, str_off, len(strtab)),
    u32(0xB, 80, 0, 0, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
]
image = bytearray(LINKEDIT + len(linkedit))
def place(off, data): image[off:off + len(data)] = data
place(0, u32(0xFEEDFACF, 0x0100000C, 0, 0xB, len(cmds), sum(map(len, cmds)), 0x85, 0) + b"".join(cmds))
place(CSTRING, b"Base\0Derived\0")
for name, words in blob.items():
    place(c[name], u32(*words))
place(CONST, u64(B + c["init"]))
for k, slots in vtables.items():
    place(vt[k], u64(0, 0) + b"".join(u64(B + c[s]) for s in slots))
place(LINKEDIT, linkedit)
open("iokit_kext.macho", "wb").write(image)

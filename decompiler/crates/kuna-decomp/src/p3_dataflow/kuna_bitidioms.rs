//! (kuna `bitidioms`) Byte swaps and rotates written out as shifts and ORs
//! become `bswap(x)` and `rotl(x, n)`.
//!
//! SLEIGH lifts `bswap`/`rev` and `rol`/`ror` into the shift-and-mask p-code
//! they mean, and compilers emit the same shape for the portable C, so the
//! decompiled C spells a byte swap as four masked shifts ORed together.
//! Hex-Rays prints `_byteswap_ulong` / `__ROL4__` (its slot-filling bswap
//! matcher and rotate rule); this rule does the same for an `INT_OR` tree:
//!
//! * rotate: `(x << n) | (x >> (W - n))` with constant `n` and the same `x`;
//! * byte swap: followed through byte-aligned shifts, byte masks, ORs of
//!   disjoint bytes, zero extensions and byte pieces, the OR moves byte `i` of
//!   one `x` to byte `N - 1 - i`, every byte exactly once. This also reads the
//!   staged swap AArch64 `rev` lifts to (bytes within halfwords, then
//!   halfwords, then the halves), which is why it runs before the rotate test.

use kuna_base::types::{int4, uintb};
use kuna_num::opcodes::OpCode;

use crate::action::{ActionGroupList, Rule};
use crate::context::{OpId, VarnodeId};
use crate::funcdata::Funcdata;
use crate::userop::{BUILTIN_BSWAP, BUILTIN_ROTL};

/// `[x op c]` with `c` a constant input in slot 1 (or 0 for a commutative op).
fn const_operand(data: &Funcdata, op: OpId) -> Option<(VarnodeId, u64)> {
    let o = data.obank().get(op)?;
    let (a, b) = (o.get_in(0)?, o.get_in(1)?);
    let is_const = |v: VarnodeId| data.vbank().get(v).is_some_and(|v| v.is_constant());
    let value = |v: VarnodeId| data.vbank().get(v).map(|v| v.get_offset());
    if is_const(b) {
        return Some((a, value(b)?));
    }
    if o.code() == OpCode::CPUI_INT_AND && is_const(a) {
        return Some((b, value(a)?));
    }
    None
}

/// Where each byte of `vn` comes from: `Some(i)` is byte `i` of the source
/// `x`, `None` a zero byte. Followed through byte-aligned shifts, byte masks,
/// ORs of disjoint bytes, zero extensions and byte pieces; any other
/// definition is the source.
type Bytes = (VarnodeId, Vec<Option<usize>>);

fn bytes_of(data: &Funcdata, vn: VarnodeId, depth: u32, budget: &mut u32) -> Option<Bytes> {
    let v = data.vbank().get(vn)?;
    let size = v.get_size() as usize;
    if v.is_constant() || size == 0 || size > 8 {
        return None;
    }
    let source = Some((vn, (0..size).map(Some).collect()));
    if depth == 0 || *budget == 0 {
        return source;
    }
    *budget -= 1;
    let Some(def) = v.get_def() else { return source };
    let Some(o) = data.obank().get(def) else { return source };
    let mut sub = |vn: VarnodeId| bytes_of(data, vn, depth - 1, budget);
    match o.code() {
        OpCode::CPUI_INT_AND => {
            let (a, m) = const_operand(data, def)?;
            let (x, mut b) = sub(a)?;
            for (i, slot) in b.iter_mut().enumerate() {
                match (m >> (8 * i)) & 0xff {
                    0 => *slot = None,
                    0xff => {}
                    _ => return None,
                }
            }
            Some((x, b))
        }
        OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT => {
            let (a, c) = const_operand(data, def)?;
            if c % 8 != 0 {
                return None;
            }
            let k = (c / 8) as usize;
            let (x, b) = sub(a)?;
            let left = o.code() == OpCode::CPUI_INT_LEFT;
            let out = (0..size)
                .map(|i| if left { i.checked_sub(k).and_then(|j| b.get(j).copied().flatten()) } else { b.get(i + k).copied().flatten() })
                .collect();
            Some((x, out))
        }
        OpCode::CPUI_INT_OR => {
            let (x, a) = sub(o.get_in(0)?)?;
            let (y, b) = sub(o.get_in(1)?)?;
            if x != y {
                return None;
            }
            let mut out = Vec::with_capacity(size);
            for (p, q) in a.into_iter().zip(b) {
                out.push(match (p, q) {
                    (Some(_), Some(_)) => return None,
                    (p, None) => p,
                    (None, q) => q,
                });
            }
            Some((x, out))
        }
        OpCode::CPUI_INT_ZEXT => {
            let (x, mut b) = sub(o.get_in(0)?)?;
            b.resize(size, None);
            Some((x, b))
        }
        OpCode::CPUI_SUBPIECE => {
            let k = o.get_in(1).and_then(|c| data.vbank().get(c)).map(|c| c.get_offset() as usize)?;
            let (x, b) = sub(o.get_in(0)?)?;
            Some((x, (0..size).map(|i| b.get(i + k).copied().flatten()).collect()))
        }
        _ => source,
    }
}

/// `x` when `vn` rotated left by `rot` bytes reverses the bytes of an `x` of
/// its own size (`rot` is 0 for the INT_OR itself).
fn byte_swap_source(data: &Funcdata, vn: VarnodeId, rot: usize) -> Option<VarnodeId> {
    let size = data.vbank().get(vn)?.get_size();
    if !matches!(size, 2 | 4 | 8) {
        return None;
    }
    let (x, b) = bytes_of(data, vn, 10, &mut 64)?;
    if (x == vn && rot == 0) || data.vbank().get(x)?.get_size() != size {
        return None;
    }
    let n = size as usize;
    (0..n).all(|d| b[(d + n - rot % n) % n] == Some(n - 1 - d)).then_some(x)
}

/// `(x, n)` when the two inputs are `x << n` and `x >> (W - n)`.
fn rotate_source(data: &Funcdata, a: VarnodeId, b: VarnodeId, size: int4) -> Option<(VarnodeId, u64)> {
    let shift = |vn: VarnodeId, code: OpCode| -> Option<(VarnodeId, u64)> {
        let def = data.vbank().get(vn)?.get_def()?;
        (data.obank().get(def)?.code() == code).then(|| const_operand(data, def)).flatten()
    };
    let width = 8 * size as u64;
    for (l, r) in [(a, b), (b, a)] {
        if let (Some((x, n)), Some((y, m))) = (shift(l, OpCode::CPUI_INT_LEFT), shift(r, OpCode::CPUI_INT_RIGHT)) {
            if x == y && n > 0 && n < width && n + m == width && data.vbank().get(x).is_some_and(|v| v.get_size() == size) {
                return Some((x, n));
            }
        }
    }
    None
}

/// Rewrite a byte swap or a rotate (see the module docs).
pub struct RuleBitIdioms {
    group: String,
}

impl RuleBitIdioms {
    pub fn new(group: &str) -> RuleBitIdioms {
        RuleBitIdioms { group: group.to_string() }
    }
}

impl RuleBitIdioms {
    /// A `rotl(v, 8k)` whose `v` is a partial byte swap the rotate completes
    /// (the last stage of AArch64 `rev`, when the rotate was folded before the
    /// stages under it were simplified) becomes `bswap(x)`.
    fn rotate_to_swap(&self, op: OpId, data: &mut Funcdata) -> int4 {
        let Some(o) = data.obank().get(op) else { return 0 };
        let (Some(id), Some(v), Some(n)) = (o.get_in(0), o.get_in(1), o.get_in(2)) else { return 0 };
        let constant = |vn: VarnodeId| data.vbank().get(vn).filter(|v| v.is_constant()).map(|v| v.get_offset());
        if constant(id) != Some(BUILTIN_ROTL as u64) {
            return 0;
        }
        let Some(n) = constant(n).filter(|n| n % 8 == 0) else { return 0 };
        let Some(x) = byte_swap_source(data, v, (n / 8) as usize) else { return 0 };
        let id = data.new_constant(4, BUILTIN_BSWAP as uintb);
        if data.op_set_all_input(op, &[id, x]).is_err() {
            return 0;
        }
        1
    }
}

impl Rule for RuleBitIdioms {
    fn get_op_list(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_OR, OpCode::CPUI_CALLOTHER]
    }

    fn clone_rule(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Rule>> {
        grouplist.contains(&self.group).then(|| Box::new(RuleBitIdioms::new(&self.group)) as Box<dyn Rule>)
    }

    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> int4 {
        if !data.get_arch().bit_idioms {
            return 0;
        }
        let Some(o) = data.obank().get(op) else { return 0 };
        if o.code() == OpCode::CPUI_CALLOTHER {
            return self.rotate_to_swap(op, data);
        }
        let (Some(a), Some(b), Some(out)) = (o.get_in(0), o.get_in(1), o.get_out()) else { return 0 };
        let Some(size) = data.vbank().get(out).map(|v| v.get_size()) else { return 0 };
        if let Some(x) = byte_swap_source(data, out, 0) {
            let id = data.new_constant(4, BUILTIN_BSWAP as uintb);
            if data.op_set_all_input(op, &[id, x]).is_err() {
                return 0;
            }
            data.op_set_opcode(op, crate::typeop::type_op_for(OpCode::CPUI_CALLOTHER));
            return 1;
        }
        if let Some((x, n)) = rotate_source(data, a, b, size) {
            let id = data.new_constant(4, BUILTIN_ROTL as uintb);
            let count = data.new_constant(4, n as uintb);
            if data.op_set_all_input(op, &[id, x, count]).is_err() {
                return 0;
            }
            data.op_set_opcode(op, crate::typeop::type_op_for(OpCode::CPUI_CALLOTHER));
            return 1;
        }
        0
    }
}

//! (kuna `vaarg`) The x86-64 SysV `va_arg` expansion prints as `va_arg(ap, T)`.
//!
//! `va_arg(ap, T)` on a `va_list` in memory compiles to a diamond (gcc
//! `ix86_gimplify_va_arg`, clang `X86_64ABIInfo::EmitVAArg`): the block `C`
//! loads `gp_offset` (or `fp_offset` for a double) and branches; the register
//! arm `R` stores the offset plus `8n` (or 16) and forms
//! `reg_save_area + offset`; the memory arm `M` loads `overflow_arg_area` and
//! stores it plus the slot size; the join `J` reads `T` through the merged
//! address, or merges the two loads. kuna printed both arms:
//!
//! ```text
//! v2 = argp->gp_offset;
//! if (0x29 <= v2) { v7 = argp->overflow_arg_area; argp->overflow_arg_area = &v7[2]; }
//! else { v7 = (int *)((unsigned long)v2 + (long)argp->reg_save_area); argp->gp_offset = v2 + 8; }
//! ... *v7
//! ```
//!
//! [`ActionVaArg`] matches the diamond: every access is a LOAD or STORE at a
//! constant offset from one pointer `ap` (0 `gp_offset`, 4 `fp_offset`, 8
//! `overflow_arg_area`, 16 `reg_save_area`); the branch, evaluated on the
//! offset, sends the in-register values (below `48 - 8n`, or `176 - 16`) to
//! `R` and the others to `M`; `R` steps the offset by what it consumed and `M`
//! the overflow pointer by the value's size rounded up to 8; the value is `n * 8` (or 16)
//! bytes or fewer. When the join reads `T` through the merged address, that
//! LOAD becomes the CALLOTHER `va_arg(ap)` and both arms go. When each arm
//! loads the value, the arms may otherwise only do the same thing with it
//! (copy or store it alike, checked at the join's MULTIEQUALs); the CALLOTHER
//! goes before the branch, the register arm's load reads it, its offset step
//! goes (with the INDIRECTs that STORE left), and the memory arm goes with the
//! branch. The call's third input is 1 for the SSE half. It prints
//! `va_arg(ap,T)`, `T` the type of its output, or for an untyped output (or a
//! piece of a union) `double` (SSE, 8 bytes) or `int`/`long` by size.

use kuna_base::types::{int4, uintb};
use kuna_num::opcodes::OpCode;

use crate::action::{Action, ActionBase, ActionContext, ActionGroupList, ApplyResult};
use crate::context::{BlockId, OpId, VarnodeId};
use crate::funcdata::Funcdata;
use crate::kuna_strlenscan::{eval, taken};

/// `(base, offset)` of a pointer expression `base + offset`.
fn field(data: &Funcdata, mut v: VarnodeId) -> Option<(VarnodeId, u64)> {
    let mut off = 0u64;
    for _ in 0..4 {
        let Some(d) = data.vbank().get(v)?.get_def().and_then(|d| data.obank().get(d)) else { return Some((v, off)) };
        let k = |i: int4| d.get_in(i).and_then(|x| data.vbank().get(x)).filter(|x| x.is_constant()).map(|x| x.get_offset());
        match d.code() {
            OpCode::CPUI_COPY | OpCode::CPUI_CAST => v = d.get_in(0)?,
            OpCode::CPUI_INT_ADD | OpCode::CPUI_PTRSUB if k(1).is_some() => {
                off = off.wrapping_add(k(1)?);
                v = d.get_in(0)?;
            }
            OpCode::CPUI_PTRADD if k(1).is_some() && k(2).is_some() => {
                off = off.wrapping_add(k(1)?.wrapping_mul(k(2)?));
                v = d.get_in(0)?;
            }
            _ => return Some((v, off)),
        }
    }
    Some((v, off))
}

/// The pointer a LOAD or STORE goes through, and its access size.
fn access(data: &Funcdata, op: OpId) -> Option<(OpCode, VarnodeId, int4)> {
    let o = data.obank().get(op)?;
    let size = match o.code() {
        OpCode::CPUI_LOAD => data.vbank().get(o.get_out()?)?.get_size(),
        OpCode::CPUI_STORE => data.vbank().get(o.get_in(2)?)?.get_size(),
        _ => return None,
    };
    Some((o.code(), o.get_in(1)?, size))
}

/// Is `v` the `ap` field at `off` read by a LOAD of `size` bytes? Its LOAD op.
fn loaded(data: &Funcdata, v: VarnodeId, ap: VarnodeId, off: u64, size: int4) -> Option<OpId> {
    let mut v = v;
    for _ in 0..3 {
        let d = data.vbank().get(v)?.get_def()?;
        let o = data.obank().get(d)?;
        match o.code() {
            OpCode::CPUI_LOAD => {
                let (_, p, s) = access(data, d)?;
                return (s == size && field(data, p) == Some((ap, off))).then_some(d);
            }
            OpCode::CPUI_COPY | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT | OpCode::CPUI_CAST => v = o.get_in(0)?,
            _ => return None,
        }
    }
    None
}

struct Site {
    c: BlockId,
    to_m: int4,
    r: BlockId,
    m: BlockId,
    ap: VarnodeId,
    /// The J LOAD through the merged address, or the register arm's value LOAD.
    value: OpId,
    /// The address MULTIEQUAL, in the merged-address form.
    addr_phi: Option<OpId>,
    /// The register arm's offset STORE.
    step_store: OpId,
    /// The value comes from the SSE half of the save area (`fp_offset`).
    sse: bool,
}

fn defined_in(data: &Funcdata, v: VarnodeId, arm: BlockId) -> bool {
    data.vbank().get(v).and_then(|n| n.get_def()).and_then(|d| data.obank().get(d)).and_then(|o| o.get_parent()) == Some(arm)
}

/// The op whose output is `v`, when it is a COPY of `of` in `arm`.
fn copy_of(data: &Funcdata, v: VarnodeId, of: VarnodeId, arm: BlockId) -> bool {
    defined_in(data, v, arm)
        && data.vbank().get(v).and_then(|n| n.get_def()).and_then(|d| data.obank().get(d)).is_some_and(|o| o.code() == OpCode::CPUI_COPY && o.get_in(0) == Some(of))
}

fn arm_ops(data: &Funcdata, b: BlockId) -> Vec<OpId> {
    data.bb_ops(b).into_iter().filter(|&o| data.obank().get(o).is_some_and(|p| p.code() != OpCode::CPUI_BRANCH)).collect()
}

fn match_site(data: &Funcdata, c: BlockId) -> Option<Site> {
    let (t, f) = taken(data, c)?;
    let branch = data.bb_op_tail(c)?;
    let cond = data.obank().get(branch)?.get_in(1)?;
    // The offset the branch tests, loaded from `ap`.
    let cmp = data.obank().get(data.vbank().get(cond)?.get_def()?)?;
    let (a, b) = (cmp.get_in(0)?, cmp.get_in(1)?);
    let tested = if data.vbank().get(a)?.is_constant() { b } else { a };
    let ld = data.obank().get(data.vbank().get(tested)?.get_def()?)?;
    let tested_load = if ld.code() == OpCode::CPUI_LOAD { data.vbank().get(tested)?.get_def()? } else { return None };
    let (_, p, size) = access(data, tested_load)?;
    let (ap, off) = field(data, p)?;
    let (sse, limit, step) = match (off, size) {
        (0, 4 | 8) => (false, 48u64, 8u64),
        (4, 4) => (true, 176, 16),
        _ => return None,
    };
    let all = [c];
    let goes = |x: u64| eval(data, cond, &[(tested, x)], &all, 0).map(|v| if v != 0 { t } else { f });
    let (r, m) = (goes(if sse { 48 } else { 0 })?, goes(limit)?);
    if r == m {
        return None;
    }
    // The registers it consumes: the smallest offset the branch sends away.
    let n = (1..=2u64).find(|&n| goes(limit - step * n) == Some(r) && goes(limit - step * n + step) == Some(m))?;
    if sse && n != 1 {
        return None;
    }
    let consumed = step * n;
    let bb = |x: BlockId| data.bblocks_ref().block(x);
    if bb(r).size_in() != 1 || bb(m).size_in() != 1 || bb(r).size_out() != bb(m).size_out() || bb(r).size_out() > 1 {
        return None;
    }
    // Both arms reach one join, or both return.
    let join = (bb(r).size_out() == 1).then(|| bb(r).get_out(0));
    if let Some(j) = join {
        if bb(m).get_out(0) != j || bb(j).size_in() < 2 {
            return None;
        }
    }
    // R: STORE(ap+off, offset + consumed); maybe value = LOAD(reg_save_area + offset).
    let mut step_store = None;
    let mut r_value: Option<(OpId, VarnodeId, VarnodeId, int4)> = None;
    let mut r_sinks = Vec::new();
    for op in arm_ops(data, r) {
        let o = data.obank().get(op)?;
        match o.code() {
            OpCode::CPUI_STORE => {
                let (_, sp, _) = access(data, op)?;
                if field(data, sp) != Some((ap, off)) {
                    r_sinks.push((field(data, sp)?, o.get_in(2)?));
                    continue;
                }
                let sv = data.obank().get(data.vbank().get(o.get_in(2)?)?.get_def()?)?;
                let plus = sv.code() == OpCode::CPUI_INT_ADD
                    && sv.get_in(0).is_some_and(|x| x == tested || loaded(data, x, ap, off, size).is_some())
                    && sv.get_in(1).and_then(|k| data.vbank().get(k)).is_some_and(|k| k.is_constant() && k.get_offset() == consumed);
                if !plus || step_store.is_some() {
                    return None;
                }
                step_store = Some(op);
            }
            OpCode::CPUI_LOAD => {
                let (_, lp, s) = access(data, op)?;
                if field(data, lp).is_some_and(|(b, _)| b == ap) {
                    continue;
                }
                let (base, 0) = field(data, lp)? else { return None };
                if r_value.is_some() {
                    return None;
                }
                r_value = Some((op, o.get_out()?, base, s));
            }
            OpCode::CPUI_INT_ADD | OpCode::CPUI_PTRADD | OpCode::CPUI_PTRSUB | OpCode::CPUI_COPY | OpCode::CPUI_CAST | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT | OpCode::CPUI_INDIRECT => {}
            OpCode::CPUI_RETURN if join.is_none() => {}
            _ => return None,
        }
    }
    let step_store = step_store?;
    // M: o = LOAD(ap+8); STORE(ap+8, o + slot); maybe value = LOAD(o).
    let mut m_slot: Option<u64> = None;
    let mut m_value: Option<(VarnodeId, int4, VarnodeId)> = None;
    let mut m_sinks = Vec::new();
    let mut ovf: Option<VarnodeId> = None;
    for op in arm_ops(data, m) {
        let o = data.obank().get(op)?;
        match o.code() {
            OpCode::CPUI_LOAD => {
                let (_, lp, s) = access(data, op)?;
                if field(data, lp) == Some((ap, 8)) && s == 8 {
                    ovf = o.get_out();
                } else {
                    if m_value.is_some() {
                        return None;
                    }
                    m_value = Some((o.get_out()?, s, lp));
                }
            }
            OpCode::CPUI_STORE => {
                let (_, sp, _) = access(data, op)?;
                if field(data, sp) != Some((ap, 8)) {
                    m_sinks.push((field(data, sp)?, o.get_in(2)?));
                    continue;
                }
                if m_slot.is_some() {
                    return None;
                }
                let (base, slot) = field(data, o.get_in(2)?)?;
                m_slot = Some(slot);
                if Some(base) != ovf {
                    return None;
                }
            }
            OpCode::CPUI_INT_ADD | OpCode::CPUI_PTRADD | OpCode::CPUI_PTRSUB | OpCode::CPUI_COPY | OpCode::CPUI_CAST | OpCode::CPUI_INT_SEXT | OpCode::CPUI_INDIRECT => {}
            OpCode::CPUI_RETURN if join.is_none() => {}
            _ => return None,
        }
    }
    let ovf = ovf?;
    let m_slot = m_slot?;
    let slot_of = |size: int4| (size as u64).div_ceil(8).max(1) * 8;
    let save_plus_offset = |mut addr: VarnodeId| -> bool {
        for _ in 0..3 {
            match data.vbank().get(addr).and_then(|v| v.get_def()).and_then(|d| data.obank().get(d)) {
                Some(o) if matches!(o.code(), OpCode::CPUI_COPY | OpCode::CPUI_CAST) => match o.get_in(0) {
                    Some(x) => addr = x,
                    None => return false,
                },
                _ => break,
            }
        }
        let Some(d) = data.vbank().get(addr).and_then(|v| v.get_def()).and_then(|d| data.obank().get(d)) else { return false };
        if !matches!(d.code(), OpCode::CPUI_INT_ADD | OpCode::CPUI_PTRADD | OpCode::CPUI_PTRSUB) {
            return false;
        }
        let ins: Vec<VarnodeId> = (0..2).filter_map(|i| d.get_in(i)).collect();
        ins.len() == 2
            && ins.iter().any(|&x| loaded(data, x, ap, 16, 8).is_some())
            && ins.iter().any(|&x| loaded(data, x, ap, off, size).is_some() || x == tested)
    };
    // The pairs of values the arms hand on: the join's MULTIEQUAL inputs, or
    // the two RETURNs' inputs.
    let (ri, mi, phis, two_way) = match join {
        Some(j) => {
            let jb = bb(j);
            let phis: Vec<OpId> = data.bb_ops(j).into_iter().filter(|&op| data.obank().get(op).is_some_and(|o| o.code() == OpCode::CPUI_MULTIEQUAL)).collect();
            (jb.get_in_index(r), jb.get_in_index(m), phis, jb.size_in() == 2)
        }
        None => (0, 0, Vec::new(), false),
    };
    let returns = |b: BlockId| data.bb_op_tail(b).filter(|&o| data.obank().get(o).is_some_and(|p| p.code() == OpCode::CPUI_RETURN));
    let handed: Vec<(VarnodeId, VarnodeId)> = match join {
        Some(_) => phis.iter().filter_map(|&p| data.obank().get(p).and_then(|o| Some((o.get_in(ri)?, o.get_in(mi)?)))).collect(),
        None => {
            let (Some(rr), Some(mr)) = (returns(r), returns(m)) else { return None };
            let (ro, mo) = (data.obank().get(rr)?, data.obank().get(mr)?);
            if ro.num_input() != mo.num_input() {
                return None;
            }
            (1..ro.num_input()).filter_map(|i| Some((ro.get_in(i)?, mo.get_in(i)?))).collect()
        }
    };
    let site = |value: OpId, addr_phi: Option<OpId>| Site { c, to_m: bb(c).get_out_index(m), r, m, ap, value, addr_phi, step_store, sse };
    match (r_value, m_value) {
        // Each arm loads the value; whatever the arms do with it they do alike.
        (Some((r_load, rv, ra, rs)), Some((mv, ms, mp))) => {
            if rs != ms || rs as u64 > consumed || m_slot != slot_of(rs) || !save_plus_offset(ra) || field(data, mp) != Some((ovf, 0)) {
                return None;
            }
            r_sinks.sort();
            m_sinks.sort();
            let sinks_alike = r_sinks.len() == m_sinks.len() && r_sinks.iter().zip(&m_sinks).all(|(a, b)| a.0 == b.0 && a.1 == rv && b.1 == mv);
            if !sinks_alike {
                return None;
            }
            for &(x, y) in &handed {
                let through = |v: VarnodeId, arm: BlockId| -> VarnodeId {
                    match data.vbank().get(v).and_then(|n| n.get_def()).and_then(|d| data.obank().get(d)) {
                        Some(o) if o.code() == OpCode::CPUI_INDIRECT && o.get_parent() == Some(arm) => o.get_in(0).unwrap_or(v),
                        _ => v,
                    }
                };
                let alike = x == y
                    || through(x, r) == through(y, m)
                    || (x == rv && y == mv)
                    || (copy_of(data, x, rv, r) && copy_of(data, y, mv, m));
                if !alike {
                    return None;
                }
            }
            Some(site(r_load, None))
        }
        // J reads the value through the merged address.
        (None, None) if two_way && r_sinks.is_empty() && m_sinks.is_empty() => {
            let phi = phis.iter().copied().find(|&op| {
                data.obank().get(op).is_some_and(|o| o.get_in(mi).and_then(|x| field(data, x)) == Some((ovf, 0)) && o.get_in(ri).is_some_and(save_plus_offset))
            })?;
            let addr = data.obank().get(phi)?.get_out()?;
            let readers = data.descend_snapshot(addr);
            let [load] = readers.as_slice() else { return None };
            let (code, _, s) = access(data, *load)?;
            if code != OpCode::CPUI_LOAD || s as u64 > consumed || m_slot != slot_of(s) {
                return None;
            }
            for &other in phis.iter().filter(|&&p| p != phi) {
                let o = data.obank().get(other)?;
                if o.get_in(ri) != o.get_in(mi) {
                    return None;
                }
            }
            Some(site(*load, Some(phi)))
        }
        _ => None,
    }
}

/// Every output of an arm op is read only by arm ops or by the join's
/// MULTIEQUALs (which `match_site` checked), or by the value op.
fn arms_closed(data: &Funcdata, s: &Site) -> bool {
    let rb = data.bblocks_ref().block(s.r);
    let j = (rb.size_out() == 1).then(|| rb.get_out(0));
    let ok = |op: OpId| {
        Some(op) == s.addr_phi
            || op == s.value
            || data.obank().get(op).is_some_and(|o| {
                let b = o.get_parent();
                b == Some(s.r) || b == Some(s.m) || (j.is_some() && b == j && o.code() == OpCode::CPUI_MULTIEQUAL)
            })
    };
    [s.r, s.m].into_iter().all(|b| {
        arm_ops(data, b).into_iter().all(|op| {
            data.obank().get(op).is_some_and(|o| o.get_out().is_none_or(|out| data.descend_snapshot(out).into_iter().all(ok)))
        })
    })
}

fn rewrite(data: &mut Funcdata, s: &Site) -> kuna_base::error::KunaResult<()> {
    use kuna_base::error::KunaError;
    let id = data.new_constant(4, crate::userop::BUILTIN_VAARG as uintb);
    match s.addr_phi {
        Some(phi) => {
            let class = data.new_constant(4, s.sse as uintb);
            data.op_set_all_input(s.value, &[id, s.ap, class])?;
            data.op_set_opcode(s.value, crate::typeop::type_op_for(OpCode::CPUI_CALLOTHER));
            data.op_destroy(phi);
            for op in arm_ops(data, s.r).into_iter().rev() {
                if let Some((out, input)) = data.obank().get(op).filter(|o| o.code() == OpCode::CPUI_INDIRECT).and_then(|o| Some((o.get_out()?, o.get_in(0)?))) {
                    data.total_replace(out, input)?;
                }
                data.op_destroy(op);
            }
        }
        None => {
            let (rv, size, at) = {
                let o = data.obank().get(s.value).ok_or_else(|| KunaError::lowlevel("vaarg: value"))?;
                let rv = o.get_out().ok_or_else(|| KunaError::lowlevel("vaarg: out"))?;
                (rv, data.vbank().get(rv).map_or(8, |v| v.get_size()), o.get_addr().clone())
            };
            let branch = data.bb_op_tail(s.c).ok_or_else(|| KunaError::lowlevel("vaarg: branch"))?;
            let call = data.new_op(3, at);
            data.op_set_opcode_code(call, OpCode::CPUI_CALLOTHER);
            data.op_set_input(call, id, 0)?;
            data.op_set_input(call, s.ap, 1)?;
            let class = data.new_constant(4, s.sse as uintb);
            data.op_set_input(call, class, 2)?;
            let u = data.new_unique_out(size, call)?;
            data.op_insert_before(call, branch);
            data.total_replace(rv, u)?;
            // The step's STORE and the INDIRECTs it leaves go; then what only
            // fed the address dies.
            let step_ref = |data: &Funcdata, op: OpId| {
                data.obank().get(op).filter(|o| o.code() == OpCode::CPUI_INDIRECT).and_then(|o| o.get_in(1)).and_then(|iop| data.vbank().get(iop)).is_some_and(|v| {
                    use slotmap::KeyData;
                    OpId::from(KeyData::from_ffi(v.get_offset())) == s.step_store
                })
            };
            for op in arm_ops(data, s.r) {
                if step_ref(data, op) {
                    if let Some((out, input)) = data.obank().get(op).and_then(|o| Some((o.get_out()?, o.get_in(0)?))) {
                        data.total_replace(out, input)?;
                    }
                    data.op_destroy(op);
                }
            }
            data.op_destroy(s.step_store);
            loop {
                let dead: Vec<OpId> = arm_ops(data, s.r)
                    .into_iter()
                    .filter(|&op| {
                        data.obank().get(op).is_some_and(|o| {
                            matches!(o.code(), OpCode::CPUI_LOAD | OpCode::CPUI_INT_ADD | OpCode::CPUI_PTRADD | OpCode::CPUI_PTRSUB | OpCode::CPUI_CAST | OpCode::CPUI_INT_ZEXT)
                                && o.get_out().is_some_and(|w| data.descend_snapshot(w).is_empty())
                        })
                    })
                    .collect();
                if dead.is_empty() {
                    break;
                }
                for op in dead {
                    data.op_destroy(op);
                }
            }
        }
    }
    data.remove_branch(s.c, s.to_m)?;
    data.remove_unreachable_blocks(false, true)?;
    Ok(())
}

/// Fold the `va_arg` expansion into one call (see the module docs).
pub struct ActionVaArg {
    base: ActionBase,
}

impl ActionVaArg {
    pub fn boxed(g: &str) -> Box<dyn Action> {
        Box::new(ActionVaArg { base: ActionBase::new(0, "vaarg", g) })
    }
}

impl Action for ActionVaArg {
    fn base(&self) -> &ActionBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut ActionBase {
        &mut self.base
    }
    fn clone_filtered(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Action>> {
        grouplist.contains(self.get_group()).then(|| Box::new(ActionVaArg { base: self.base.clone() }) as Box<dyn Action>)
    }
    fn apply(&mut self, data: &mut Funcdata, _ctx: &mut ActionContext) -> ApplyResult {
        if !data.get_arch().va_arg {
            return 0;
        }
        let blocks: Vec<BlockId> = (0..data.bblocks_get_size()).map(|i| data.bblocks_get_block(i)).collect();
        for c in blocks {
            let Some(site) = match_site(data, c) else { continue };
            if !arms_closed(data, &site) {
                continue;
            }
            if rewrite(data, &site).is_err() {
                return 0;
            }
            self.base.count += 1;
            return 1;
        }
        0
    }
}

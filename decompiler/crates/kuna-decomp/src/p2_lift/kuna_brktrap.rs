//! (kuna `brktrap`) An AArch64 `brk` is a trap that ends its path.
//!
//! The AArch64 spec lifts `brk #imm` to
//! `tmp = imm; pc = SoftwareBreakpoint(tmp, inst_next); goto [pc];`. The jump's
//! target is a user-op result, so jump-table recovery cannot resolve it and
//! `truncateIndirectJump` turns it into an ordinary indirect call that returns:
//! `(*(void *)SoftwareBreakpoint(1,0x100003f8c))(); // jump-as-call` followed by
//! `return;`. Compilers plant `brk` only as a trap: clang's `__builtin_trap()` is
//! `brk #1` (Swift's `fatalError`, precondition and overflow traps, Rust's
//! `abort`), and its `__builtin_arm_trap(imm)` is `brk #imm` (arm64e's
//! pointer-authentication failure is `brk #0xc47x`).
//!
//! At flow classification the jump is recognized by its instruction: a CALLOTHER
//! of `SoftwareBreakpoint` writing the storage the BRANCHIND reads. The CALLOTHER
//! becomes a call of the synthetic user-op `__builtin_trap` (immediate 1) or
//! `__builtin_arm_trap(imm)` with no output, and the BRANCHIND becomes the
//! artificial no-return halt, so the path ends at the trap and nothing after it
//! prints.

use kuna_base::error::KunaResult;
use kuna_base::types::uintb;
use kuna_num::opcodes::OpCode;

use crate::context::OpId;
use crate::funcdata::Funcdata;
use crate::op::pcodeop_flags;

/// The user-op the AArch64 spec lifts `brk` to.
pub const BREAKPOINT_USEROP: &str = "SoftwareBreakpoint";
/// The synthetic user-op a `brk #1` prints as.
pub const TRAP_USEROP: &str = "__builtin_trap";
/// The synthetic user-op any other `brk #imm` prints as.
pub const ARM_TRAP_USEROP: &str = "__builtin_arm_trap";

/// The immediate clang's `__builtin_trap()` encodes.
const BUILTIN_TRAP_IMM: uintb = 1;

/// The user-op ids the rewrite reads and writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrapOps {
    pub breakpoint: u32,
    pub trap: u32,
    pub arm_trap: u32,
}

/// A recognized trap: the `SoftwareBreakpoint` CALLOTHER and its immediate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrkTrap {
    pub producer: OpId,
    pub imm: Option<uintb>,
}

fn same_storage(data: &Funcdata, a: crate::context::VarnodeId, b: crate::context::VarnodeId) -> bool {
    match (data.vbank().get(a), data.vbank().get(b)) {
        (Some(x), Some(y)) => x.get_addr() == y.get_addr() && x.get_size() == y.get_size(),
        _ => false,
    }
}

/// The constant the instruction copies into the storage of `vn`, walking back
/// from `from` to the instruction start.
fn copied_constant(data: &Funcdata, from: OpId, vn: crate::context::VarnodeId) -> Option<uintb> {
    let v = data.vbank().get(vn)?;
    if v.is_constant() {
        return Some(v.get_offset());
    }
    let mut cur = Some(from);
    while let Some(id) = cur {
        let op = data.obank().get(id)?;
        if id != from && op.get_out().is_some_and(|o| same_storage(data, o, vn)) {
            let src = op.get_in(0).and_then(|i| data.vbank().get(i))?;
            return (op.code() == OpCode::CPUI_COPY && src.is_constant()).then(|| src.get_offset());
        }
        if op.is_instruction_start() {
            break;
        }
        cur = data.obank().dead_prev(id);
    }
    None
}

/// The `SoftwareBreakpoint` CALLOTHER whose result `branch` jumps through, in
/// the same instruction.
pub fn find(data: &Funcdata, branch: OpId, breakpoint: u32) -> Option<BrkTrap> {
    if !data.obank().on_dead_list(branch) {
        return None;
    }
    let bop = data.obank().get(branch)?;
    if bop.code() != OpCode::CPUI_BRANCHIND {
        return None;
    }
    let target = bop.get_in(0)?;
    if bop.is_instruction_start() {
        return None;
    }
    let mut cur = data.obank().dead_prev(branch);
    while let Some(id) = cur {
        let op = data.obank().get(id)?;
        if let Some(out) = op.get_out() {
            if same_storage(data, out, target) {
                let is_brk = op.code() == OpCode::CPUI_CALLOTHER
                    && op
                        .get_in(0)
                        .and_then(|v| data.vbank().get(v))
                        .is_some_and(|v| v.is_constant() && v.get_offset() == breakpoint as uintb);
                if !is_brk {
                    return None;
                }
                let imm = op.get_in(1).and_then(|v| copied_constant(data, id, v));
                return Some(BrkTrap { producer: id, imm });
            }
        }
        if op.is_instruction_start() {
            break;
        }
        cur = data.obank().dead_prev(id);
    }
    None
}

/// Rewrite the trap: the producer calls the trap user-op with no output, and
/// `branch` becomes the artificial no-return halt.
pub fn rewrite(data: &mut Funcdata, branch: OpId, trap: &BrkTrap, ops: TrapOps) -> KunaResult<()> {
    let id_size = data
        .obank()
        .get(trap.producer)
        .and_then(|o| o.get_in(0))
        .and_then(|v| data.vbank().get(v))
        .map_or(4, |v| v.get_size());
    let inputs = match trap.imm {
        Some(BUILTIN_TRAP_IMM) => vec![data.new_constant(id_size, ops.trap as uintb)],
        Some(imm) => vec![data.new_constant(id_size, ops.arm_trap as uintb), data.new_constant(2, imm)],
        None => {
            let imm = data.obank().get(trap.producer).and_then(|o| o.get_in(1));
            let mut v = vec![data.new_constant(id_size, ops.arm_trap as uintb)];
            v.extend(imm);
            v
        }
    };
    data.op_unset_output(trap.producer);
    data.op_set_all_input(trap.producer, &inputs)?;
    let one = data.new_constant(4, 1);
    data.op_set_opcode_code(branch, OpCode::CPUI_RETURN);
    data.op_set_all_input(branch, &[one])?;
    data.op_mark_halt(branch, pcodeop_flags::noreturn)?;
    Ok(())
}

/// Register `__builtin_trap` and `__builtin_arm_trap` after the translator's
/// own user-ops when the language declares `SoftwareBreakpoint`.
pub fn register_trap_ops(userops: &mut crate::userop::UserOpManage) -> KunaResult<()> {
    if userops.get_op_by_name(BREAKPOINT_USEROP.as_bytes()).is_none() {
        return Ok(());
    }
    for nm in [TRAP_USEROP, ARM_TRAP_USEROP] {
        if userops.get_op_by_name(nm.as_bytes()).is_none() {
            let ind = userops.next_index();
            userops.register_op(crate::userop::UserPcodeOp::new_unspecialized(nm.as_bytes(), ind))?;
        }
    }
    Ok(())
}

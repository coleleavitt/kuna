//! (kuna) `calleeretpurge` — the bytes a callee's own `ret imm16` pops.
//!
//! A call's extrapop comes from the prototype model: `x86gcc.cspec` says every
//! `__cdecl` callee pops only its return address. The machine can say
//! otherwise. An i386 SysV function that returns a struct in memory ends with
//! `ret $4` and pops the hidden result pointer itself, and gcc compiles every
//! caller around that: the stack offsets after the call are four bytes higher
//! than the model predicts, so each later local is read at the wrong slot.
//! Callee-cleans conventions (`stdcall`, Pascal, Borland `register`) do the
//! same with every argument.
//!
//! IDA keeps this as a function property (`func_t` purged bytes, set from the
//! `ret N` it finds). Here the callee body is decoded once per image: a walk
//! from the entry that follows fall-through (calls are assumed to return),
//! direct branches and conditional branches, and stops a path at an indirect
//! branch. Every `RETURN` instruction met on the walk contributes the sum of
//! the constant stack-pointer increments it carries — the return-address pop
//! plus the `imm16`. When every return agrees, that sum is the callee's
//! extrapop and replaces the model's at every call to it.
//!
//! An imported callee is skipped: its call spec's entry is the import slot,
//! whose bytes are a pointer, not code.
//!
//! x86 only: on a RISC target the return instruction can restore the stack
//! pointer for its own frame (`pop {r4,pc}`), which is not a purge.

use std::collections::BTreeMap;

use kuna_base::address::Address;
use kuna_base::types::int4;
use kuna_num::opcodes::OpCode;
use kuna_num::pcoderaw::VarnodeData;

use crate::funcdata::Funcdata;

const MAX_PURGE_PROBE_INSTRUCTIONS: usize = 4000;

#[derive(Default)]
struct PurgeEmit {
    sp: Option<(int4, u64, u32)>,
    returns: bool,
    sp_adds: i64,
    targets: Vec<Address>,
    ends_flow: bool,
}

impl PurgeEmit {
    fn is_sp(&self, v: &VarnodeData) -> bool {
        match (&v.space, self.sp) {
            (Some(s), Some((idx, off, size))) => s.get_index() == idx && v.offset == off && v.size == size,
            _ => false,
        }
    }
}

impl kuna_sleigh::translate::PcodeEmit for PurgeEmit {
    fn dump(&mut self, _addr: &Address, opc: OpCode, outvar: Option<&VarnodeData>, vars: &[VarnodeData]) {
        match opc {
            OpCode::CPUI_INT_ADD => {
                if let (Some(out), Some(a), Some(b)) = (outvar, vars.first(), vars.get(1)) {
                    let is_const = b.space.as_ref().is_some_and(|s| s.get_type() == kuna_base::space::spacetype::IPTR_CONSTANT);
                    if self.is_sp(out) && self.is_sp(a) && is_const {
                        let bits = b.size * 8;
                        let raw = b.offset;
                        let v = if bits >= 64 { raw as i64 } else { ((raw << (64 - bits)) as i64) >> (64 - bits) };
                        self.sp_adds += v;
                    }
                }
            }
            OpCode::CPUI_RETURN => {
                self.returns = true;
                self.ends_flow = true;
            }
            OpCode::CPUI_BRANCHIND => self.ends_flow = true,
            OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH => {
                if let Some(sp) = vars.first().and_then(|v| v.space.as_ref()) {
                    if sp.get_type() != kuna_base::space::spacetype::IPTR_CONSTANT {
                        self.targets.push(Address::new(std::rc::Rc::clone(sp), vars[0].offset));
                        if opc == OpCode::CPUI_BRANCH {
                            self.ends_flow = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// The extrapop every `RETURN` reachable from `entry` agrees on, or `None`
/// when none is reached or two disagree.
pub fn probe_callee_purge<T: kuna_sleigh::translate::Translate + ?Sized>(
    tr: &T,
    entry: &Address,
    sp: (int4, u64, u32),
) -> Option<int4> {
    let mut seen = std::collections::HashSet::new();
    let mut todo = vec![entry.clone()];
    let mut purge: Option<i64> = None;
    let mut budget = MAX_PURGE_PROBE_INSTRUCTIONS;
    while let Some(at) = todo.pop() {
        let space = at.get_space()?;
        if !seen.insert((space.get_index(), at.get_offset())) {
            continue;
        }
        if budget == 0 {
            return None;
        }
        budget -= 1;
        let mut emit = PurgeEmit { sp: Some(sp), ..PurgeEmit::default() };
        let Ok(len) = tr.one_instruction(&mut emit, &at) else { continue };
        if len <= 0 {
            continue;
        }
        if emit.returns {
            match purge {
                None => purge = Some(emit.sp_adds),
                Some(p) if p != emit.sp_adds => return None,
                _ => {}
            }
        }
        todo.append(&mut emit.targets);
        if !emit.ends_flow {
            todo.push(&at + len as i64);
        }
    }
    purge.filter(|&p| p > 0 && p <= 0x10000).map(|p| p as int4)
}

/// Decode the callee of every direct call in `data` and record the purges the
/// bodies state. Cached per image on the `Architecture`.
pub fn seed(arch: &mut crate::architecture::Architecture, data: &mut Funcdata) {
    if !arch.callee_ret_purge || !arch.get_description().starts_with("x86:") {
        return;
    }
    let Some(base) = arch.manage().get_stack_space().and_then(|s| s.get_spacebase(0).ok()) else { return };
    let Some(space) = base.space.as_ref() else { return };
    let sp = (space.get_index(), base.offset, base.size);
    let mut purges = BTreeMap::new();
    for i in 0..data.num_calls() {
        let e = data.get_call_specs(i).get_entry_address().clone();
        let Some(space) = e.get_space() else { continue };
        let props = data.get_arch().query_global_properties(&e, space.get_addr_size() as int4, &e);
        if props & crate::varnode::varnode_flags::externref != 0 {
            continue;
        }
        let key = (space.get_index(), e.get_offset());
        let purge = match arch.kuna_callee_purge_cache.get(&key) {
            Some(p) => *p,
            None => {
                let p = probe_callee_purge(arch.translate(), &e, sp);
                arch.kuna_callee_purge_cache.insert(key, p);
                p
            }
        };
        if let Some(p) = purge {
            purges.insert(key, p);
        }
    }
    data.kuna_set_callee_purges(purges);
}

/// Give call `i` the extrapop its callee's body states, when one was recorded
/// and the prototype does not already agree.
pub fn apply(data: &mut Funcdata, i: int4) {
    let entry = data.get_call_specs(i).get_entry_address().clone();
    let Some(purge) = data.kuna_callee_purge(&entry) else { return };
    if data.get_call_specs(i).proto().get_extra_pop() != purge {
        data.get_call_specs_mut(i).proto_mut().set_extra_pop(purge);
    }
}

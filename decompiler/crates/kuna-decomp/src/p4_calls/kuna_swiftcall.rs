//! (kuna `swiftcall`) Swift calls: the ones that may throw, the `self` a
//! method hands on, and the `self` a call to a struct member does not pass.
//!
//! A throwing Swift function returns its error in the `swifterror` register
//! (x21 on arm64, r12 on x86-64), which every other convention preserves:
//! the caller zeroes the register, makes the call and tests it, so under the
//! C model the test reads the zero it just stored and the error path folds
//! away. A call whose block writes the constant zero to that register as its
//! last write before the call is such a call, direct or indirect, and is
//! given `__swiftcall_throws`, which hands the register back to the caller
//! ([`throwing_call`]).
//!
//! A struct member takes `self` in `swiftself` only when it is mutating or
//! its value is passed indirectly; a non-mutating member of a loadable struct
//! gets it in the trailing argument registers and leaves `swiftself` alone.
//! Its name does not say which, so a call to one keeps a `swiftself`
//! argument only when the caller set the register for that call: a value
//! that reaches it across an earlier call is that call's, not this one's
//! ([`stale_self`]).
//!
//! A method hands its own `self` on to the methods it calls without writing
//! the register again; that value is the caller's input in a preserved
//! register, which ancestor scoring takes for no argument, so it is passed
//! explicitly ([`passes_own_self`]). An indirect call through a target its
//! block loads takes `__swiftcall` ([`indirect_call`]), and passes
//! `swiftself` exactly when it dispatches on the value the register holds,
//! through that value's isa ([`indirect_self`]).
//!
//! Inert unless the Swift metadata pass bound the convention in this image.
//!
//! The two models are derived from the compiler spec's own default model
//! when the spec declares neither ([`derive_model`]), so any AArch64 or
//! x86-64 spec carries them, including one a Ghidra host sends: `__swiftcall`
//! is the default with `swiftself` added as an input of storage class
//! `class1`, its own resource section, so it is a parameter exactly when the
//! body reads it and never forces the argument registers around it;
//! `__swiftcall_throws` also moves the error register from the preserved
//! registers to the killed ones.

use std::collections::BTreeSet;
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::types::{int4, uintb};
use kuna_base::xml::Element;
use kuna_num::opcodes::OpCode;

use crate::context::OpId;
use crate::fspec::ProtoModel;
use crate::funcdata::Funcdata;

/// The Swift registers of the image and its four models.
#[derive(Debug)]
pub struct SwiftAbi {
    pub self_reg: (Address, int4),
    pub error_reg: (Address, int4),
    pub async_reg: (Address, int4),
    pub throws: Rc<ProtoModel>,
    /// `__swiftcall`, `__swiftasynccall`, `__swiftasynccall_throws`.
    pub plain: Rc<ProtoModel>,
    pub asynccall: Rc<ProtoModel>,
    pub asynccall_throws: Rc<ProtoModel>,
    /// The bound callees that may or may not take `swiftself`, by entry
    /// `(space index, offset)`.
    pub maybe_self: BTreeSet<(int4, uintb)>,
}

impl SwiftAbi {
    /// The model for a function that is `async` and/or `throws`.
    pub fn model(&self, is_async: bool, throws: bool) -> Rc<ProtoModel> {
        Rc::clone(match (is_async, throws) {
            (true, true) => &self.asynccall_throws,
            (true, false) => &self.asynccall,
            (false, true) => &self.throws,
            (false, false) => &self.plain,
        })
    }
}

/// Runtime entry points only an `async` function's frames call.
const ASYNC_CALLEES: [&str; 12] = [
    "swift_task_switch",
    "swift_task_alloc",
    "swift_task_dealloc",
    "swift_continuation_await",
    "swift_continuation_init",
    "swift_asyncLet_begin",
    "swift_asyncLet_get",
    "swift_asyncLet_get_throwing",
    "swift_asyncLet_finish",
    "swift_taskGroup_wait_next_throwing",
    "swift_task_future_wait",
    "swift_task_future_wait_throwing",
];

/// What a function's own calls say about its convention: a call to
/// `swift_willThrow` means it throws, a call to the task runtime's
/// suspension entry points means it is `async` — the shape a stripped
/// image keeps when no name says so. `callee_name` names the function a
/// direct call enters.
pub fn callee_evidence(
    data: &Funcdata,
    callee_name: impl Fn(&Address) -> Option<String>,
) -> (bool, bool) {
    let (mut is_async, mut throws) = (false, false);
    for i in 0..data.num_calls() {
        let entry = data.get_call_specs(i).get_entry_address();
        if entry.is_invalid() {
            continue;
        }
        let Some(name) = callee_name(entry) else {
            continue;
        };
        let name = name.trim_start_matches('_');
        if name == "swift_willThrow" || name == "swift_willThrowTypedImpl" {
            throws = true;
        } else if ASYNC_CALLEES.contains(&name) {
            is_async = true;
        }
    }
    (is_async, throws)
}

fn overlaps(a: &Address, asize: int4, b: &Address, bsize: int4) -> bool {
    a.overlap(0, b, bsize) >= 0 || b.overlap(0, a, asize) >= 0
}

/// The names of the four models.
pub const SWIFTCALL: &str = "__swiftcall";
pub const SWIFTCALL_THROWS: &str = "__swiftcall_throws";
/// An `async` function: the task's context arrives in the `swiftasync`
/// register (x22 / r14) and the function resumes a continuation instead of
/// returning.
pub const SWIFTASYNCCALL: &str = "__swiftasynccall";
pub const SWIFTASYNCCALL_THROWS: &str = "__swiftasynccall_throws";

/// The models to derive: `(name, takes the error register, takes the
/// async context)`.
pub const MODELS: [(&str, bool, bool); 4] = [
    (SWIFTCALL, false, false),
    (SWIFTCALL_THROWS, true, false),
    (SWIFTASYNCCALL, false, true),
    (SWIFTASYNCCALL_THROWS, true, true),
];

/// How many ops before the call the zeroing store is looked for.
const MAX_SCAN: usize = 64;

/// Is the op at `id` a write of zero to all of `(addr, size)`: a constant
/// copy, an `xor` of the register with itself, or the zero extension of one
/// of those into it?
fn zeroes(data: &Funcdata, id: OpId, depth: u32) -> bool {
    let Some(op) = data.obank().get(id) else {
        return false;
    };
    let input = |i: i32| op.get_in(i).and_then(|v| data.vbank().get(v));
    match op.code() {
        OpCode::CPUI_COPY => input(0).is_some_and(|v| v.is_constant() && v.get_offset() == 0),
        OpCode::CPUI_INT_XOR => match (input(0), input(1)) {
            (Some(a), Some(b)) => {
                !a.is_constant() && a.get_addr() == b.get_addr() && a.get_size() == b.get_size()
            }
            _ => false,
        },
        OpCode::CPUI_INT_ZEXT if depth == 0 => {
            let Some(low) = input(0) else { return false };
            let (addr, size) = (low.get_addr().clone(), low.get_size());
            let mut cur = data.op_previous_op(id);
            while let Some(prev) = cur {
                let written = data
                    .obank()
                    .get(prev)
                    .and_then(|o| o.get_out())
                    .and_then(|o| data.vbank().get(o));
                if let Some(out) = written {
                    if overlaps(out.get_addr(), out.get_size(), &addr, size) {
                        return out.get_addr() == &addr
                            && out.get_size() == size
                            && zeroes(data, prev, 1);
                    }
                }
                cur = data.op_previous_op(prev);
            }
            false
        }
        _ => false,
    }
}

/// `__swiftcall_throws` when `call` is a throwing Swift call.
pub fn throwing_call(data: &Funcdata, call: OpId) -> Option<Rc<ProtoModel>> {
    let abi = data.get_arch().swift_abi.as_ref()?;
    let (reg, size) = &abi.error_reg;
    let mut cur = data.op_previous_op(call);
    for _ in 0..MAX_SCAN {
        let id = cur?;
        let op = data.obank().get(id)?;
        if matches!(
            op.code(),
            OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER
        ) {
            return None;
        }
        if let Some(out) = op.get_out().and_then(|o| data.vbank().get(o)) {
            if overlaps(out.get_addr(), out.get_size(), reg, *size) {
                let whole = out.get_addr() == reg && out.get_size() == *size;
                return (whole && zeroes(data, id, 0)).then(|| Rc::clone(&abi.throws));
            }
        }
        cur = data.op_previous_op(id);
    }
    None
}

/// Is the `swiftself` trial of call `idx` (input `slot`, in `addr`/`size`) a
/// value the caller did not set for a callee that may not take it?
pub fn stale_self(data: &Funcdata, idx: int4, slot: int4, addr: &Address, size: int4) -> bool {
    let Some(abi) = data.get_arch().swift_abi.as_ref() else {
        return false;
    };
    if addr != &abi.self_reg.0 || size != abi.self_reg.1 {
        return false;
    }
    let call = data.get_call_specs(idx);
    let entry = call.get_entry_address();
    let Some(sp) = entry.get_space() else {
        return false;
    };
    if !abi
        .maybe_self
        .contains(&(sp.get_index(), entry.get_offset()))
    {
        return false;
    }
    let op = call.get_op();
    let Some(vn) = data.obank().get(op).and_then(|o| o.get_in(slot)) else {
        return false;
    };
    let def = data.vbank().get(vn).and_then(|v| v.get_def());
    if def
        .and_then(|d| data.obank().get(d))
        .is_some_and(|d| d.code() == OpCode::CPUI_INDIRECT)
    {
        return true;
    }
    call_since(data, def, op)
}

/// Is `(addr, size)` the image's `swiftself` register?
pub fn is_self_storage(data: &Funcdata, addr: &Address, size: int4) -> bool {
    data.get_arch().swift_abi.as_ref().is_some_and(|abi| &abi.self_reg.0 == addr && abi.self_reg.1 == size)
}

/// Is the model one of the two Swift models?
fn is_swift(model: &ProtoModel) -> bool {
    matches!(model.get_name(), SWIFTCALL | SWIFTCALL_THROWS)
}

/// Is the `swiftself` trial of call `idx` (input `slot`, in `addr`/`size`) the
/// caller's own `self`, handed on untouched or through copies (a value saved
/// in another callee-saved register and moved back)? A Swift method decompiled under
/// the convention passes the `self` it received to a callee that takes one
/// without writing the register again; its input is preserved by every call,
/// so it reads as no argument at all. [`stale_self`] has already refused it
/// for a callee that may not take `self`. A direct call only; an indirect
/// one is [`indirect_self`]'s.
pub fn passes_own_self(data: &Funcdata, idx: int4, slot: int4, addr: &Address, size: int4) -> bool {
    let Some(abi) = data.get_arch().swift_abi.as_ref() else { return false };
    if addr != &abi.self_reg.0 || size != abi.self_reg.1 {
        return false;
    }
    let own = data.get_func_proto();
    let call = data.get_call_specs(idx);
    if !own.has_model() || !is_swift(own.model()) || !call.proto().has_model() || !is_swift(call.proto().model()) {
        return false;
    }
    let op = call.get_op();
    let Some(vn) = data.obank().get(op).and_then(|o| o.get_in(slot)) else { return false };
    let root = copy_root(data, vn);
    let own = data.vbank().get(root).is_some_and(|v| v.is_input() && v.get_addr() == addr && v.get_size() == size);
    own && data.obank().get(op).is_some_and(|o| o.code() == OpCode::CPUI_CALL)
}

/// The Varnode `vn` copies, through any chain of copies.
fn copy_root(data: &Funcdata, mut vn: crate::context::VarnodeId) -> crate::context::VarnodeId {
    for _ in 0..8 {
        let def = data.vbank().get(vn).and_then(|v| v.get_def()).and_then(|d| data.obank().get(d));
        match def {
            Some(d) if d.code() == OpCode::CPUI_COPY => match d.get_in(0) {
                Some(a) => vn = a,
                None => break,
            },
            _ => break,
        }
    }
    vn
}

/// The `swiftself` trial of the indirect call `idx`, when the call is under
/// a Swift model: an argument exactly when the call dispatches on the value
/// the register holds, through that value's own isa (`obj->isa[k](obj, …)`).
/// A value witness, a witness-table entry or a closure reached any other way
/// is not told what `swiftself` holds, so the register is not its argument.
pub fn indirect_self(data: &Funcdata, idx: int4, slot: int4, addr: &Address, size: int4) -> Option<bool> {
    let abi = data.get_arch().swift_abi.as_ref()?;
    if addr != &abi.self_reg.0 || size != abi.self_reg.1 {
        return None;
    }
    let call = data.get_call_specs(idx);
    let op = call.get_op();
    if !data.obank().get(op).is_some_and(|o| o.code() == OpCode::CPUI_CALLIND)
        || !call.proto().has_model()
        || !is_swift(call.proto().model())
    {
        return None;
    }
    let vn = data.obank().get(op).and_then(|o| o.get_in(slot))?;
    Some(dispatches_on(data, op, vn))
}

/// Is the target of the indirect call `op` a slot loaded through `obj`'s
/// own first word, its isa: `obj->isa[k]`, a method dispatched on `obj`?
fn dispatches_on(data: &Funcdata, op: OpId, obj: crate::context::VarnodeId) -> bool {
    let def = |v: crate::context::VarnodeId| {
        data.vbank().get(v).and_then(|v| v.get_def()).and_then(|d| data.obank().get(d))
    };
    let root = |v| copy_root(data, v);
    let obj = root(obj);
    let mut v = match data.obank().get(op).and_then(|o| o.get_in(0)) {
        Some(v) => v,
        None => return false,
    };
    let mut loads = 0;
    for _ in 0..8 {
        if loads == 2 {
            return root(v) == obj;
        }
        let Some(d) = def(v) else { return false };
        v = match d.code() {
            OpCode::CPUI_LOAD => {
                loads += 1;
                match d.get_in(1) {
                    Some(a) => a,
                    None => return false,
                }
            }
            OpCode::CPUI_COPY | OpCode::CPUI_INT_ADD | OpCode::CPUI_PTRADD | OpCode::CPUI_PTRSUB => {
                match d.get_in(0) {
                    Some(a) => a,
                    None => return false,
                }
            }
            _ => return false,
        };
    }
    false
}

/// `__swiftcall` for an indirect call whose target its block loads from
/// memory, in an image the convention is bound in: a vtable slot, a witness
/// entry or a closure's function, which take it. The model only makes room
/// for `swiftself`; [`indirect_self`] decides whether the call passes it. A
/// trap's target or a coroutine continuation the previous call returned is
/// not a load and keeps the C model.
pub fn indirect_call(data: &Funcdata, call: OpId) -> Option<Rc<ProtoModel>> {
    let abi = data.get_arch().swift_abi.as_ref()?;
    let op = data.obank().get(call)?;
    if op.code() != OpCode::CPUI_CALLIND {
        return None;
    }
    let target = data.vbank().get(op.get_in(0)?)?;
    let (mut addr, mut size) = (target.get_addr().clone(), target.get_size());
    let mut cur = data.op_previous_op(call);
    for _ in 0..MAX_SCAN {
        let id = cur?;
        let prev = data.obank().get(id)?;
        if let Some(out) = prev.get_out().and_then(|o| data.vbank().get(o)) {
            if overlaps(out.get_addr(), out.get_size(), &addr, size) {
                match prev.code() {
                    OpCode::CPUI_LOAD => return Some(Rc::clone(&abi.plain)),
                    OpCode::CPUI_COPY => {
                        let src = data.vbank().get(prev.get_in(0)?)?;
                        if src.is_constant() {
                            return None;
                        }
                        (addr, size) = (src.get_addr().clone(), src.get_size());
                    }
                    _ => return None,
                }
            }
        }
        cur = data.op_previous_op(id);
    }
    None
}

/// How many dominating blocks [`call_since`] walks.
const MAX_BLOCKS: usize = 64;

/// Is there a call on the dominator path from `def` (the function entry when
/// `None`) down to the call `op`?
fn call_since(data: &Funcdata, def: Option<OpId>, op: OpId) -> bool {
    let Some(mut bl) = data.obank().get(op).and_then(|o| o.get_parent()) else {
        return false;
    };
    let mut cur = data.op_previous_op(op);
    for _ in 0..MAX_BLOCKS {
        while let Some(id) = cur {
            if Some(id) == def {
                return false;
            }
            let Some(o) = data.obank().get(id) else {
                return false;
            };
            if matches!(o.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND) {
                return true;
            }
            cur = data.op_previous_op(id);
        }
        let Some(up) = data.bblocks_ref().block(bl).get_immed_dom() else {
            return false;
        };
        bl = up;
        cur = data.bb_op_tail(bl);
    }
    false
}

/// The `swiftself`, `swifterror` and `swiftasync` register names of a
/// language Swift targets: AArch64's x20 / x21 / x22 and x86-64's r13 /
/// r12 / r14.
pub fn swift_registers(
    has_register: impl Fn(&str) -> Option<int4>,
) -> Option<(&'static str, &'static str, &'static str)> {
    [("x20", "x21", "x22"), ("R13", "R12", "R14")]
        .into_iter()
        .find(|(s, e, a)| {
            has_register(s) == Some(8) && has_register(e) == Some(8) && has_register(a) == Some(8)
        })
}

/// The registers a Swift function returns a value in beyond the C model's:
/// Swift returns up to four words directly (x0–x3 / rax, rdx, rcx, r8), so
/// a struct of 17 to 32 bytes comes back in registers where C passes it
/// through the indirect-result register (x8 / rax), which Swift uses only
/// from 33 bytes.
const EXTRA_RETURN_REGS: [(&str, [&str; 2]); 2] = [("x1", ["x2", "x3"]), ("RDX", ["RCX", "R8"])];

fn register(name: &str) -> Rc<Element> {
    let mut r = Element::new();
    r.set_name("register");
    r.add_attribute("name", name.as_bytes());
    Rc::new(r)
}

fn shell(from: &Element) -> Element {
    let mut el = Element::new();
    el.set_name(from.get_name());
    for i in 0..from.get_num_attributes() {
        el.add_attribute(from.get_attribute_name(i), from.get_attribute_value_at(i));
    }
    el
}

fn pentry(storage: Option<&str>, reg: &str) -> Rc<Element> {
    let mut entry = Element::new();
    entry.set_name("pentry");
    entry.add_attribute("minsize", b"1");
    entry.add_attribute("maxsize", b"8");
    if let Some(class) = storage {
        entry.add_attribute("storage", class.as_bytes());
    }
    entry.add_child(register(reg));
    Rc::new(entry)
}

/// The `<output>` of `proto` with Swift's return rule: two more general
/// registers after the second one, and the indirect result from 33 bytes
/// instead of 17 (the rule bounded at 17 or at 16, as the spec words it).
fn swift_output(output: &Element) -> Element {
    let mut out = shell(output);
    let reg_name = |el: &Element| {
        el.get_children()
            .iter()
            .find(|c| c.get_name() == "register")
            .and_then(|r| {
                r.get_attribute_value("name")
                    .ok()
                    .map(|v| String::from_utf8_lossy(v).into_owned())
            })
    };
    for c in output.get_children() {
        match c.get_name() {
            "pentry" => {
                out.add_child(Rc::clone(c));
                let Some(name) = reg_name(c) else { continue };
                if let Some((_, extra)) = EXTRA_RETURN_REGS
                    .iter()
                    .find(|(second, _)| second.eq_ignore_ascii_case(&name))
                {
                    for r in extra {
                        out.add_child(pentry(None, r));
                    }
                }
            }
            "rule" => {
                // The indirect result from 33 bytes (`minsize="17"` →
                // `"33"`), the register join up to 32 (`maxsize="16"` →
                // `"32"`), whichever way the spec words it.
                let mut rule = shell(c);
                for rc in c.get_children() {
                    let bound = |attr: &'static str,
                                 from: &[u8],
                                 to: &'static [u8]|
                     -> Option<(&'static str, &'static [u8])> {
                        (rc.get_name() == "datatype"
                            && rc.get_attribute_value(attr).ok() == Some(from))
                        .then_some((attr, to))
                    };
                    match bound("minsize", b"17", b"33").or_else(|| bound("maxsize", b"16", b"32"))
                    {
                        Some((attr, to)) => {
                            let mut dt = Element::new();
                            dt.set_name("datatype");
                            for i in 0..rc.get_num_attributes() {
                                let name = rc.get_attribute_name(i);
                                let value = if name == attr {
                                    to
                                } else {
                                    rc.get_attribute_value_at(i)
                                };
                                dt.add_attribute(name, value);
                            }
                            rule.add_child(Rc::new(dt));
                        }
                        None => rule.add_child(Rc::clone(rc)),
                    }
                }
                out.add_child(Rc::new(rule));
            }
            _ => out.add_child(Rc::clone(c)),
        }
    }
    out
}

/// The `<prototype>` named `name`: the default model `proto` with
/// `self_reg` as a `class1` input ahead of every other (and `async_reg` as a
/// `class2` input ahead of that), with `error_reg` killed by the call rather
/// than preserved across it, and with Swift's four-register return.
pub fn derive_model(
    proto: &Element,
    name: &str,
    self_reg: &str,
    error_reg: Option<&str>,
    async_reg: Option<&str>,
) -> Element {
    let mut out = Element::new();
    out.set_name("prototype");
    for i in 0..proto.get_num_attributes() {
        let attr = proto.get_attribute_name(i);
        let value = if attr == "name" {
            name.as_bytes()
        } else {
            proto.get_attribute_value_at(i)
        };
        out.add_attribute(attr, value);
    }
    let names = |el: &Element, reg: &str| {
        el.get_attribute_value("name")
            .is_ok_and(|n| n.eq_ignore_ascii_case(reg.as_bytes()))
    };
    for child in proto.get_children() {
        match (child.get_name(), error_reg) {
            ("input", _) => {
                let mut input = shell(child);
                if let Some(ctx) = async_reg {
                    input.add_child(pentry(Some("class2"), ctx));
                }
                input.add_child(pentry(Some("class1"), self_reg));
                // Swift's indirect result goes through rax on x86-64, where
                // C uses the first argument register; arm64's x8 is already
                // the default model's.
                if self_reg.eq_ignore_ascii_case("R13")
                    && !child.get_children().iter().any(|c| {
                        c.get_attribute_value("storage").ok() == Some(b"hiddenret".as_slice())
                    })
                {
                    input.add_child(pentry(Some("hiddenret"), "RAX"));
                }
                for c in child.get_children() {
                    input.add_child(Rc::clone(c));
                }
                out.add_child(Rc::new(input));
            }
            ("output", _) => out.add_child(Rc::new(swift_output(child))),
            ("unaffected", Some(err)) => {
                let mut list = shell(child);
                for c in child.get_children().iter().filter(|c| !names(c, err)) {
                    list.add_child(Rc::clone(c));
                }
                out.add_child(Rc::new(list));
            }
            ("killedbycall", Some(err)) => {
                let mut list = shell(child);
                list.add_child(register(err));
                for c in child.get_children() {
                    list.add_child(Rc::clone(c));
                }
                out.add_child(Rc::new(list));
            }
            _ => out.add_child(Rc::clone(child)),
        }
    }
    if let Some(err) = error_reg {
        if !proto
            .get_children()
            .iter()
            .any(|c| c.get_name() == "killedbycall")
        {
            let mut list = Element::new();
            list.set_name("killedbycall");
            list.add_child(register(err));
            out.add_child(Rc::new(list));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn el(name: &str, attrs: &[(&str, &str)], children: Vec<Rc<Element>>) -> Rc<Element> {
        let mut e = Element::new();
        e.set_name(name);
        for (k, v) in attrs {
            e.add_attribute(k, v.as_bytes());
        }
        for c in children {
            e.add_child(c);
        }
        Rc::new(e)
    }

    fn reg_entry(name: &str, attrs: &[(&str, &str)]) -> Rc<Element> {
        let mut a = vec![("minsize", "1"), ("maxsize", "8")];
        a.extend_from_slice(attrs);
        el("pentry", &a, vec![register(name)])
    }

    fn names(e: &Element, child: &str) -> Vec<String> {
        e.get_children()
            .iter()
            .filter(|c| c.get_name() == child)
            .filter_map(|c| {
                c.get_children()
                    .iter()
                    .find(|r| r.get_name() == "register")
                    .and_then(|r| {
                        r.get_attribute_value("name")
                            .ok()
                            .map(|v| String::from_utf8_lossy(v).into_owned())
                    })
            })
            .collect()
    }

    /// An AArch64-shaped default: `x8` hidden return, `x0`..`x1` returns, the
    /// 17-byte indirect rule.
    fn aarch64_like() -> Rc<Element> {
        let input = el(
            "input",
            &[],
            vec![
                reg_entry("x8", &[("storage", "hiddenret")]),
                reg_entry("x0", &[]),
                reg_entry("x1", &[]),
            ],
        );
        let output = el(
            "output",
            &[],
            vec![
                reg_entry("x0", &[]),
                reg_entry("x1", &[]),
                el(
                    "rule",
                    &[],
                    vec![
                        el("datatype", &[("name", "any"), ("minsize", "17")], vec![]),
                        el("hidden_return", &[("voidlock", "true")], vec![]),
                    ],
                ),
                el(
                    "rule",
                    &[],
                    vec![
                        el("datatype", &[("name", "any")], vec![]),
                        el("join", &[], vec![]),
                    ],
                ),
            ],
        );
        let unaffected = el(
            "unaffected",
            &[],
            vec![register("x20"), register("x21"), register("x22")],
        );
        el(
            "prototype",
            &[("name", "default"), ("extrapop", "0"), ("stackshift", "0")],
            vec![input, output, unaffected],
        )
    }

    #[test]
    fn swift_models_add_the_context_self_and_four_word_returns() {
        let proto = aarch64_like();
        let m = derive_model(
            &proto,
            SWIFTASYNCCALL_THROWS,
            "x20",
            Some("x21"),
            Some("x22"),
        );
        assert_eq!(
            m.get_attribute_value("name").unwrap(),
            b"__swiftasynccall_throws"
        );
        let input = m
            .get_children()
            .iter()
            .find(|c| c.get_name() == "input")
            .unwrap();
        assert_eq!(names(input, "pentry"), ["x22", "x20", "x8", "x0", "x1"]);
        let classes: Vec<String> = input
            .get_children()
            .iter()
            .map(|c| {
                String::from_utf8_lossy(c.get_attribute_value("storage").unwrap_or(b"general"))
                    .into_owned()
            })
            .collect();
        assert_eq!(
            classes,
            ["class2", "class1", "hiddenret", "general", "general"]
        );
        let output = m
            .get_children()
            .iter()
            .find(|c| c.get_name() == "output")
            .unwrap();
        assert_eq!(names(output, "pentry"), ["x0", "x1", "x2", "x3"]);
        let rules: Vec<Rc<Element>> = output
            .get_children()
            .iter()
            .filter(|c| c.get_name() == "rule")
            .cloned()
            .collect();
        assert_eq!(
            rules[0].get_children()[0]
                .get_attribute_value("minsize")
                .unwrap(),
            b"33"
        );
        let unaffected = m
            .get_children()
            .iter()
            .find(|c| c.get_name() == "unaffected")
            .unwrap();
        assert_eq!(names(unaffected, "register").len(), 0);
        let killed = m
            .get_children()
            .iter()
            .find(|c| c.get_name() == "killedbycall")
            .unwrap();
        assert_eq!(
            killed.get_children()[0]
                .get_attribute_value("name")
                .unwrap(),
            b"x21"
        );
        // The plain model: no context, the error register still preserved.
        let plain = derive_model(&proto, SWIFTCALL, "x20", None, None);
        let input = plain
            .get_children()
            .iter()
            .find(|c| c.get_name() == "input")
            .unwrap();
        assert_eq!(names(input, "pentry"), ["x20", "x8", "x0", "x1"]);
        assert!(
            plain
                .get_children()
                .iter()
                .all(|c| c.get_name() != "killedbycall")
        );
    }

    #[test]
    fn x86_64_takes_rax_as_the_indirect_result() {
        let input = el(
            "input",
            &[],
            vec![reg_entry("RDI", &[]), reg_entry("RSI", &[])],
        );
        let output = el(
            "output",
            &[],
            vec![
                reg_entry("RAX", &[]),
                reg_entry("RDX", &[]),
                el(
                    "rule",
                    &[],
                    vec![
                        el("datatype", &[("name", "any"), ("maxsize", "16")], vec![]),
                        el("join_dual_class", &[], vec![]),
                    ],
                ),
                el(
                    "rule",
                    &[],
                    vec![
                        el("datatype", &[("name", "any")], vec![]),
                        el("hidden_return", &[], vec![]),
                    ],
                ),
            ],
        );
        let proto = el("prototype", &[("name", "__stdcall")], vec![input, output]);
        let m = derive_model(&proto, SWIFTCALL, "R13", None, None);
        let input = m
            .get_children()
            .iter()
            .find(|c| c.get_name() == "input")
            .unwrap();
        assert_eq!(names(input, "pentry"), ["R13", "RAX", "RDI", "RSI"]);
        let output = m
            .get_children()
            .iter()
            .find(|c| c.get_name() == "output")
            .unwrap();
        assert_eq!(names(output, "pentry"), ["RAX", "RDX", "RCX", "R8"]);
        let rules: Vec<Rc<Element>> = output
            .get_children()
            .iter()
            .filter(|c| c.get_name() == "rule")
            .cloned()
            .collect();
        assert_eq!(
            rules[0].get_children()[0]
                .get_attribute_value("maxsize")
                .unwrap(),
            b"32"
        );
    }
}

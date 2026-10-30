//! **chkstkdarwin** — drop the `___chkstk_darwin` stack probe.
//!
//! ```text
//!   mov  x9, x2                 ;  v2 = a2 * 8;
//!   bl   ___chkstk_darwin       ;  __chkstk_darwin();          -->  (gone)
//!   sub  sp, sp, x9             ;
//! ```
//!
//! Apple's compilers probe every stack page before a frame larger than a page
//! (or a variable-length one) is allocated: the size goes in x9 and
//! `___chkstk_darwin` touches each page below sp, preserving every register.
//! The default call model has the call clobber x0–x18 like any other, which
//! cuts the data flow of the live argument registers across it, and the call
//! itself is runtime machinery the source never wrote. IDA drops it the same
//! way (its stack-probe list beside `__security_check_cookie`).
//!
//! The CALL is deleted pre-SSA (the `cleanupcode` window), so heritage never
//! sees the clobber and the size computation dies to dead-code elimination. A
//! call through `__auth_ptr` reaches this as a direct call after
//! `ActionDeindirect` names it and the function restarts.

use crate::action::{Action, ActionBase, ActionContext, ActionGroupList, ApplyResult};
use crate::context::OpId;
use crate::funcdata::Funcdata;

/// Is `name` the Darwin stack probe, in any of its underscore spellings?
pub fn is_chkstk_darwin(name: &str) -> bool {
    name.trim_start_matches('_') == "chkstk_darwin"
}

/// The live CALLs to the stack probe whose output nothing reads.
fn probe_calls(data: &Funcdata) -> Vec<OpId> {
    let mut out = Vec::new();
    for i in 0..data.num_calls() {
        let fc = data.get_call_specs(i);
        if !is_chkstk_darwin(fc.get_name()) {
            continue;
        }
        let op = fc.get_op();
        let Some(o) = data.obank().get(op) else { continue };
        if o.get_parent().is_none() {
            continue;
        }
        let read = o.get_out().and_then(|v| data.vbank().get(v)).is_some_and(|v| !v.has_no_descend());
        if !read {
            out.push(op);
        }
    }
    out
}

/// (kuna) `ActionChkstkDarwin` — delete the `___chkstk_darwin` probe calls
/// (option `chkstkdarwin`, default on).
pub struct ActionChkstkDarwin {
    base: ActionBase,
}

impl ActionChkstkDarwin {
    /// Construct the action in the given group.
    pub fn boxed(g: impl Into<String>) -> Box<dyn Action> {
        Box::new(ActionChkstkDarwin { base: ActionBase::new(0, "chkstkdarwin", g) })
    }
}

impl Action for ActionChkstkDarwin {
    fn base(&self) -> &ActionBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut ActionBase {
        &mut self.base
    }
    fn clone_filtered(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Action>> {
        if !grouplist.contains(self.get_group()) {
            return None;
        }
        Some(Box::new(ActionChkstkDarwin { base: self.base.clone() }))
    }
    fn apply(&mut self, data: &mut Funcdata, _ctx: &mut ActionContext) -> ApplyResult {
        if !data.get_arch().chkstk_darwin || data.get_heritage_pass() != 0 || data.num_calls() == 0 {
            return 0;
        }
        if is_chkstk_darwin(data.get_name()) {
            return 0;
        }
        let victims = probe_calls(data);
        if victims.is_empty() {
            return 0;
        }
        for op in victims {
            data.delete_call_specs(op);
            data.op_destroy(op);
            self.base.count += 1;
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_names() {
        for name in ["___chkstk_darwin", "__chkstk_darwin", "chkstk_darwin"] {
            assert!(is_chkstk_darwin(name), "{name}");
        }
        for name in ["__chkstk", "___chkstk_darwin_llvm_probe", "chkstk"] {
            assert!(!is_chkstk_darwin(name), "{name}");
        }
    }
}

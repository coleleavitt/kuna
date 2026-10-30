//! (kuna) The processor spec's `<segmentop>` definitions, compiled once per
//! architecture, for `ActionSegmentize` and `RuleSegment` (C++ `SegmentOp`).
//!
//! A segmented language (x86 real and 16-bit protected mode) computes every
//! segment-relative address through a `segment(base, inner)` user-op.
//! `ActionSegmentize` rewrites those CALLOTHERs into `CPUI_SEGMENTOP`, which
//! heritage, the stack analysis and the LOAD/STORE rules already understand: a
//! segment over the stack pointer is a stack access and the base is ignored.
//! `RuleSegment` folds a segment of two constants by running the spec's p-code
//! body (`SegmentOp::execute`).

use std::rc::Rc;

use kuna_base::space::AddrSpace;
use kuna_base::types::{int4, uint4, uintb};

use crate::context::ArchContext;
use crate::inject_sleigh::PcodeInjectLibrarySleigh;
use crate::kuna_jumpassist::Script;
use crate::userop::UserOpManage;

/// One `<segmentop>`.
#[derive(Debug)]
pub struct SegmentDef {
    /// The CALLOTHER index of its user-op.
    pub index: uint4,
    /// The space a segmented pointer points into.
    pub spc: Rc<AddrSpace>,
    pub baseinsize: int4,
    pub innerinsize: int4,
    pub farpointer: bool,
    script: Script,
}

impl SegmentDef {
    /// `SegmentOp::execute`: the full address of `base:inner`.
    pub fn execute(&self, glb: &ArchContext, base: uintb, inner: uintb) -> Option<uintb> {
        let inputs: Vec<uintb> = if self.baseinsize == 0 { vec![inner] } else { vec![base, inner] };
        self.script.evaluate(glb, &inputs).ok()
    }
}

/// Every `<segmentop>` of an architecture.
#[derive(Debug, Default)]
pub struct SegmentDefs {
    pub defs: Vec<SegmentDef>,
}

impl SegmentDefs {
    pub fn from_library(userops: &UserOpManage, lib: &PcodeInjectLibrarySleigh) -> SegmentDefs {
        let mut defs = Vec::new();
        for i in 0..userops.num_segment_ops() {
            let Some(op) = userops.get_segment_op(i) else { continue };
            let Some(seg) = op.as_segment() else { continue };
            let (Some(spc), Some(script)) = (seg.spc.clone(), Script::compile(lib, seg.inject_id)) else { continue };
            defs.push(SegmentDef {
                index: op.get_index() as uint4,
                spc,
                baseinsize: seg.baseinsize,
                innerinsize: seg.innerinsize,
                farpointer: seg.supportsfarpointer,
                script,
            });
        }
        SegmentDefs { defs }
    }

    /// The definition whose segmented space is `spc`.
    pub fn for_space(&self, spc: &AddrSpace) -> Option<&SegmentDef> {
        self.defs.iter().find(|d| d.spc.get_index() == spc.get_index())
    }
}

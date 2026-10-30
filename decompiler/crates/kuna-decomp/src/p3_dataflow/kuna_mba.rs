//! (kuna `mba`) Linear mixed boolean-arithmetic simplification.
//!
//! Obfuscators (Tigress, OLLVM) hide `x + y` as `(x ^ y) + 2 * (x & y)`. Such an
//! expression is a *linear MBA*: an integer combination of bitwise functions of
//! the same variables. For that class one theorem does all the work: two linear
//! MBAs are equal at every width when they agree on every input whose variables
//! are each 0 or 1 (SiMBA). So the rule needs no SMT solver:
//!
//! 1. Collect the expression tree under an arithmetic root. Interior ops with one
//!    reader are inlined; anything else is a leaf. The tree must have the linear
//!    shape: `+`, `-`, negation and multiplication by a constant over bitwise
//!    subterms (`&`, `|`, `^`, `~` of leaves only).
//! 2. Evaluate it on the `2^n` points with each leaf 0 or 1 and Möbius-invert the
//!    values into coefficients of the conjunction basis: `f = b0 + Σ b_S·AND(S)`.
//! 3. Pick the cheapest of: that sum, a linear sum of the leaves (when every
//!    multi-leaf coefficient is 0), or `k + c·g(x, y) + Σ c_i·z_i` when every
//!    multi-leaf term lies inside one pair `x, y` and `g` is one two-variable
//!    boolean function. Replace the root only when the candidate has fewer ops, and
//!    only after 64 random full-width evaluations agree.
//!
//! IDA 9.5's gooMBA (goomba.so 0x3eb60) runs the same truth-table step but proves
//! every candidate with z3; the syntactic linearity check is what makes the proof
//! unnecessary here.

use std::collections::HashMap;

use kuna_base::types::{int4, uintb};
use kuna_num::opcodes::OpCode;

use crate::action::{ActionGroupList, Rule};
use crate::context::{OpId, VarnodeId};
use crate::funcdata::Funcdata;

/// Most distinct leaves the truth table covers (`2^4` evaluations).
const MAX_LEAVES: usize = 4;
/// Largest tree the rule looks at.
const MAX_NODES: usize = 48;

#[derive(Clone, Debug, PartialEq)]
enum Expr {
    Leaf(usize),
    Const(u64),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Neg(Box<Expr>),
    Mul(Box<Expr>, u64),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

impl Expr {
    fn eval(&self, leaves: &[u64], mask: u64) -> u64 {
        let v = match self {
            Expr::Leaf(i) => leaves[*i],
            Expr::Const(c) => *c,
            Expr::Add(a, b) => a.eval(leaves, mask).wrapping_add(b.eval(leaves, mask)),
            Expr::Sub(a, b) => a.eval(leaves, mask).wrapping_sub(b.eval(leaves, mask)),
            Expr::Neg(a) => a.eval(leaves, mask).wrapping_neg(),
            Expr::Mul(a, c) => a.eval(leaves, mask).wrapping_mul(*c),
            Expr::And(a, b) => a.eval(leaves, mask) & b.eval(leaves, mask),
            Expr::Or(a, b) => a.eval(leaves, mask) | b.eval(leaves, mask),
            Expr::Xor(a, b) => a.eval(leaves, mask) ^ b.eval(leaves, mask),
            Expr::Not(a) => !a.eval(leaves, mask),
        };
        v & mask
    }

    fn ops(&self) -> usize {
        match self {
            Expr::Leaf(_) | Expr::Const(_) => 0,
            Expr::Neg(a) | Expr::Not(a) | Expr::Mul(a, _) => 1 + a.ops(),
            Expr::Add(a, b) | Expr::Sub(a, b) | Expr::And(a, b) | Expr::Or(a, b) | Expr::Xor(a, b) => {
                1 + a.ops() + b.ops()
            }
        }
    }

    fn is_bitwise_of_leaves(&self) -> bool {
        match self {
            Expr::Leaf(_) => true,
            Expr::Not(a) => a.is_bitwise_of_leaves(),
            Expr::And(a, b) | Expr::Or(a, b) | Expr::Xor(a, b) => a.is_bitwise_of_leaves() && b.is_bitwise_of_leaves(),
            _ => false,
        }
    }

    /// A linear combination of bitwise subterms and constants.
    fn is_linear(&self) -> bool {
        match self {
            Expr::Const(_) => true,
            Expr::Add(a, b) | Expr::Sub(a, b) => a.is_linear() && b.is_linear(),
            Expr::Neg(a) | Expr::Mul(a, _) => a.is_linear(),
            e => e.is_bitwise_of_leaves(),
        }
    }

    fn has_bitwise(&self) -> bool {
        match self {
            Expr::And(..) | Expr::Or(..) | Expr::Xor(..) | Expr::Not(_) => true,
            Expr::Add(a, b) | Expr::Sub(a, b) => a.has_bitwise() || b.has_bitwise(),
            Expr::Neg(a) | Expr::Mul(a, _) => a.has_bitwise(),
            _ => false,
        }
    }

    fn has_arith(&self) -> bool {
        match self {
            Expr::Add(..) | Expr::Sub(..) | Expr::Neg(_) | Expr::Mul(..) => true,
            Expr::And(a, b) | Expr::Or(a, b) | Expr::Xor(a, b) => a.has_arith() || b.has_arith(),
            Expr::Not(a) => a.has_arith(),
            _ => false,
        }
    }
}

/// The conjunction-basis coefficients `b[S]` (index = leaf bitmask) of `f`.
fn coefficients(f: &Expr, n: usize, mask: u64) -> Vec<u64> {
    let points = 1usize << n;
    let mut b: Vec<u64> = (0..points)
        .map(|e| {
            let leaves: Vec<u64> = (0..n).map(|i| ((e >> i) & 1) as u64).collect();
            f.eval(&leaves, mask)
        })
        .collect();
    for i in 0..n {
        for s in 0..points {
            if s & (1 << i) != 0 {
                b[s] = b[s].wrapping_sub(b[s ^ (1 << i)]) & mask;
            }
        }
    }
    b
}

/// `AND` of the leaves in `s`.
fn conj(s: usize) -> Expr {
    let mut it = (0..MAX_LEAVES).filter(|i| s & (1 << i) != 0).map(Expr::Leaf);
    let first = it.next().expect("non-empty set");
    it.fold(first, |acc, l| Expr::And(Box::new(acc), Box::new(l)))
}

/// `c * term`, with 1 and -1 spelled without a multiply.
fn scaled(term: Expr, c: u64, mask: u64) -> (Expr, bool) {
    if c == 1 {
        (term, false)
    } else if c == mask {
        (term, true)
    } else if (c.wrapping_neg() & mask) < c && (c.wrapping_neg() & mask) != 0 {
        (Expr::Mul(Box::new(term), c.wrapping_neg() & mask), true)
    } else {
        (Expr::Mul(Box::new(term), c), false)
    }
}

/// `k + Σ c_i·term_i` with subtraction for the negative terms.
fn sum(terms: Vec<(Expr, u64)>, k: u64, mask: u64) -> Expr {
    let mut acc: Option<Expr> = None;
    let mut neg: Vec<Expr> = Vec::new();
    for (t, c) in terms.into_iter().filter(|(_, c)| *c != 0) {
        let (e, is_neg) = scaled(t, c, mask);
        if is_neg {
            neg.push(e);
        } else {
            acc = Some(match acc {
                None => e,
                Some(a) => Expr::Add(Box::new(a), Box::new(e)),
            });
        }
    }
    let mut acc = match (acc, neg.is_empty()) {
        (Some(a), _) => a,
        (None, true) => return Expr::Const(k),
        (None, false) => Expr::Neg(Box::new(neg.remove(0))),
    };
    for e in neg {
        acc = Expr::Sub(Box::new(acc), Box::new(e));
    }
    if k == 0 {
        acc
    } else if (k.wrapping_neg() & mask) < k {
        Expr::Sub(Box::new(acc), Box::new(Expr::Const(k.wrapping_neg() & mask)))
    } else {
        Expr::Add(Box::new(acc), Box::new(Expr::Const(k)))
    }
}

/// The sixteen two-variable boolean functions, each in a smallest form.
fn boolean2() -> Vec<Expr> {
    let x = || Box::new(Expr::Leaf(0));
    let y = || Box::new(Expr::Leaf(1));
    let not = |e: Expr| Expr::Not(Box::new(e));
    vec![
        Expr::And(x(), y()),
        Expr::Or(x(), y()),
        Expr::Xor(x(), y()),
        not(Expr::And(x(), y())),
        not(Expr::Or(x(), y())),
        not(Expr::Xor(x(), y())),
        Expr::And(x(), Box::new(not(Expr::Leaf(1)))),
        Expr::And(Box::new(not(Expr::Leaf(0))), y()),
        Expr::Or(x(), Box::new(not(Expr::Leaf(1)))),
        Expr::Or(Box::new(not(Expr::Leaf(0))), y()),
        not(Expr::Leaf(0)),
        not(Expr::Leaf(1)),
    ]
}

/// Rename leaf `0`/`1` of a two-variable expression to `p.0`/`p.1`.
fn remap(e: &Expr, p: (usize, usize)) -> Expr {
    let r = |e: &Expr| Box::new(remap(e, p));
    match e {
        Expr::Leaf(0) => Expr::Leaf(p.0),
        Expr::Leaf(_) => Expr::Leaf(p.1),
        Expr::Const(c) => Expr::Const(*c),
        Expr::Add(a, b) => Expr::Add(r(a), r(b)),
        Expr::Sub(a, b) => Expr::Sub(r(a), r(b)),
        Expr::And(a, b) => Expr::And(r(a), r(b)),
        Expr::Or(a, b) => Expr::Or(r(a), r(b)),
        Expr::Xor(a, b) => Expr::Xor(r(a), r(b)),
        Expr::Neg(a) => Expr::Neg(r(a)),
        Expr::Not(a) => Expr::Not(r(a)),
        Expr::Mul(a, c) => Expr::Mul(r(a), *c),
    }
}

/// `(g, c, k)` with `c*g(x,y) + k` equal to the two-variable coefficients `b2`.
fn single_boolean(b2: &[u64; 4], mask: u64) -> Option<(Expr, u64, u64)> {
    let mut best: Option<(Expr, u64, u64)> = None;
    for g in boolean2() {
        let gb = coefficients(&g, 2, mask);
        let Some(s0) = (1..4).find(|&s| gb[s] != 0) else { continue };
        for c in [b2[s0], b2[s0].wrapping_neg() & mask] {
            if (1..4).all(|s| gb[s].wrapping_mul(c) & mask == b2[s]) {
                let k = b2[0].wrapping_sub(gb[0].wrapping_mul(c)) & mask;
                let better = best.as_ref().is_none_or(|(bg, _, _)| g.ops() < bg.ops());
                if better {
                    best = Some((g.clone(), c, k));
                }
            }
        }
    }
    best
}

/// The cheapest expression equal to the linear MBA `f` over `n` leaves.
fn simplify(f: &Expr, n: usize, mask: u64) -> Expr {
    let b = coefficients(f, n, mask);
    let multi: Vec<usize> = (1..b.len()).filter(|&s| s.count_ones() > 1 && b[s] != 0).collect();
    let full = sum((1..b.len()).map(|s| (conj(s), b[s])).collect(), b[0], mask);
    if multi.is_empty() {
        return full;
    }
    // Every multi-leaf term inside one pair: a boolean function of that pair
    // plus a linear sum of the other leaves.
    let pair = multi.iter().fold(0usize, |acc, &s| acc | s);
    if pair.count_ones() != 2 {
        return full;
    }
    let p0 = pair.trailing_zeros() as usize;
    let p1 = (pair & !(1 << p0)).trailing_zeros() as usize;
    let b2 = [b[0], b[1 << p0], b[1 << p1], b[pair]];
    let Some((g, c, k)) = single_boolean(&b2, mask) else { return full };
    let mut terms = vec![(remap(&g, (p0, p1)), c)];
    terms.extend((0..n).filter(|&i| i != p0 && i != p1).map(|i| (Expr::Leaf(i), b[1 << i])));
    let cand = sum(terms, k, mask);
    if cand.ops() < full.ops() {
        cand
    } else {
        full
    }
}

/// A small deterministic PRNG for the random cross-check.
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Do `a` and `b` agree on 64 pseudo-random full-width inputs?
fn agree(a: &Expr, b: &Expr, n: usize, mask: u64) -> bool {
    let mut st = 0x6b75_6e61u64;
    (0..64).all(|_| {
        let leaves: Vec<u64> = (0..n).map(|_| splitmix(&mut st) & mask).collect();
        a.eval(&leaves, mask) == b.eval(&leaves, mask)
    })
}

fn is_candidate(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::CPUI_INT_ADD
            | OpCode::CPUI_INT_SUB
            | OpCode::CPUI_INT_2COMP
            | OpCode::CPUI_INT_MULT
            | OpCode::CPUI_INT_AND
            | OpCode::CPUI_INT_OR
            | OpCode::CPUI_INT_XOR
            | OpCode::CPUI_INT_NEGATE
    )
}

/// Builds an [`Expr`] from the IR, numbering leaves as it meets them.
struct Collector<'a> {
    data: &'a Funcdata,
    size: int4,
    leaves: Vec<VarnodeId>,
    nodes: usize,
}

impl Collector<'_> {
    fn leaf(&mut self, vn: VarnodeId) -> Option<Expr> {
        let i = match self.leaves.iter().position(|&l| l == vn) {
            Some(i) => i,
            None => {
                self.leaves.push(vn);
                self.leaves.len() - 1
            }
        };
        (i < MAX_LEAVES).then_some(Expr::Leaf(i))
    }

    fn vn(&mut self, vn: VarnodeId, inline: bool) -> Option<Expr> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return None;
        }
        let v = self.data.vbank().get(vn)?;
        if v.get_size() != self.size {
            return None;
        }
        if v.is_constant() {
            return Some(Expr::Const(v.get_offset()));
        }
        let def = v.get_def().filter(|_| v.is_written());
        match def {
            Some(op) if inline && self.data.lone_descend(vn).is_some() => self.op(op),
            _ => self.leaf(vn),
        }
    }

    fn op(&mut self, op: OpId) -> Option<Expr> {
        let o = self.data.obank().get(op)?;
        let code = o.code();
        if !is_candidate(code) {
            let out = o.get_out()?;
            return self.leaf(out);
        }
        let i0 = o.get_in(0)?;
        let i1 = o.get_in(1);
        let a = Box::new(self.vn(i0, true)?);
        let mut b = || -> Option<Box<Expr>> { Some(Box::new(self.vn(i1?, true)?)) };
        Some(match code {
            OpCode::CPUI_INT_ADD => Expr::Add(a, b()?),
            OpCode::CPUI_INT_SUB => Expr::Sub(a, b()?),
            OpCode::CPUI_INT_2COMP => Expr::Neg(a),
            OpCode::CPUI_INT_NEGATE => Expr::Not(a),
            OpCode::CPUI_INT_AND => Expr::And(a, b()?),
            OpCode::CPUI_INT_OR => Expr::Or(a, b()?),
            OpCode::CPUI_INT_XOR => {
                let b = b()?;
                match (*a, *b) {
                    (e, Expr::Const(c)) | (Expr::Const(c), e) if c == mask_of(self.size) => Expr::Not(Box::new(e)),
                    (a, b) => Expr::Xor(Box::new(a), Box::new(b)),
                }
            }
            OpCode::CPUI_INT_MULT => match (*a, *b()?) {
                (e, Expr::Const(c)) | (Expr::Const(c), e) => Expr::Mul(Box::new(e), c),
                _ => return None,
            },
            _ => return None,
        })
    }
}

fn mask_of(size: int4) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * size)) - 1
    }
}

/// Materialize `e` as ops before `root`, returning the varnode holding it.
fn emit(data: &mut Funcdata, root: OpId, e: &Expr, leaves: &[VarnodeId], size: int4) -> VarnodeId {
    let mut bin = |data: &mut Funcdata, code: OpCode, a: &Expr, b: VarnodeId| {
        let va = emit(data, root, a, leaves, size);
        let op = data.new_op_before(root, code, va, b, None);
        data.obank().get(op).and_then(|o| o.get_out()).expect("new_op_before output")
    };
    match e {
        Expr::Leaf(i) => leaves[*i],
        Expr::Const(c) => data.new_constant(size, *c as uintb),
        Expr::Add(a, b) | Expr::Sub(a, b) | Expr::And(a, b) | Expr::Or(a, b) | Expr::Xor(a, b) => {
            let vb = emit(data, root, b, leaves, size);
            let code = match e {
                Expr::Add(..) => OpCode::CPUI_INT_ADD,
                Expr::Sub(..) => OpCode::CPUI_INT_SUB,
                Expr::And(..) => OpCode::CPUI_INT_AND,
                Expr::Or(..) => OpCode::CPUI_INT_OR,
                _ => OpCode::CPUI_INT_XOR,
            };
            bin(data, code, a, vb)
        }
        Expr::Mul(a, c) => {
            let vc = data.new_constant(size, *c as uintb);
            bin(data, OpCode::CPUI_INT_MULT, a, vc)
        }
        Expr::Neg(a) | Expr::Not(a) => {
            let va = emit(data, root, a, leaves, size);
            let addr = data.obank().get(root).map(|o| o.get_addr().clone()).expect("root");
            let op = data.new_op(1, addr);
            data.op_set_opcode_code(op, if matches!(e, Expr::Neg(_)) { OpCode::CPUI_INT_2COMP } else { OpCode::CPUI_INT_NEGATE });
            let out = data.new_unique_out(size, op).expect("unique out");
            data.op_set_input(op, va, 0).expect("set input");
            data.op_insert_before(op, root);
            out
        }
    }
}

/// (kuna `mba`) `RuleMbaSimplify`.
pub struct RuleMbaSimplify {
    group: String,
}

impl RuleMbaSimplify {
    pub fn new(g: impl Into<String>) -> RuleMbaSimplify {
        RuleMbaSimplify { group: g.into() }
    }
}

impl Rule for RuleMbaSimplify {
    fn get_op_list(&self) -> Vec<OpCode> {
        vec![
            OpCode::CPUI_INT_ADD,
            OpCode::CPUI_INT_SUB,
            OpCode::CPUI_INT_2COMP,
            OpCode::CPUI_INT_MULT,
            OpCode::CPUI_INT_AND,
            OpCode::CPUI_INT_OR,
            OpCode::CPUI_INT_XOR,
            OpCode::CPUI_INT_NEGATE,
        ]
    }

    fn clone_rule(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Rule>> {
        grouplist.contains(&self.group).then(|| Box::new(RuleMbaSimplify { group: self.group.clone() }) as Box<dyn Rule>)
    }

    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> int4 {
        if !data.get_arch().mba {
            return 0;
        }
        let Some(out) = data.obank().get(op).and_then(|o| o.get_out()) else { return 0 };
        let Some(size) = data.vbank().get(out).map(|v| v.get_size()) else { return 0 };
        if size > 8 {
            return 0;
        }
        // Only the root of a candidate tree: a single reader that is itself a
        // candidate will see this op as its interior.
        if let Some(reader) = data.lone_descend(out) {
            if data.obank().get(reader).is_some_and(|r| is_candidate(r.code())) {
                return 0;
            }
        }
        let mut col = Collector { data, size, leaves: Vec::new(), nodes: 0 };
        let Some(expr) = col.op(op) else { return 0 };
        let leaves = col.leaves;
        let n = leaves.len();
        if n == 0 || n > MAX_LEAVES || !expr.has_bitwise() || !expr.has_arith() || !expr.is_linear() {
            return 0;
        }
        let mask = mask_of(size);
        let simple = simplify(&expr, n, mask);
        if simple.ops() >= expr.ops() || !agree(&expr, &simple, n, mask) {
            return 0;
        }
        let res = emit(data, op, &simple, &leaves, size);
        let copy = crate::context::TypeOp::new(OpCode::CPUI_COPY, 0, "COPY");
        data.op_set_opcode(op, copy);
        if data.op_set_all_input(op, &[res]).is_err() {
            return 0;
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x() -> Box<Expr> {
        Box::new(Expr::Leaf(0))
    }
    fn y() -> Box<Expr> {
        Box::new(Expr::Leaf(1))
    }

    #[test]
    fn xor_plus_twice_and_is_add() {
        let m = u32::MAX as u64;
        let f = Expr::Add(Box::new(Expr::Xor(x(), y())), Box::new(Expr::Mul(Box::new(Expr::And(x(), y())), 2)));
        assert!(f.is_linear());
        assert_eq!(simplify(&f, 2, m), Expr::Add(x(), y()));
    }

    #[test]
    fn or_minus_and_is_xor() {
        let m = u64::MAX;
        let f = Expr::Sub(Box::new(Expr::Or(x(), y())), Box::new(Expr::And(x(), y())));
        let s = simplify(&f, 2, m);
        assert_eq!(s, Expr::Xor(x(), y()));
        assert!(agree(&f, &s, 2, m));
    }

    #[test]
    fn sub_via_not() {
        // x - y == x + ~y + 1
        let m = u64::MAX;
        let f = Expr::Add(Box::new(Expr::Add(x(), Box::new(Expr::Not(y())))), Box::new(Expr::Const(1)));
        assert_eq!(simplify(&f, 2, m), Expr::Sub(x(), y()));
    }

    #[test]
    fn pair_function_plus_linear_rest() {
        // (x & ~y) + y + z == (x | y) + z
        let m = u32::MAX as u64;
        let z = Box::new(Expr::Leaf(2));
        let f = Expr::Add(Box::new(Expr::Add(Box::new(Expr::And(x(), Box::new(Expr::Not(y())))), y())), z.clone());
        assert_eq!(simplify(&f, 3, m), Expr::Add(Box::new(Expr::Or(x(), y())), z));
    }

    #[test]
    fn non_linear_shape_is_refused() {
        let f = Expr::And(Box::new(Expr::Add(x(), y())), x());
        assert!(!f.is_linear());
    }
}

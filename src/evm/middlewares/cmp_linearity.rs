//! Feature 009a — comparison-operand linearity taint.
//!
//! Substrate for Feature 009 (concolic/secant dispatch). Classifies each
//! input-tainted comparison as LINEAR (secant-solvable: the symbolic operand
//! reached the comparison only through monotonic ops — ADD/SUB, MUL-by-constant,
//! LT/GT/EQ) or NON-LINEAR (concolic-only: SHA3, EXP, bitwise, DIV/MOD,
//! MUL of two symbolics, SIGNEXTEND).
//!
//! Model: a shadow stack mirroring the real EVM stack, one **tuple** `TB{t,nl}`
//! per slot — `t` = input-tainted, `nl` = tainted value passed through a
//! non-linear op. Using a single tuple stack (vs two parallel vecs) makes the
//! shadow desync-proof: t and nl always push/pop together, so the
//! `len == real stack len` invariant is the only one to maintain (same as
//! `sha3_bypass`, which this is modeled on).
//!
//! Simplification: memory/storage carry only the `t` (taint) bit; `nl` is reset
//! to false on MLOAD/SLOAD. A non-linear value laundered through memory is thus
//! mis-classified linear — caught by the secant stall→requeue fallback (spec
//! 009 §5.3), never a lost branch.

use std::{any, collections::HashMap};

use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::{
    interpreter_types::{InputsTr, Jumps},
    Interpreter,
};

use super::middleware::{Middleware, MiddlewareType};
use crate::evm::{
    host::FuzzHost,
    types::{as_u64, EVMAddress, EVMFuzzState, EVMU256},
};

const MAX_CALL_DEPTH: u64 = 3;
const MEMORY_LIMIT_BYTES: usize = 16 * 1024 * 1024;

fn safe_mem_end(offset: usize, len: usize) -> Option<usize> {
    offset.checked_add(len).filter(|&end| end <= MEMORY_LIMIT_BYTES)
}

/// Per-execution classification, read by the concolic-dispatch triage
/// (`ConcolicFeedbackWrapper::append_metadata`) right after the reexecution.
/// Reset at the start of each linearity reexecution via `full_reset`.
pub static mut LIN_SAW_TAINTED_CMP: bool = false;
pub static mut LIN_SAW_NONLINEAR_CMP: bool = false;

/// Per-(contract, pc) classification: true = LINEAR (secant), false = NON-LINEAR.
/// Optional finer-grained view for `is_linear_gate`-style queries.
pub static mut CMP_LINEARITY: Option<HashMap<(EVMAddress, usize), bool>> = None;

/// Reset the per-execution dispatch verdict. Call before each reexecution.
pub fn lin_reset_verdict() {
    unsafe {
        LIN_SAW_TAINTED_CMP = false;
        LIN_SAW_NONLINEAR_CMP = false;
        if let Some(m) = CMP_LINEARITY.as_mut() {
            m.clear();
        } else {
            CMP_LINEARITY = Some(HashMap::new());
        }
    }
}

/// Dispatch verdict for the most recent linearity reexecution:
/// `true`  → the input has a tainted gate AND every tainted gate is linear
///           → the secant lane can handle it; do NOT queue for concolic.
/// `false` → no tainted gate, or at least one non-linear tainted gate
///           → keep concolic (today's behavior). Additive/safe.
pub fn lin_route_to_secant() -> bool {
    unsafe { LIN_SAW_TAINTED_CMP && !LIN_SAW_NONLINEAR_CMP }
}

/// True only when concolic is enabled (`config.concolic`). The whole 009 dispatch
/// is concolic-budget management — there is no point running the linearity
/// reexecution (extra work per interesting input) when concolic is off, since
/// nothing drains the concolic queue. Set once at fuzzer setup.
pub static mut LIN_CONCOLIC_ENABLED: bool = false;
pub fn lin_set_concolic_enabled(v: bool) {
    unsafe { LIN_CONCOLIC_ENABLED = v }
}
pub fn lin_concolic_enabled() -> bool {
    unsafe { LIN_CONCOLIC_ENABLED }
}

// --- §7 validation counters: the measured linear/non-linear dispatch ratio. ---
pub static mut LIN_ROUTED_SECANT: u64 = 0; // linear gate → routed away from concolic
pub static mut LIN_QUEUED_CONCOLIC: u64 = 0; // non-linear / no-tainted-gate → concolic
pub static mut LIN_REQUEUED: u64 = 0; // stall→requeue fallback fired

pub fn lin_bump_routed() {
    unsafe {
        LIN_ROUTED_SECANT += 1;
    }
}
pub fn lin_bump_queued() {
    unsafe {
        LIN_QUEUED_CONCOLIC += 1;
    }
}
pub fn lin_bump_requeued() {
    unsafe {
        LIN_REQUEUED += 1;
    }
}

/// Print the running dispatch ratio (for the §7 validation A/B run).
pub fn lin_print_stats() {
    unsafe {
        let (r, q, rq) = (LIN_ROUTED_SECANT, LIN_QUEUED_CONCOLIC, LIN_REQUEUED);
        let total = r + q;
        let pct = if total > 0 { 100 * r / total } else { 0 };
        println!(
            "[009-dispatch] routed_secant={r} queued_concolic={q} requeued={rq} \
             linear_ratio={pct}% (of {total} concolic-eligible inputs)"
        );
    }
}

/// Bump the routed/queued counter and emit the ratio every 100 decisions.
pub fn lin_tick(routed: bool) {
    if routed {
        lin_bump_routed();
    } else {
        lin_bump_queued();
    }
    unsafe {
        if (LIN_ROUTED_SECANT + LIN_QUEUED_CONCOLIC) % 100 == 0 {
            lin_print_stats();
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct TB {
    t: bool,
    nl: bool,
}

#[derive(Clone, Debug)]
struct Ctx {
    mem: Vec<bool>,
    storage: HashMap<EVMU256, bool>,
    stack: Vec<TB>,
    input_data: Vec<bool>,
}

impl Ctx {
    fn read_input(&self, start: usize, length: usize) -> Vec<bool> {
        let length = length.min(MEMORY_LIMIT_BYTES);
        let mut res = vec![false; length];
        let available = self.input_data.len();
        if start < available && length > 0 {
            let end = start.saturating_add(length).min(available);
            if end > start {
                res[..end - start].copy_from_slice(&self.input_data[start..end]);
            }
        }
        res
    }
}

#[derive(Clone, Debug, Default)]
pub struct CmpLinearityTaint {
    mem: Vec<bool>,
    storage: HashMap<EVMU256, bool>,
    stack: Vec<TB>,
    ctxs: Vec<Ctx>,
}

impl CmpLinearityTaint {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn full_reset(&mut self) {
        self.mem.clear();
        self.storage.clear();
        self.stack.clear();
        self.ctxs.clear();
        lin_reset_verdict();
    }

    fn read_mem_tainted(&mut self, offset: usize, len: usize) -> bool {
        match safe_mem_end(offset, len) {
            Some(end) => {
                if self.mem.len() < end {
                    self.mem.resize(end, false);
                }
                self.mem[offset..end].iter().any(|x| *x)
            }
            None => false,
        }
    }

    fn write_input(&self, start: usize, length: usize) -> Vec<bool> {
        let length = length.min(MEMORY_LIMIT_BYTES);
        let mut res = vec![false; length];
        let available = self.mem.len();
        if start < available && length > 0 {
            let end = start.saturating_add(length).min(available);
            if end > start {
                res[..end - start].copy_from_slice(&self.mem[start..end]);
            }
        }
        res
    }

    fn push_ctx(&mut self, interp: &mut Interpreter) {
        let (arg_offset, arg_len) = match interp.bytecode.opcode() {
            0xf1 | 0xf2 | 0xf4 | 0xfa => (interp.stack.peek(3).unwrap(), interp.stack.peek(2).unwrap()),
            _ => return,
        };
        let arg_offset = as_u64(arg_offset) as usize;
        let arg_len = as_u64(arg_len) as usize;
        self.ctxs.push(Ctx {
            input_data: self.write_input(arg_offset, arg_len),
            mem: self.mem.clone(),
            storage: self.storage.clone(),
            stack: self.stack.clone(),
        });
        self.mem.clear();
        self.storage.clear();
        self.stack.clear();
    }

    fn pop_ctx(&mut self) {
        if let Some(ctx) = self.ctxs.pop() {
            self.mem = ctx.mem;
            self.storage = ctx.storage;
            self.stack = ctx.stack;
        }
    }
}

impl<SC> Middleware<SC> for CmpLinearityTaint
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {
        if host.call_depth > MAX_CALL_DEPTH {
            return;
        }

        macro_rules! pop {
            () => {
                self.stack.pop().unwrap_or_default()
            };
        }
        macro_rules! pushtb {
            ($v:expr) => {
                self.stack.push($v)
            };
        }
        // OR both fields over n popped slots, push one — LINEAR transfer.
        macro_rules! linear {
            ($n:expr) => {{
                let mut r = TB::default();
                for _ in 0..$n {
                    let x = pop!();
                    r.t |= x.t;
                    r.nl |= x.nl;
                }
                pushtb!(r);
            }};
        }
        // Non-linear op over n operands: result tainted if any operand tainted,
        // and marked non-linear whenever a tainted operand feeds it.
        macro_rules! nonlinear {
            ($n:expr) => {{
                let mut t = false;
                let mut nl = false;
                for _ in 0..$n {
                    let x = pop!();
                    t |= x.t;
                    nl |= x.nl;
                }
                pushtb!(TB { t, nl: nl || t });
            }};
        }
        macro_rules! popn {
            ($n:expr) => {
                for _ in 0..$n {
                    pop!();
                }
            };
        }
        macro_rules! clean {
            () => {
                pushtb!(TB::default())
            };
        }
        macro_rules! ensure {
            ($v:expr, $sz:expr) => {
                if $v.len() < $sz {
                    $v.resize($sz, false);
                }
            };
        }
        macro_rules! setup_mem {
            () => {{
                popn!(3);
                let len = as_u64(interp.stack.peek(0).expect("stack")) as usize;
                let off = as_u64(interp.stack.peek(2).expect("stack")) as usize;
                if let Some(end) = safe_mem_end(off, len) {
                    ensure!(self.mem, end);
                    self.mem[off..end].copy_from_slice(vec![false; len].as_slice());
                }
            }};
        }

        let opcode = interp.bytecode.opcode();
        // Shadow must track the real stack exactly; if it drifts, resync rather
        // than panic (this middleware is observ-only and must never abort a run).
        if interp.stack.len() != self.stack.len() {
            self.stack.resize(interp.stack.len(), TB::default());
        }

        match opcode {
            0x00 => {}
            0x01 => linear!(2),        // ADD
            0x02 => {
                // MUL: linear iff at most one operand tainted (tainted*const);
                // non-linear iff both tainted (symbolic*symbolic).
                let a = pop!();
                let b = pop!();
                let both = a.t && b.t;
                pushtb!(TB {
                    t: a.t || b.t,
                    nl: a.nl || b.nl || both,
                });
            }
            0x03 => linear!(2),        // SUB
            0x04..=0x07 => nonlinear!(2), // DIV SDIV MOD SMOD
            0x08..=0x09 => nonlinear!(3), // ADDMOD MULMOD
            0x0a => nonlinear!(2),     // EXP
            0x0b => nonlinear!(2),     // SIGNEXTEND
            // LT GT SLT SGT EQ — the GATE. Record classification.
            0x10..=0x14 => {
                let a = pop!();
                let b = pop!();
                let tainted = a.t || b.t;
                let nonlin = (a.t && a.nl) || (b.t && b.nl);
                if tainted {
                    LIN_SAW_TAINTED_CMP = true;
                    if nonlin {
                        LIN_SAW_NONLINEAR_CMP = true;
                    }
                    if let Some(m) = CMP_LINEARITY.as_mut() {
                        m.insert((interp.input.target_address, interp.bytecode.pc()), !nonlin);
                    }
                }
                pushtb!(TB { t: tainted, nl: nonlin });
            }
            0x15 => linear!(1),        // ISZERO
            0x16..=0x18 => nonlinear!(2), // AND OR XOR
            0x19 => nonlinear!(1),     // NOT
            0x1a..=0x1d => nonlinear!(2), // BYTE SHL SHR SAR
            0x20 => {
                // SHA3 — non-linear source.
                popn!(2);
                pushtb!(TB { t: true, nl: true });
            }
            0x30 => clean!(),
            0x31 => linear!(1),        // BALANCE
            0x32..=0x34 => clean!(),   // ORIGIN CALLER CALLVALUE
            0x35 => {
                // CALLDATALOAD — the canonical LINEAR taint source.
                pop!();
                if !self.ctxs.is_empty() {
                    let ctx = self.ctxs.last().unwrap();
                    let off = as_u64(interp.stack.peek(0).expect("stack")) as usize;
                    if off == 0 {
                        clean!();
                    } else {
                        let tainted = ctx.read_input(off, 32).contains(&true);
                        pushtb!(TB { t: tainted, nl: false });
                    }
                } else {
                    clean!();
                }
            }
            0x36 => clean!(),          // CALLDATASIZE
            0x37 => setup_mem!(),      // CALLDATACOPY
            0x38 => clean!(),
            0x39 => setup_mem!(),
            0x3a => clean!(),
            0x3b | 0x3f => {
                popn!(1);
                clean!();
            }
            0x3c => {
                popn!(4);
                let len = as_u64(interp.stack.peek(0).expect("stack")) as usize;
                let off = as_u64(interp.stack.peek(2).expect("stack")) as usize;
                if let Some(end) = safe_mem_end(off, len) {
                    ensure!(self.mem, end);
                    self.mem[off..end].copy_from_slice(vec![false; len].as_slice());
                }
            }
            0x3d => clean!(),
            0x3e => setup_mem!(),
            // TIMESTAMP (0x42) / NUMBER (0x43): the warp-controllable clock — a LINEAR
            // taint source for the warp secant (008), exactly like calldata. Without
            // this, temporal gates (reward = f(block.number)) are seen as untainted and
            // never routed to the secant. Other block ctx (COINBASE/GASLIMIT/CHAINID/…)
            // stay clean.
            0x42 | 0x43 => pushtb!(TB { t: true, nl: false }),
            0x41 | 0x44..=0x48 => clean!(),
            0x50 => {
                pop!();
            }
            0x51 => {
                // MLOAD — memory carries only taint; nl reset (simplification).
                pop!();
                let off = as_u64(interp.stack.peek(0).expect("stack")) as usize;
                let t = self.read_mem_tainted(off, 32);
                pushtb!(TB { t, nl: false });
            }
            0x52 => {
                popn!(1);
                let off = as_u64(interp.stack.peek(0).expect("stack")) as usize;
                let v = pop!();
                if let Some(end) = safe_mem_end(off, 32) {
                    ensure!(self.mem, end);
                    self.mem[off..end].copy_from_slice(vec![v.t; 32].as_slice());
                }
            }
            0x53 => {
                popn!(1);
                let off = as_u64(interp.stack.peek(0).expect("stack")) as usize;
                let v = pop!();
                if let Some(end) = safe_mem_end(off, 1) {
                    ensure!(self.mem, end);
                    self.mem[off] = v.t;
                }
            }
            0x54 | 0x5c => {
                pop!();
                let key = interp.stack.peek(0).expect("stack");
                let t = *self.storage.get(&key).unwrap_or(&false);
                pushtb!(TB { t, nl: false });
            }
            0x55 | 0x5d => {
                pop!();
                let v = pop!();
                let key = interp.stack.peek(0).expect("stack");
                self.storage.insert(key, v.t);
            }
            0x56 => {
                pop!();
            }
            0x57 => {
                // JUMPI — drop dest + cond.
                pop!();
                pop!();
            }
            0x58..=0x5a => clean!(),
            0x5b => {}
            0x5e => {
                popn!(3);
            }
            0x5f..=0x7f => clean!(), // PUSH
            0x80..=0x8f => {
                // DUP
                let n = (opcode - 0x80 + 1) as usize;
                let v = self.stack[self.stack.len() - n];
                pushtb!(v);
            }
            0x90..=0x9f => {
                // SWAP
                let n = (opcode - 0x90 + 2) as usize;
                let l = self.stack.len();
                self.stack.swap(l - n, l - 1);
            }
            0xa0..=0xa4 => {
                let n = (opcode - 0xa0 + 2) as usize;
                popn!(n);
            }
            0xf0 => {
                popn!(3);
                clean!();
            }
            0xf1 | 0xf2 => {
                popn!(7);
                clean!();
                self.push_ctx(interp);
            }
            0xf3 => {
                popn!(2);
            }
            0xf4 | 0xfa => {
                popn!(6);
                clean!();
                self.push_ctx(interp);
            }
            0xf5 => {
                popn!(4);
                clean!();
            }
            0xfd | 0xfe | 0xff => {}
            _ => {
                // Unknown opcode: resync defensively on next step (never panic).
            }
        }
    }

    unsafe fn on_return(
        &mut self,
        _interp: &mut Interpreter,
        host: &mut FuzzHost<SC>,
        _state: &mut EVMFuzzState,
        _by: &Bytes,
    ) {
        if host.call_depth > MAX_CALL_DEPTH {
            return;
        }
        self.pop_ctx();
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::CmpLinearity
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn any::Any {
        self
    }
}

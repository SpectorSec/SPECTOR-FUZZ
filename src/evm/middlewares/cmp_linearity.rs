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
    types::{as_u64, convert_u256_to_h160, EVMAddress, EVMFuzzState, EVMU256},
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

/// Feature 013 Phase 1 — injection detection flags.
/// Set at the CALL/DELEGATECALL/STATICCALL boundary when tainted bytes reach
/// the `to` address or forwarded calldata. Reset per-execution in `full_reset`.
pub static mut INJECTION_TAINTED_CALL_TARGET: bool = false;
pub static mut INJECTION_TAINTED_CALLDATA: bool = false;

/// Feature 013 Phase 2 — four-link chain records.
/// Per-CALL record appended during reexecution when a CALL has injection taint.
#[derive(Clone, Debug)]
pub struct TaintedCallRecord {
    pub target: EVMAddress,
    pub selector: [u8; 4],
    pub succeeded: bool,
}

pub static mut TAINTED_CALLS: Vec<TaintedCallRecord> = Vec::new();

/// Feature 013 Phase 4 — value-confirmed provenance flag.
/// Set when a storage slot read retains its tainted written value.
pub static mut INJECTION_CONFIRMED_PROVENANCE: bool = false;

/// Feature 013 Phase 5 — master flag: a tainted call passed GUARD + SINK + SELECTOR.
pub static mut INJECTION_CONFIRMED_EXPLOIT_PATH: bool = false;

/// Phase 0 safety gate: true when the taint analysis reexecution actually ran
/// this execution. When false, `injection_exploit_path_detected()` returns true
/// (no gating), so oracles fire as normal for step/non-concolic inputs.
pub static mut INJECTION_ANALYSIS_RAN: bool = false;

/// Post-reexecution: run the four-link chain on all recorded tainted calls.
pub fn injection_chain_verdict() -> bool {
    unsafe {
        if TAINTED_CALLS.is_empty() {
            INJECTION_CONFIRMED_EXPLOIT_PATH = false;
            return false;
        }
        for rec in TAINTED_CALLS.iter() {
            if rec.succeeded && rec.selector != [0u8; 4] {
                INJECTION_CONFIRMED_EXPLOIT_PATH = true;
                return true;
            }
        }
        INJECTION_CONFIRMED_EXPLOIT_PATH = false;
        false
    }
}

/// Read the Phase 5 exploit path flag. Returns true by default when the
/// taint analysis hasn't run (safe no-op for step/non-concolic inputs).
pub fn injection_exploit_path_detected() -> bool {
    unsafe { !INJECTION_ANALYSIS_RAN || INJECTION_CONFIRMED_EXPLOIT_PATH }
}

/// Per-execution reset of all injection detection static flags.
pub fn injection_reset_static() {
    unsafe {
        INJECTION_TAINTED_CALL_TARGET = false;
        INJECTION_TAINTED_CALLDATA = false;
        INJECTION_CONFIRMED_PROVENANCE = false;
        INJECTION_CONFIRMED_EXPLOIT_PATH = false;
        INJECTION_ANALYSIS_RAN = false;
    }
    injection_reset_chain();
}

pub fn injection_reset_chain() {
    unsafe {
        TAINTED_CALLS.clear();
    }
}

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
    /// Bitmap of arg indices (after the 4-byte selector) that contributed to
    /// this value. Bit i set = the u128 word at calldata offset 4+i*32 is in
    /// the provenance chain. Propagated through linear/nonlinear ops via OR;
    /// cleared at SLOAD/MLOAD (memory/storage lose provenance).
    provenance: u64,
}

#[derive(Clone, Debug)]
struct Ctx {
    mem: Vec<bool>,
    storage: HashMap<EVMU256, bool>,
    stack: Vec<TB>,
    input_data: Vec<bool>,
    shared_storage: bool,
    tainted_record_idx: Option<usize>,
    callee: EVMAddress,
    callee_selector: [u8; 4],
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
        unsafe {
            INJECTION_TAINTED_CALL_TARGET = false;
            INJECTION_TAINTED_CALLDATA = false;
            INJECTION_CONFIRMED_PROVENANCE = false;
            INJECTION_CONFIRMED_EXPLOIT_PATH = false;
        }
        injection_reset_chain();
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

    fn push_ctx(&mut self, interp: &mut Interpreter, tainted_record_idx: Option<usize>) {
        let opcode = interp.bytecode.opcode();
        let (arg_offset, arg_len) = match opcode {
            0xf1 | 0xf2 => (interp.stack.peek(3).unwrap(), interp.stack.peek(4).unwrap()),
            0xf4 | 0xfa => (interp.stack.peek(2).unwrap(), interp.stack.peek(3).unwrap()),
            _ => return,
        };
        let arg_offset = as_u64(arg_offset) as usize;
        let arg_len = as_u64(arg_len) as usize;
        let shared_storage = opcode == 0xf4 || opcode == 0xf2;
        let callee = convert_u256_to_h160(interp.stack.peek(1).unwrap_or(EVMU256::ZERO));
        let callee_selector = {
            let mut sel = [0u8; 4];
            if arg_len >= 4 {
                if interp.memory.len() >= arg_offset + 4 {
                    sel.copy_from_slice(&interp.memory.slice_len(arg_offset, 4));
                }
            }
            sel
        };
        self.ctxs.push(Ctx {
            input_data: self.write_input(arg_offset, arg_len),
            mem: self.mem.clone(),
            storage: self.storage.clone(),
            stack: self.stack.clone(),
            shared_storage,
            tainted_record_idx,
            callee,
            callee_selector,
        });
        self.mem.clear();
        if !shared_storage {
            self.storage.clear();
        }
        self.stack.clear();
    }

    fn pop_ctx(&mut self) -> Option<usize> {
        if let Some(ctx) = self.ctxs.pop() {
            self.mem = ctx.mem;
            self.stack = ctx.stack;
            if !ctx.shared_storage {
                self.storage = ctx.storage;
            }
            ctx.tainted_record_idx
        } else {
            None
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
                    r.provenance |= x.provenance;
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
                let mut provenance = 0u64;
                for _ in 0..$n {
                    let x = pop!();
                    t |= x.t;
                    nl |= x.nl;
                    provenance |= x.provenance;
                }
                pushtb!(TB { t, nl: nl || t, provenance });
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
                    provenance: a.provenance | b.provenance,
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
                pushtb!(TB { t: tainted, nl: nonlin, provenance: a.provenance | b.provenance });
            }
            0x15 => {
                let a = pop!();
                pushtb!(TB { t: a.t, nl: a.nl, provenance: a.provenance });
            }
            0x16..=0x18 => nonlinear!(2), // AND OR XOR
            0x19 => nonlinear!(1),     // NOT
            0x1a..=0x1d => nonlinear!(2), // BYTE SHL SHR SAR
            0x20 => {
                // SHA3 — non-linear source.
                popn!(2);
                pushtb!(TB { t: true, nl: true, provenance: 0 });
            }
            0x30 => clean!(),
            0x31 => linear!(1),        // BALANCE
            0x32..=0x34 => clean!(),   // ORIGIN CALLER CALLVALUE
            0x35 => {
                // CALLDATALOAD — the canonical LINEAR taint source.
                // Sets provenance bit i when loading bytes from arg i offset.
                pop!();
                if !self.ctxs.is_empty() {
                    let ctx = self.ctxs.last().unwrap();
                    let off = as_u64(interp.stack.peek(0).expect("stack")) as usize;
                    if off == 0 {
                        clean!();
                    } else {
                        let tainted = ctx.read_input(off, 32).contains(&true);
                        let provenance = if tainted && off >= 4 {
                            let arg_idx = (off - 4) / 32;
                            if arg_idx < 64 { 1u64 << arg_idx } else { 0 }
                        } else { 0 };
                        pushtb!(TB { t: tainted, nl: false, provenance });
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
            0x42 | 0x43 => pushtb!(TB { t: true, nl: false, provenance: 0 }),
            0x41 | 0x44..=0x48 => clean!(),
            0x50 => {
                pop!();
            }
            0x51 => {
                // MLOAD — memory carries only taint; nl and provenance reset (simplification).
                pop!();
                let off = as_u64(interp.stack.peek(0).expect("stack")) as usize;
                let t = self.read_mem_tainted(off, 32);
                pushtb!(TB { t, nl: false, provenance: 0 });
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
                let address = interp.input.target_address;
                let persistent = host.tainted_storage.get(&(address, key))
                    .map(|p| p.tainted).unwrap_or(false);
                let local = *self.storage.get(&key).unwrap_or(&false);
                let merged = persistent || local;
                self.storage.insert(key, merged);
                if merged && persistent {
                    INJECTION_CONFIRMED_PROVENANCE = true;
                }
                pushtb!(TB { t: merged, nl: false, provenance: 0 });
            }
            0x55 | 0x5d => {
                pop!();
                let v = pop!();
                let key = interp.stack.peek(0).expect("stack");
                self.storage.insert(key, v.t);
                let addr = interp.input.target_address;
                if v.t {
                    host.tainted_storage.insert(
                        (addr, key),
                        crate::evm::host::TaintProvenance {
                            tainted: true,
                            stored_value: interp.stack.peek(1).unwrap_or(EVMU256::ZERO),
                        },
                    );
                }
                if v.provenance != 0 {
                    let entry = host.arg_slot_provenance
                        .entry((addr, key))
                        .or_insert(0);
                    *entry |= v.provenance;
                }
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
                let stack_len = self.stack.len();
                let tainted = stack_len >= 7 && self.stack[stack_len - 6].t;
                if tainted {
                    INJECTION_TAINTED_CALL_TARGET = true;
                }
                let (calldata_off, calldata_len) = (
                    as_u64(interp.stack.peek(3).unwrap_or(EVMU256::ZERO)) as usize,
                    as_u64(interp.stack.peek(4).unwrap_or(EVMU256::ZERO)) as usize,
                );
                let calldata_tainted = self.read_mem_tainted(calldata_off, calldata_len);
                if calldata_tainted {
                    INJECTION_TAINTED_CALLDATA = true;
                }
                let tainted_record_idx = if tainted || calldata_tainted {
                    let target = convert_u256_to_h160(interp.stack.peek(1).unwrap_or(EVMU256::ZERO));
                    let mut selector = [0u8; 4];
                    if calldata_len >= 4 {
                        if interp.memory.len() >= calldata_off + 4 {
                            selector.copy_from_slice(&interp.memory.slice_len(calldata_off, 4));
                        } else if interp.memory.len() > calldata_off {
                            let avail = interp.memory.len() - calldata_off;
                            selector[..avail].copy_from_slice(&interp.memory.slice_len(calldata_off, avail));
                        }
                    }
                    unsafe {
                        TAINTED_CALLS.push(TaintedCallRecord {
                            target,
                            selector,
                            succeeded: false,
                        });
                        Some(TAINTED_CALLS.len() - 1)
                    }
                } else {
                    None
                };
                popn!(7);
                clean!();
                self.push_ctx(interp, tainted_record_idx);
            }
            0xf3 => {
                popn!(2);
            }
            0xf4 | 0xfa => {
                let stack_len = self.stack.len();
                let tainted = stack_len >= 6 && self.stack[stack_len - 5].t;
                if tainted {
                    INJECTION_TAINTED_CALL_TARGET = true;
                }
                let (calldata_off, calldata_len) = (
                    as_u64(interp.stack.peek(2).unwrap_or(EVMU256::ZERO)) as usize,
                    as_u64(interp.stack.peek(3).unwrap_or(EVMU256::ZERO)) as usize,
                );
                let calldata_tainted = self.read_mem_tainted(calldata_off, calldata_len);
                if calldata_tainted {
                    INJECTION_TAINTED_CALLDATA = true;
                }
                let tainted_record_idx = if tainted || calldata_tainted {
                    let target = convert_u256_to_h160(interp.stack.peek(1).unwrap_or(EVMU256::ZERO));
                    let mut selector = [0u8; 4];
                    if calldata_len >= 4 {
                        if interp.memory.len() >= calldata_off + 4 {
                            selector.copy_from_slice(&interp.memory.slice_len(calldata_off, 4));
                        } else if interp.memory.len() > calldata_off {
                            let avail = interp.memory.len() - calldata_off;
                            selector[..avail].copy_from_slice(&interp.memory.slice_len(calldata_off, avail));
                        }
                    }
                    unsafe {
                        TAINTED_CALLS.push(TaintedCallRecord {
                            target,
                            selector,
                            succeeded: false,
                        });
                        Some(TAINTED_CALLS.len() - 1)
                    }
                } else {
                    None
                };
                popn!(6);
                clean!();
                self.push_ctx(interp, tainted_record_idx);
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
        ret: &Bytes,
    ) {
        if host.call_depth > MAX_CALL_DEPTH {
            return;
        }

        // Feature 014 Phase 0: mark oracle return data as tainted in memory.
        // Check the returning call's callee against known oracle selectors.
        if !self.ctxs.is_empty() {
            if let Some(ctx) = self.ctxs.last() {
                if let Some(selectors) = host.oracle_selectors.get(&ctx.callee) {
                    if selectors.contains(&ctx.callee_selector) {
                        let end = ret.len().min(MEMORY_LIMIT_BYTES);
                        if self.mem.len() < end {
                            self.mem.resize(end, false);
                        }
                        self.mem[..end].fill(true);
                    }
                }
            }
        }

        if let Some(tainted_idx) = self.pop_ctx() {
            if let Some(rec) = TAINTED_CALLS.get_mut(tainted_idx) {
                rec.succeeded = true;
            }
        }
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

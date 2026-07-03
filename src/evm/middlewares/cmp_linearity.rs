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

/// Feature 016 Phase 1 — known oracle selectors for per-word-offset dim tagging.
/// Each is keccak256(canonical signature)[:4]; pinned by selector_constants_match_keccak.
const LATEST_ROUND_DATA_SEL: [u8; 4] = [0xfe, 0xaf, 0x96, 0x8c]; // latestRoundData()
const LATEST_ANSWER_SEL: [u8; 4] = [0x50, 0xd2, 0x5b, 0xcd]; // latestAnswer()
const GET_ROUND_DATA_SEL: [u8; 4] = [0x9a, 0x6f, 0xc8, 0xf5]; // getRoundData(uint80)
const PEEK_SEL: [u8; 4] = [0x59, 0xe0, 0x2d, 0xd7]; // peek()

/// Feature 016 Phase 2 — the 015↔016 BRIDGE. Reflexive valuation reads that
/// Feature 015 targets (Promote→Locate→Amplify). Unlike Chainlink, these are
/// SELF-IDENTIFYING by selector alone: any contract exposing `get_virtual_price()`
/// is, by ABI convention, returning a manipulable price-per-share. So they are
/// recognized ADDRESS-AGNOSTICALLY in on_return (no host.oracle_selectors entry
/// needed) — the manipulated price gets a Price dim → secant probes /256 not /64
/// → PRICE_MANIPULATION_FLOW can fire on the yDAI class. All keccak-pinned by
/// selector_constants_match_keccak.
const GET_VIRTUAL_PRICE_SEL: [u8; 4] = [0xbb, 0x7b, 0x8b, 0x80]; // get_virtual_price()  (Curve)
const PRICE_PER_SHARE_SEL: [u8; 4] = [0x99, 0x53, 0x0b, 0x06]; // pricePerShare()  (Yearn v2)
const GET_PRICE_PER_FULL_SHARE_SEL: [u8; 4] = [0x77, 0xc7, 0xb8, 0xfc]; // getPricePerFullShare()  (Yearn v1 / yDAI)
const EXCHANGE_RATE_STORED_SEL: [u8; 4] = [0x18, 0x2d, 0xf0, 0xf5]; // exchangeRateStored()  (Compound cToken)
const EXCHANGE_RATE_CURRENT_SEL: [u8; 4] = [0xbd, 0x6d, 0x89, 0x4d]; // exchangeRateCurrent()  (Compound cToken)
const CONVERT_TO_ASSETS_SEL: [u8; 4] = [0x07, 0xa2, 0xd1, 0x3a]; // convertToAssets(uint256)  (ERC4626)
const GET_UNDERLYING_PRICE_SEL: [u8; 4] = [0xfc, 0x57, 0xd4, 0xdf]; // getUnderlyingPrice(address)  (Compound oracle)
const GET_DY_SEL: [u8; 4] = [0x5e, 0x0d, 0x44, 0x3f]; // get_dy(int128,int128,uint256)  (Curve)
const SLOT0_SEL: [u8; 4] = [0x38, 0x50, 0xc7, 0xbd]; // slot0()  (Uniswap V3 → word0 = sqrtPriceX96)

/// Membership test for the address-agnostic reflexive bridge. Any selector here is
/// tagged by tag_oracle_return regardless of the callee address.
fn is_reflexive_valuation_selector(selector: &[u8; 4]) -> bool {
    matches!(
        *selector,
        GET_VIRTUAL_PRICE_SEL
            | PRICE_PER_SHARE_SEL
            | GET_PRICE_PER_FULL_SHARE_SEL
            | EXCHANGE_RATE_STORED_SEL
            | EXCHANGE_RATE_CURRENT_SEL
            | CONVERT_TO_ASSETS_SEL
            | GET_UNDERLYING_PRICE_SEL
            | GET_DY_SEL
            | SLOT0_SEL
    )
}

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

/// Feature 016 Phase 2 — flow type detection flags.
/// Proxy bridge: dim != Generic crosses DELEGATECALL boundary.
pub static mut PROXY_TAINT_FLOW: bool = false;
/// Price manipulation: Price-dim comparison gates value-moving CALL.
pub static mut PRICE_MANIPULATION_FLOW: bool = false;
/// Accumulator inflation: same slot written with Price-dim ≥2×.
pub static mut ACCUMULATOR_INFLATION_FLOW: bool = false;
/// Internal: Price-dim comparison seen before the next CALL.
pub static mut PRICE_DIM_CMP_SEEN: bool = false;

/// Feature 017 Wire B — published alongside located_dim. True when the located
/// lever carried Timestamp taint (ts_seen reached SSTORE). Read by the planner
/// to engage the warp lever dimensionally (campaign_planner.rs).
pub static mut TIMESTAMP_DIM_LOCATED: bool = false;
/// Feature 017 internal — set during reexecution when any SSTORE writes a value
/// with ts_seen=true. Checked after reexecution to set TIMESTAMP_DIM_LOCATED.
pub static mut TIMESTAMP_TAINT_WRITTEN: bool = false;

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
        PROXY_TAINT_FLOW = false;
        PRICE_MANIPULATION_FLOW = false;
        ACCUMULATOR_INFLATION_FLOW = false;
        PRICE_DIM_CMP_SEEN = false;
        TIMESTAMP_DIM_LOCATED = false;
        TIMESTAMP_TAINT_WRITTEN = false;
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

/// Feature 016 — Taint dimension tags.
/// Tags the economic dimension of a tainted value. Most-specific-wins lattice:
/// Price > Accumulator > Balance > Timestamp > Generic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum TaintDim {
    #[default]
    Generic = 0,
    Timestamp = 1,
    Balance = 2,
    Accumulator = 3,
    Price = 4,
}

// Most-specific-wins is the enum's own `Ord`: the `#[repr(u8)]` discriminants are
// laid out Generic(0) < Timestamp < Balance < Accumulator < Price(4), so `a.max(b)`
// picks the more specific dimension. Single source of truth — no separate priority
// table to drift out of sync with the variant order.

#[derive(Clone, Copy, Debug)]
struct TB {
    t: bool,
    nl: bool,
    /// Bitmap of arg indices (after the 4-byte selector) that contributed to
    /// this value. Bit i set = the u128 word at calldata offset 4+i*32 is in
    /// the provenance chain. Propagated through linear/nonlinear ops via OR;
    /// cleared at SLOAD/MLOAD (memory/storage lose provenance).
    provenance: u64,
    /// Feature 016 — economic dimension tag. Most-specific-wins propagation.
    dim: TaintDim,
    /// Feature 017 Wire A — Timestamp-present bit that survives the .max() merge
    /// via OR (where dim gets collapsed). Set on TIMESTAMP/NUMBER opcode, OR'd
    /// through linear ops, reset by nonlinear ops. Published at SSTORE as
    /// TaintProvenance.ts_seen for persistence; SLOAD merges it back.
    ts_seen: bool,
}

impl Default for TB {
    fn default() -> Self {
        TB { t: false, nl: false, provenance: 0, dim: TaintDim::Generic, ts_seen: false }
    }
}

#[derive(Clone, Debug)]
struct Ctx {
    mem: Vec<TaintDim>,
    // 017 Phase 2 (cross-CALL provenance): the caller's memory-provenance shadow,
    // saved here so pop_ctx can restore it symmetrically with `mem`.
    mem_prov: Vec<u64>,
    storage: HashMap<EVMU256, TaintDim>,
    stack: Vec<TB>,
    input_data: Vec<TaintDim>,
    // 017 Phase 2: the callee's inherited calldata provenance, snapshotted from the
    // caller's `mem_prov` over the forwarded argOffset..argLen at push_ctx. Read by the
    // callee's CALLDATALOAD to inherit origin-anchored bits instead of re-minting local ones.
    input_prov: Vec<u64>,
    shared_storage: bool,
    tainted_record_idx: Option<usize>,
    callee: EVMAddress,
    callee_selector: [u8; 4],
    // Feature 016 Phase 4 (return-data seam): where the caller expects this call's
    // return data to land in ITS memory. Captured pre-execution in push_ctx; used in
    // on_return (after pop_ctx restores caller mem) to splice the tagged return dims
    // into the caller at the legacy CALL retOffset. Without this the dim tagged onto
    // the callee's memory is discarded when pop_ctx swaps memory contexts back.
    ret_offset: usize,
    ret_len: usize,
}

impl Ctx {
    fn read_input(&self, start: usize, length: usize) -> Vec<TaintDim> {
        let length = length.min(MEMORY_LIMIT_BYTES);
        let mut res = vec![TaintDim::Generic; length];
        let available = self.input_data.len();
        if start < available && length > 0 {
            let end = start.saturating_add(length).min(available);
            if end > start {
                res[..end - start].copy_from_slice(&self.input_data[start..end]);
            }
        }
        res
    }

    /// 017 Phase 2: OR the inherited provenance bits over a `length`-byte calldata window
    /// starting at `start`. Returns 0 when the window has no inherited bits (fail-safe:
    /// the callee then falls back to the origin-anchored mint, preserving existing behavior).
    fn read_input_prov(&self, start: usize, length: usize) -> u64 {
        let length = length.min(MEMORY_LIMIT_BYTES);
        let available = self.input_prov.len();
        if start >= available || length == 0 {
            return 0;
        }
        let end = start.saturating_add(length).min(available);
        self.input_prov[start..end].iter().fold(0u64, |acc, b| acc | *b)
    }
}

#[derive(Clone, Debug)]
pub struct CmpLinearityTaint {
    mem: Vec<TaintDim>,
    storage: HashMap<EVMU256, TaintDim>,
    stack: Vec<TB>,
    ctxs: Vec<Ctx>,
    // Feature 016 Phase 4: shadow of the RETURNDATA buffer's dimensions, refreshed on
    // every call return. RETURNDATACOPY reads from here instead of wiping to Generic,
    // so a price fetched via `x = vault.getPricePerFullShare()` (which solc lowers to a
    // CALL + RETURNDATACOPY) keeps its Price dim into the caller.
    ret_dims: Vec<TaintDim>,
    // 017 Phase 2 (cross-CALL provenance): memory-provenance shadow, a per-byte twin of
    // `mem`. Written on MSTORE/MSTORE8 with the stored value's `TB.provenance`; read at
    // push_ctx (write_input_prov) to forward origin-anchored bits into a callee's calldata.
    // Never read by MLOAD (that stays provenance-lossy, preserving depth-0 byte-identity);
    // its sole consumer is the CALL boundary.
    mem_prov: Vec<u64>,
}

impl Default for CmpLinearityTaint {
    fn default() -> Self {
        CmpLinearityTaint {
            mem: Vec::new(),
            storage: HashMap::new(),
            stack: Vec::new(),
            ctxs: Vec::new(),
            ret_dims: Vec::new(),
            mem_prov: Vec::new(),
        }
    }
}

impl CmpLinearityTaint {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn full_reset(&mut self) {
        self.mem.clear();
        self.mem_prov.clear();
        self.storage.clear();
        self.stack.clear();
        self.ctxs.clear();
        self.ret_dims.clear();
        lin_reset_verdict();
        unsafe {
            INJECTION_TAINTED_CALL_TARGET = false;
            INJECTION_TAINTED_CALLDATA = false;
            INJECTION_CONFIRMED_PROVENANCE = false;
            INJECTION_CONFIRMED_EXPLOIT_PATH = false;
            TIMESTAMP_TAINT_WRITTEN = false;
        }
        injection_reset_chain();
    }

    fn read_mem_tainted(&mut self, offset: usize, len: usize) -> bool {
        match safe_mem_end(offset, len) {
            Some(end) => {
                if self.mem.len() < end {
                    self.mem.resize(end, TaintDim::Generic);
                }
                self.mem[offset..end].iter().any(|d| *d != TaintDim::Generic)
            }
            None => false,
        }
    }

    fn write_input(&self, start: usize, length: usize) -> Vec<TaintDim> {
        let length = length.min(MEMORY_LIMIT_BYTES);
        let mut res = vec![TaintDim::Generic; length];
        let available = self.mem.len();
        if start < available && length > 0 {
            let end = start.saturating_add(length).min(available);
            if end > start {
                res[..end - start].copy_from_slice(&self.mem[start..end]);
            }
        }
        res
    }

    /// 017 Phase 2: snapshot the provenance shadow over the forwarded calldata region
    /// (argOffset..argLen) into the callee's `input_prov`. Provenance-typed twin of
    /// `write_input`; a region with no bits yields all-zero (callee falls back to mint).
    fn write_input_prov(&self, start: usize, length: usize) -> Vec<u64> {
        let length = length.min(MEMORY_LIMIT_BYTES);
        let mut res = vec![0u64; length];
        let available = self.mem_prov.len();
        if start < available && length > 0 {
            let end = start.saturating_add(length).min(available);
            if end > start {
                res[..end - start].copy_from_slice(&self.mem_prov[start..end]);
            }
        }
        res
    }

    fn push_ctx(&mut self, interp: &mut Interpreter, tainted_record_idx: Option<usize>) {
        let opcode = interp.bytecode.opcode();
        let (arg_offset, arg_len, ret_offset, ret_len) = match opcode {
            // CALL / CALLCODE: gas addr value argOff argLen retOff retLen
            0xf1 | 0xf2 => (
                interp.stack.peek(3).unwrap(),
                interp.stack.peek(4).unwrap(),
                interp.stack.peek(5).unwrap_or(EVMU256::ZERO),
                interp.stack.peek(6).unwrap_or(EVMU256::ZERO),
            ),
            // DELEGATECALL / STATICCALL: gas addr argOff argLen retOff retLen
            0xf4 | 0xfa => (
                interp.stack.peek(2).unwrap(),
                interp.stack.peek(3).unwrap(),
                interp.stack.peek(4).unwrap_or(EVMU256::ZERO),
                interp.stack.peek(5).unwrap_or(EVMU256::ZERO),
            ),
            _ => return,
        };
        let arg_offset = as_u64(arg_offset) as usize;
        let arg_len = as_u64(arg_len) as usize;
        let ret_offset = as_u64(ret_offset) as usize;
        let ret_len = as_u64(ret_len) as usize;
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
            // 017 Phase 2: forward origin-anchored provenance over the same calldata window.
            input_prov: self.write_input_prov(arg_offset, arg_len),
            mem: self.mem.clone(),
            mem_prov: self.mem_prov.clone(),
            storage: self.storage.clone(),
            stack: self.stack.clone(),
            shared_storage,
            tainted_record_idx,
            callee,
            callee_selector,
            ret_offset,
            ret_len,
        });
        self.mem.clear();
        self.mem_prov.clear();
        if !shared_storage {
            self.storage.clear();
        }
        self.stack.clear();
    }

    fn pop_ctx(&mut self) -> Option<usize> {
        if let Some(ctx) = self.ctxs.pop() {
            self.mem = ctx.mem;
            self.mem_prov = ctx.mem_prov;
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

/// Feature 016 Phase 1 — tag oracle return data per word offset with
/// dimension-specific TaintDim (Price / Timestamp / Generic).
fn tag_oracle_return(mem: &mut Vec<TaintDim>, ret: &Bytes, selector: &[u8; 4]) {
    let word_layout: &[(usize, TaintDim)] = if *selector == LATEST_ROUND_DATA_SEL || *selector == GET_ROUND_DATA_SEL {
        &[
            (0, TaintDim::Generic),    // roundId
            (32, TaintDim::Price),     // answer
            (64, TaintDim::Timestamp), // startedAt
            (96, TaintDim::Timestamp), // updatedAt
            (128, TaintDim::Generic),  // answeredInRound
        ]
    } else if *selector == LATEST_ANSWER_SEL {
        &[(0, TaintDim::Price)]
    } else if *selector == PEEK_SEL {
        &[(0, TaintDim::Price)]
    } else if *selector == SLOT0_SEL {
        // Uniswap V3 slot0(): word0 = sqrtPriceX96 (Price). The remaining packed
        // words (tick, observationIndex, cardinality, feeProtocol, unlocked) are
        // Generic and left untagged — only the price component carries a dim.
        &[(0, TaintDim::Price)]
    } else if is_reflexive_valuation_selector(selector) {
        // get_virtual_price / pricePerShare / getPricePerFullShare / exchangeRate* /
        // convertToAssets / getUnderlyingPrice / get_dy — all return a single
        // price-per-share / exchange-rate word.
        &[(0, TaintDim::Price)]
    } else {
        &[(0, TaintDim::Generic)]
    };

    for &(offset, dim) in word_layout {
        let start = offset;
        let end = (offset + 32).min(ret.len()).min(MEMORY_LIMIT_BYTES);
        if end > start {
            if mem.len() < end {
                mem.resize(end, TaintDim::Generic);
            }
            mem[start..end].fill(dim);
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
        // OR fields over n popped slots, push one — LINEAR transfer.
        // Dim: most-specific-wins via TaintDim's Ord (a.dim.max(b.dim)).
        // 017: ts_seen OR-merged so Timestamp provenance survives scalar collapse.
        macro_rules! linear {
            ($n:expr) => {{
                let mut r = TB::default();
                for _ in 0..$n {
                    let x = pop!();
                    r.t |= x.t;
                    r.nl |= x.nl;
                    r.provenance |= x.provenance;
                    r.dim = r.dim.max(x.dim); // most-specific-wins via TaintDim Ord
                    r.ts_seen |= x.ts_seen; // OR-merge: preserves through .max() collapse
                }
                pushtb!(r);
            }};
        }
        // Non-linear op over n operands: result tainted if any operand tainted,
        // and marked non-linear whenever a tainted operand feeds it.
        // Dim: reset to Generic (non-linear ops lose dimension context).
        // 017: ts_seen reset (non-linear ops lose all temporal context).
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
                pushtb!(TB { t, nl: nl || t, provenance, dim: TaintDim::Generic, ts_seen: false });
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
                    $v.resize($sz, TaintDim::Generic);
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
                    let fill = vec![TaintDim::Generic; len];
                    self.mem[off..end].copy_from_slice(fill.as_slice());
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
                    dim: a.dim.max(b.dim),
                    ts_seen: a.ts_seen || b.ts_seen, // 017: temporal signal passes through MUL
                });
            }
            0x03 => linear!(2),        // SUB
            // DIV / SDIV — non-linear for the secant (breaks the linear model), but
            // dimension-PRESERVING: division is how on-chain prices are constructed
            // (price = numerator / denominator), so lumping it with SHA3/EXP under
            // `nonlinear!` (which resets dim → Generic) silently strips the Price tag
            // off every self-computed AMM spot price / pricePerShare before it reaches
            // the secant. Keep `nl` set; carry the numerator's dimension when the
            // denominator is just a scaling factor. See dim_propagation_tests.
            0x04 | 0x05 => {
                let a = pop!(); // numerator (top of stack)
                let b = pop!(); // denominator
                let dim = match (a.dim, b.dim) {
                    // price / scalar → price ; scalar / supply → supply's dim
                    (d, TaintDim::Generic) | (TaintDim::Generic, d) => d,
                    // same specific axis divided out → dimensionless ratio
                    (x, y) if x == y => TaintDim::Generic,
                    // two different specific dims → most-specific-wins
                    (x, y) => x.max(y),
                };
                let tainted = a.t || b.t;
                pushtb!(TB {
                    t: tainted,
                    nl: tainted, // non-linear whenever a tainted operand feeds the DIV
                    provenance: a.provenance | b.provenance,
                    dim,
                    ts_seen: a.ts_seen || b.ts_seen, // 017: temporal signal preserved through division
                });
            }
            0x06..=0x07 => nonlinear!(2), // MOD SMOD — truly dimensionless
            0x08..=0x09 => nonlinear!(3), // ADDMOD MULMOD
            0x0a => nonlinear!(2),     // EXP
            // SIGNEXTEND — non-linear at the sign boundary, but dimension-PRESERVING:
            // widening a signed integer (int128→int256 in Curve get_dy, int24 `tick`
            // sign-extended out of V3 slot0) does not change its economic meaning. Stack
            // top is the byte-count constant; the value operand carries the dimension.
            0x0b => {
                let _size = pop!(); // byte index (top of stack) — the width constant
                let value = pop!();
                let tainted = _size.t || value.t;
                pushtb!(TB {
                    t: tainted,
                    nl: tainted,
                    provenance: _size.provenance | value.provenance,
                    dim: value.dim,
                    ts_seen: _size.ts_seen || value.ts_seen, // 017: temporal signal survives signextend
                });
            }
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
                    // Feature 016 Phase 2: track Price-dim comparisons.
                    if a.dim == TaintDim::Price || b.dim == TaintDim::Price {
                        PRICE_DIM_CMP_SEEN = true;
                    }
                    if let Some(m) = CMP_LINEARITY.as_mut() {
                        m.insert((interp.input.target_address, interp.bytecode.pc()), !nonlin);
                    }
                }
                pushtb!(TB {
                    t: tainted,
                    nl: nonlin,
                    provenance: a.provenance | b.provenance,
                    dim: a.dim.max(b.dim),
                    ts_seen: a.ts_seen || b.ts_seen, // 017: temporal signal passes through comparisons
                });
            }
            0x15 => {
                // ISZERO — a comparison against zero. LT/GT/EQ (0x10..=0x14) set
                // PRICE_DIM_CMP_SEEN, but a raw Price flowing straight into ISZERO
                // was uncounted: `require(price != 0)`, `if (price)` truthiness, and
                // the negation half of `!(a < b)` all compile to ISZERO(price). A
                // manipulated price gating one of those guards slipped past the
                // price-manipulation flow. Flag it here too; dim passes through.
                let a = pop!();
                if a.t && a.dim == TaintDim::Price {
                    PRICE_DIM_CMP_SEEN = true;
                }
                pushtb!(TB { t: a.t, nl: a.nl, provenance: a.provenance, dim: a.dim, ts_seen: a.ts_seen });
            }
            // AND — non-linear for the secant, but dimension-PRESERVING when one
            // operand is a constant BITMASK. This is how packed storage words are
            // unpacked (Uniswap V3 slot0: `value & 0xff…` isolates a sub-field), so
            // lumping it with OR/XOR would strip the Price tag off sqrtPriceX96 the
            // instant slot0() is decoded (finding ② tags it, ③ keeps it alive).
            0x16 => {
                let a = pop!();
                let b = pop!();
                let dim = match (a.dim, b.dim) {
                    // value & const-mask → value's dimension survives the unpack
                    (d, TaintDim::Generic) | (TaintDim::Generic, d) => d,
                    // two specific dims masked together → most-specific-wins
                    (x, y) => x.max(y),
                };
                let tainted = a.t || b.t;
                pushtb!(TB { t: tainted, nl: tainted, provenance: a.provenance | b.provenance, dim, ts_seen: a.ts_seen || b.ts_seen });
            }
            0x17..=0x18 => nonlinear!(2), // OR XOR — genuine bit-mixing, dimension-destroying
            0x19 => nonlinear!(1),     // NOT
            0x1a => nonlinear!(2),     // BYTE — single-byte extraction destroys magnitude
            // SHL / SHR / SAR — non-linear (truncating), but dimension-PRESERVING when
            // the SHIFT AMOUNT is a constant: shifting by k is scaling by 2^±k, exactly
            // the Q64.96 fixed-point conversion `sqrtPriceX96 >> 96`. Stack order is
            // `shift` (top) then `value`, so the value operand carries the dimension.
            0x1b..=0x1d => {
                let _shift = pop!(); // shift amount (top of stack) — the scaling constant
                let value = pop!();
                let tainted = _shift.t || value.t;
                pushtb!(TB {
                    t: tainted,
                    nl: tainted,
                    provenance: _shift.provenance | value.provenance,
                    dim: value.dim, // value's economic dimension survives the shift
                    ts_seen: _shift.ts_seen || value.ts_seen, // 017: temporal signal survives the shift
                });
            }
            0x20 => {
                // SHA3 — non-linear source.
                popn!(2);
                pushtb!(TB { t: true, nl: true, provenance: 0, dim: TaintDim::Generic, ts_seen: false });
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
                        let dim_tainted = ctx.read_input(off, 32).iter().any(|d| *d != TaintDim::Generic);
                        // 017 Phase 2: prefer origin-anchored bits forwarded from the caller
                        // (populated only at call_depth > 0). When none are inherited we fall
                        // back to the origin-frame mint — at the top frame `input_prov` is empty,
                        // so this is byte-identical to pre-Phase-2 for single-contract executions.
                        let inherited = ctx.read_input_prov(off, 32);
                        let provenance = if inherited != 0 {
                            inherited
                        } else if dim_tainted && off >= 4 {
                            let arg_idx = (off - 4) / 32;
                            if arg_idx < 64 { 1u64 << arg_idx } else { 0 }
                        } else { 0 };
                        // provenance != 0 implies attacker-derived → tainted; preserve that
                        // invariant even if the dim shadow collapsed to Generic-but-tainted.
                        let tainted = dim_tainted || inherited != 0;
                        pushtb!(TB { t: tainted, nl: false, provenance, dim: TaintDim::Generic, ts_seen: false });
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
                    self.mem[off..end].copy_from_slice(vec![TaintDim::Generic; len].as_slice());
                }
            }
            0x3d => clean!(),
            0x3e => {
                // RETURNDATACOPY(destOffset, offset, length) — copy the returndata dim
                // shadow into memory. This is the modern-solc path for external returns
                // (`x = vault.getPricePerFullShare()` lowers to CALL then RETURNDATACOPY);
                // previously this wiped the destination to Generic, dropping the price dim.
                popn!(3);
                let dest = as_u64(interp.stack.peek(0).expect("stack")) as usize;
                let src = as_u64(interp.stack.peek(1).expect("stack")) as usize;
                let len = as_u64(interp.stack.peek(2).expect("stack")) as usize;
                if let Some(end) = safe_mem_end(dest, len) {
                    ensure!(self.mem, end);
                    for i in 0..len {
                        self.mem[dest + i] =
                            self.ret_dims.get(src + i).copied().unwrap_or(TaintDim::Generic);
                    }
                }
            }
             // TIMESTAMP (0x42) / NUMBER (0x43): the warp-controllable clock — a LINEAR
            // taint source for the warp secant (008), exactly like calldata. Without
            // this, temporal gates (reward = f(block.number)) are seen as untainted and
            // never routed to the secant. Other block ctx (COINBASE/GASLIMIT/CHAINID/…)
            // stay clean.
            // 017: ts_seen=true preserves Timestamp provenance through .max() merge.
            0x42 | 0x43 => pushtb!(TB { t: true, nl: false, provenance: 0, dim: TaintDim::Timestamp, ts_seen: true }),
            0x41 | 0x44..=0x48 => clean!(),
            0x50 => {
                pop!();
            }
            0x51 => {
                // MLOAD — memory carries dim; nl and provenance reset (simplification).
                pop!();
                let off = as_u64(interp.stack.peek(0).expect("stack")) as usize;
                let t = self.read_mem_tainted(off, 32);
                let dim = if t {
                    match safe_mem_end(off, 32) {
                        Some(end) => {
                            if self.mem.len() < end { TaintDim::Generic }
                            else { *self.mem[off..end].iter().max().unwrap_or(&TaintDim::Generic) }
                        }
                        None => TaintDim::Generic,
                    }
                } else {
                    TaintDim::Generic
                };
                pushtb!(TB { t, nl: false, provenance: 0, dim, ts_seen: false });
            }
            0x52 => {
                popn!(1);
                let off = as_u64(interp.stack.peek(0).expect("stack")) as usize;
                let v = pop!();
                if let Some(end) = safe_mem_end(off, 32) {
                    ensure!(self.mem, end);
                    let fill = vec![if v.t { v.dim } else { TaintDim::Generic }; 32];
                    self.mem[off..end].copy_from_slice(fill.as_slice());
                    // 017 Phase 2: stamp the value's provenance across the word so it can be
                    // forwarded to a callee's calldata at the next CALL boundary.
                    if self.mem_prov.len() < end { self.mem_prov.resize(end, 0u64); }
                    self.mem_prov[off..end].fill(v.provenance);
                }
            }
            0x53 => {
                popn!(1);
                let off = as_u64(interp.stack.peek(0).expect("stack")) as usize;
                let v = pop!();
                if let Some(end) = safe_mem_end(off, 1) {
                    ensure!(self.mem, end);
                    self.mem[off] = if v.t { v.dim } else { TaintDim::Generic };
                    // 017 Phase 2: single-byte provenance stamp.
                    if self.mem_prov.len() < end { self.mem_prov.resize(end, 0u64); }
                    self.mem_prov[off] = v.provenance;
                }
            }
            0x54 | 0x5c => {
                pop!();
                let key = interp.stack.peek(0).expect("stack");
                let address = interp.input.target_address;
                let (persistent, host_dim, host_ts) = host.tainted_storage.get(&(address, key))
                    .map(|p| (p.tainted, p.dim, p.ts_seen))
                    .unwrap_or((false, TaintDim::Generic, false));
                let local_dim = self.storage.get(&key).copied().unwrap_or(TaintDim::Generic);
                let merged = persistent || local_dim != TaintDim::Generic;
                let dim = host_dim.max(local_dim); // most-specific-wins via TaintDim Ord
                // 017: ts_seen OR-merged from persistent store — survives .max() scalar collapse.
                let ts_seen = host_ts;
                self.storage.insert(key, dim);
                if merged && persistent {
                    INJECTION_CONFIRMED_PROVENANCE = true;
                }
                pushtb!(TB { t: merged, nl: false, provenance: 0, dim, ts_seen });
            }
            0x55 | 0x5d => {
                pop!();
                let v = pop!();
                let key = interp.stack.peek(0).expect("stack");
                let dim = if v.t { v.dim } else { TaintDim::Generic };
                self.storage.insert(key, dim);
                let addr = interp.input.target_address;
                // 017: track ts_seen for TIMESTAMP_DIM_LOCATED publication.
                if v.ts_seen {
                    TIMESTAMP_TAINT_WRITTEN = true;
                }
                if v.t {
                    host.tainted_storage.insert(
                        (addr, key),
                        crate::evm::host::TaintProvenance {
                            tainted: true,
                            stored_value: interp.stack.peek(1).unwrap_or(EVMU256::ZERO),
                            dim: v.dim,
                            ts_seen: v.ts_seen, // 017: persist for cross-execution survival
                        },
                    );
                }
                // Feature 016 Phase 2: accumulator inflation — repeated Price-dim SSTORE to same slot.
                if v.t && v.dim == TaintDim::Price {
                    if let Some(existing) = host.tainted_storage.get(&(addr, key)) {
                        if existing.tainted && existing.dim == TaintDim::Price {
                            ACCUMULATOR_INFLATION_FLOW = true;
                        }
                    }
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
                // MCOPY(destOffset, srcOffset, length) — memory→memory copy (EIP-5656,
                // emitted by modern solc for struct/array copies). Propagate the dim
                // shadow so a price copied between memory regions keeps its dimension;
                // previously this dropped it (same class as the old RETURNDATACOPY bug).
                popn!(3);
                let dest = as_u64(interp.stack.peek(0).expect("stack")) as usize;
                let src = as_u64(interp.stack.peek(1).expect("stack")) as usize;
                let len = as_u64(interp.stack.peek(2).expect("stack")) as usize;
                if let (Some(src_end), Some(dst_end)) = (safe_mem_end(src, len), safe_mem_end(dest, len)) {
                    ensure!(self.mem, src_end.max(dst_end));
                    // Snapshot source first — src/dest regions may overlap (memmove).
                    let snapshot: Vec<TaintDim> = self.mem[src..src_end].to_vec();
                    self.mem[dest..dst_end].copy_from_slice(&snapshot);
                }
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
                // Feature 016 Phase 2: Price-dim comparison followed by value-moving CALL.
                if PRICE_DIM_CMP_SEEN {
                    PRICE_MANIPULATION_FLOW = true;
                    PRICE_DIM_CMP_SEEN = false;
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
                // Feature 016 Phase 2: proxy bridge detection — dim != Generic passing through
                // DELEGATECALL (shared_storage) boundary.
                if stack_len >= 2 && self.stack.iter().any(|tb| tb.dim != TaintDim::Generic) {
                    PROXY_TAINT_FLOW = true;
                }
                // Feature 016 Phase 2: Price-dim comparison → value-moving DELEGATECALL.
                if PRICE_DIM_CMP_SEEN {
                    PRICE_MANIPULATION_FLOW = true;
                    PRICE_DIM_CMP_SEEN = false;
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

        // Feature 014 Phase 0 + Feature 016 Phase 2 (015↔016 bridge): mark oracle /
        // reflexive-valuation return data with an economic dimension in memory.
        //
        // Two gating regimes:
        //   * Chainlink-style oracles are ADDRESS-gated — trusted only when the
        //     callee address is registered in host.oracle_selectors AND the
        //     selector matches (you must know which aggregator you called).
        //   * Reflexive valuation reads (get_virtual_price/pricePerShare/slot0/…)
        //     are ADDRESS-AGNOSTIC — the selector alone is self-identifying, so any
        //     contract returning it is tagged. This is the connective tissue that
        //     lets the dimension engine fire on Feature 015's manipulable targets
        //     without the planner pre-registering every vault/pool address.
        //
        // Feature 016 Phase 4 (return-data seam): tagging self.mem here is useless on
        // its own — self.mem is the CALLEE's memory, which pop_ctx is about to discard.
        // Instead build the tagged dims into the RETURNDATA shadow buffer, then (after
        // pop_ctx restores the caller's memory) splice them into the caller at the CALL's
        // retOffset. This is what actually carries a reflexive price across the call
        // boundary; RETURNDATACOPY (0x3e) also reads self.ret_dims.
        self.ret_dims.clear();
        let (ret_offset, ret_len) = if let Some(ctx) = self.ctxs.last() {
            let address_gated = host
                .oracle_selectors
                .get(&ctx.callee)
                .map(|selectors| selectors.contains(&ctx.callee_selector))
                .unwrap_or(false);
            if address_gated || is_reflexive_valuation_selector(&ctx.callee_selector) {
                let mut dims = vec![TaintDim::Generic; ret.len().min(MEMORY_LIMIT_BYTES)];
                tag_oracle_return(&mut dims, ret, &ctx.callee_selector);
                self.ret_dims = dims;
            }
            (ctx.ret_offset, ctx.ret_len)
        } else {
            (0, 0)
        };

        if let Some(tainted_idx) = self.pop_ctx() {
            if let Some(rec) = TAINTED_CALLS.get_mut(tainted_idx) {
                rec.succeeded = true;
            }
        }

        // Legacy CALL return path: the EVM copies min(retLen, returndata) into the
        // caller's memory at retOffset. Mirror that for the dim shadow now that
        // self.mem is the caller's memory again.
        if !self.ret_dims.is_empty() && ret_len > 0 {
            let n = self.ret_dims.len().min(ret_len);
            if let Some(end) = safe_mem_end(ret_offset, n) {
                if n > 0 {
                    if self.mem.len() < end {
                        self.mem.resize(end, TaintDim::Generic);
                    }
                    self.mem[ret_offset..end].copy_from_slice(&self.ret_dims[..n]);
                }
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

#[cfg(test)]
mod dim_propagation_tests {
    //! Feature 016 regression probe: does the economic dimension tag survive the
    //! arithmetic that actually *computes* a price? Drives the real `on_step`
    //! opcode dispatch (not a reimplementation) over a seeded shadow stack.
    use super::*;
    use crate::evm::vm::EVMState;
    use libafl::schedulers::QueueScheduler;

    // PRICE_DIM_CMP_SEEN / PRICE_MANIPULATION_FLOW are process-global `static mut`s;
    // `cargo test` runs tests in parallel, so any test that resets one and later reads
    // it must serialize against the others that write it. Acquire this first.
    static PRICE_CMP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn price_cmp_guard() -> std::sync::MutexGuard<'static, ()> {
        PRICE_CMP_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn price() -> TB {
        TB { t: true, nl: false, provenance: 0, dim: TaintDim::Price, ts_seen: false }
    }
    fn generic() -> TB {
        TB { t: false, nl: false, provenance: 0, dim: TaintDim::Generic, ts_seen: false }
    }

    // Recompute each oracle selector from its canonical signature and compare to the
    // hardcoded const. Would have caught the original latestAnswer/getRoundData/peek
    // byte errors (3 of 4 were wrong -> those reads were never tagged with a dim).
    #[test]
    fn selector_constants_match_keccak() {
        fn sel(sig: &str) -> [u8; 4] {
            let h = revm_primitives::keccak256(sig.as_bytes());
            [h[0], h[1], h[2], h[3]]
        }
        assert_eq!(LATEST_ROUND_DATA_SEL, sel("latestRoundData()"), "latestRoundData()");
        assert_eq!(LATEST_ANSWER_SEL, sel("latestAnswer()"), "latestAnswer()");
        assert_eq!(GET_ROUND_DATA_SEL, sel("getRoundData(uint80)"), "getRoundData(uint80)");
        assert_eq!(PEEK_SEL, sel("peek()"), "peek()");
        // Feature 016 Phase 2 — the reflexive valuation vocabulary (015↔016 bridge).
        assert_eq!(GET_VIRTUAL_PRICE_SEL, sel("get_virtual_price()"), "get_virtual_price()");
        assert_eq!(PRICE_PER_SHARE_SEL, sel("pricePerShare()"), "pricePerShare()");
        assert_eq!(GET_PRICE_PER_FULL_SHARE_SEL, sel("getPricePerFullShare()"), "getPricePerFullShare()");
        assert_eq!(EXCHANGE_RATE_STORED_SEL, sel("exchangeRateStored()"), "exchangeRateStored()");
        assert_eq!(EXCHANGE_RATE_CURRENT_SEL, sel("exchangeRateCurrent()"), "exchangeRateCurrent()");
        assert_eq!(CONVERT_TO_ASSETS_SEL, sel("convertToAssets(uint256)"), "convertToAssets(uint256)");
        assert_eq!(GET_UNDERLYING_PRICE_SEL, sel("getUnderlyingPrice(address)"), "getUnderlyingPrice(address)");
        assert_eq!(GET_DY_SEL, sel("get_dy(int128,int128,uint256)"), "get_dy(int128,int128,uint256)");
        assert_eq!(SLOT0_SEL, sel("slot0()"), "slot0()");
    }

    // The bridge's gating discipline: reflexive valuation reads are recognized
    // address-agnostically, but Chainlink-style oracles are NOT (they stay
    // address-gated in on_return). A stray selector must match nothing.
    #[test]
    fn reflexive_selectors_recognized_chainlink_not() {
        for s in [
            GET_VIRTUAL_PRICE_SEL,
            PRICE_PER_SHARE_SEL,
            GET_PRICE_PER_FULL_SHARE_SEL,
            EXCHANGE_RATE_STORED_SEL,
            EXCHANGE_RATE_CURRENT_SEL,
            CONVERT_TO_ASSETS_SEL,
            GET_UNDERLYING_PRICE_SEL,
            GET_DY_SEL,
            SLOT0_SEL,
        ] {
            assert!(is_reflexive_valuation_selector(&s), "reflexive selector {:x?} not recognized", s);
        }
        // Chainlink oracles must remain address-gated — never self-identifying.
        assert!(!is_reflexive_valuation_selector(&LATEST_ROUND_DATA_SEL));
        assert!(!is_reflexive_valuation_selector(&LATEST_ANSWER_SEL));
        // A random selector matches nothing.
        assert!(!is_reflexive_valuation_selector(&[0xde, 0xad, 0xbe, 0xef]));
    }

    // Each single-word reflexive valuation read tags its return word0 as Price.
    #[test]
    fn reflexive_return_tagged_price() {
        for s in [
            GET_VIRTUAL_PRICE_SEL,
            PRICE_PER_SHARE_SEL,
            GET_PRICE_PER_FULL_SHARE_SEL,
            EXCHANGE_RATE_STORED_SEL,
            EXCHANGE_RATE_CURRENT_SEL,
            CONVERT_TO_ASSETS_SEL,
            GET_UNDERLYING_PRICE_SEL,
            GET_DY_SEL,
            SLOT0_SEL,
        ] {
            let mut mem: Vec<TaintDim> = Vec::new();
            let ret = Bytes::from(vec![0u8; 32]);
            tag_oracle_return(&mut mem, &ret, &s);
            assert_eq!(mem[0], TaintDim::Price, "selector {:x?} word0 should be Price", s);
        }
    }

    // Uniswap V3 slot0(): word0 = sqrtPriceX96 (Price); the packed remainder
    // (tick, observationIndex, …) is NOT fabricated into a price.
    #[test]
    fn slot0_only_word0_is_price() {
        let mut mem: Vec<TaintDim> = Vec::new();
        let ret = Bytes::from(vec![0u8; 160]); // 5 packed words
        tag_oracle_return(&mut mem, &ret, &SLOT0_SEL);
        assert_eq!(mem[0], TaintDim::Price, "sqrtPriceX96 word0 must be Price");
        // Sparse tagging: only word0 is written, so the vector stops at 32 bytes.
        // The packed remainder (tick, observationIndex, …) is absent → read as
        // Generic by omission, never fabricated into a price.
        assert_eq!(mem.len(), 32, "only word0 should be tagged for slot0");
        assert_eq!(
            mem.get(32).copied().unwrap_or(TaintDim::Generic),
            TaintDim::Generic,
            "tick word1 must read as Generic"
        );
    }

    // END-TO-END BRIDGE PROOF: a reflexive price return flows through memory
    // (MLOAD) into a comparison and is registered as a Price-dim comparison —
    // exactly the signal PRICE_MANIPULATION_FLOW keys on. Pre-bridge, this read
    // was untagged (Generic) and PRICE_DIM_CMP_SEEN never fired for yDAI-class
    // reflexive targets.
    #[test]
    fn reflexive_price_flows_to_price_cmp() {
        let _g = price_cmp_guard();
        unsafe { PRICE_DIM_CMP_SEEN = false; }
        let mut mw = CmpLinearityTaint::new();
        let mut h = host();
        let mut st = EVMFuzzState::default();

        // Return from get_virtual_price(): tag memory word0 = Price.
        let ret = Bytes::from(vec![0u8; 32]);
        tag_oracle_return(&mut mw.mem, &ret, &GET_VIRTUAL_PRICE_SEL);
        assert_eq!(mw.mem[0], TaintDim::Price);

        // MLOAD offset 0 → shadow TB carries Price out of memory.
        let mut m = interp_with(0x51, 0);
        let _ = m.stack.push(EVMU256::ZERO); // offset operand on real stack
        mw.stack.push(generic()); // shadow operand MLOAD consumes
        unsafe { mw.on_step(&mut m, &mut h, &mut st); }
        assert_eq!(mw.stack.last().unwrap().dim, TaintDim::Price, "MLOAD of tagged price keeps Price");

        // LT against a scalar → the engine records a Price-dim comparison.
        mw.stack.push(generic()); // second comparison operand
        let mut c = interp_with(0x10, 2);
        unsafe { mw.on_step(&mut c, &mut h, &mut st); }
        assert!(unsafe { PRICE_DIM_CMP_SEEN }, "reflexive price must register as a Price-dim comparison");
    }

    // Finding ③ — SHR/SHL/SAR by a constant is dimension-preserving scaling
    // (Q64.96: sqrtPriceX96 >> 96). Stack top is the shift amount, so seed
    // [value, shift]; the value operand's dim must survive.
    #[test]
    fn shr_by_constant_preserves_price_dim() {
        assert_eq!(step_dim(0x1c, &[price(), generic()]), TaintDim::Price); // SHR
        assert_eq!(step_dim(0x1b, &[price(), generic()]), TaintDim::Price); // SHL
        assert_eq!(step_dim(0x1d, &[price(), generic()]), TaintDim::Price); // SAR
    }

    // Finding ③ — AND with a constant bitmask preserves the value's dimension
    // (packed slot0 unpack: value & 0xff…). Two generics stay Generic; BYTE/OR/XOR
    // remain dimension-destroying and are covered by staying `nonlinear!`.
    #[test]
    fn and_mask_preserves_price_two_generics_generic() {
        assert_eq!(step_dim(0x16, &[price(), generic()]), TaintDim::Price);
        assert_eq!(step_dim(0x16, &[generic(), price()]), TaintDim::Price);
        assert_eq!(step_dim(0x16, &[generic(), generic()]), TaintDim::Generic);
    }

    // Guard: OR/XOR/BYTE must NOT preserve dimension — they genuinely destroy
    // magnitude and would create false Price signals if carved out.
    #[test]
    fn or_xor_byte_still_destroy_dim() {
        assert_eq!(step_dim(0x17, &[price(), generic()]), TaintDim::Generic); // OR
        assert_eq!(step_dim(0x18, &[price(), generic()]), TaintDim::Generic); // XOR
        assert_eq!(step_dim(0x1a, &[price(), generic()]), TaintDim::Generic); // BYTE
    }

    // FULL ②+③ CHAIN: Uniswap V3 slot0() → sqrtPriceX96 unpacked via SHR by a
    // constant → still Price → comparison fires PRICE_DIM_CMP_SEEN. This is the
    // realistic V3 price-read path; pre-bridge it was Generic end-to-end.
    #[test]
    fn slot0_sqrtprice_unpacked_flows_to_price_cmp() {
        let _g = price_cmp_guard();
        unsafe { PRICE_DIM_CMP_SEEN = false; }
        let mut mw = CmpLinearityTaint::new();
        let mut h = host();
        let mut st = EVMFuzzState::default();

        // Return from slot0(): word0 = sqrtPriceX96 → Price (finding ②).
        let ret = Bytes::from(vec![0u8; 32]);
        tag_oracle_return(&mut mw.mem, &ret, &SLOT0_SEL);
        assert_eq!(mw.mem[0], TaintDim::Price);

        // MLOAD offset 0 → Price onto the shadow stack.
        let mut m = interp_with(0x51, 0);
        let _ = m.stack.push(EVMU256::ZERO);
        mw.stack.push(generic());
        unsafe { mw.on_step(&mut m, &mut h, &mut st); }
        assert_eq!(mw.stack.last().unwrap().dim, TaintDim::Price);

        // SHR by 96 (Q64.96 → integer price). Stack: [value:Price, shift:const].
        mw.stack.push(generic()); // shift amount (top)
        let mut s = interp_with(0x1c, 2);
        unsafe { mw.on_step(&mut s, &mut h, &mut st); }
        assert_eq!(mw.stack.last().unwrap().dim, TaintDim::Price, "SHR by const must keep Price (finding ③)");

        // Comparison → Price-dim signal.
        mw.stack.push(generic());
        let mut c = interp_with(0x10, 2);
        unsafe { mw.on_step(&mut c, &mut h, &mut st); }
        assert!(unsafe { PRICE_DIM_CMP_SEEN }, "unpacked V3 price must register as a Price-dim comparison");
    }

    // ISZERO gate gap: a Price flowing directly into ISZERO (require(price != 0),
    // `if (price)`, negated comparisons) must count as a price comparison — LT/GT/EQ
    // already did, ISZERO previously did not.
    #[test]
    fn iszero_on_price_counts_as_price_cmp() {
        let _g = price_cmp_guard();
        unsafe { PRICE_DIM_CMP_SEEN = false; }
        let mut mw = CmpLinearityTaint::new();
        mw.stack = vec![price()];
        let mut i = interp_with(0x15, 1);
        let mut h = host();
        let mut st = EVMFuzzState::default();
        unsafe { mw.on_step(&mut i, &mut h, &mut st); }
        assert!(unsafe { PRICE_DIM_CMP_SEEN }, "ISZERO on a Price must register a price comparison");
        assert_eq!(mw.stack.last().unwrap().dim, TaintDim::Price, "ISZERO passes dim through");
    }

    // The gate is on the DIMENSION, not merely taint: a tainted non-Price (Balance)
    // through ISZERO must NOT masquerade as a price comparison.
    #[test]
    fn iszero_on_non_price_is_not_a_price_cmp() {
        let _g = price_cmp_guard();
        unsafe { PRICE_DIM_CMP_SEEN = false; }
        let mut mw = CmpLinearityTaint::new();
        mw.stack = vec![balance()]; // tainted, but Balance not Price
        let mut i = interp_with(0x15, 1);
        let mut h = host();
        let mut st = EVMFuzzState::default();
        unsafe { mw.on_step(&mut i, &mut h, &mut st); }
        assert!(!unsafe { PRICE_DIM_CMP_SEEN }, "ISZERO on a non-Price must NOT flag a price comparison");
    }

    // SIGNEXTEND widens a signed int (int128→int256, int24 tick) without changing its
    // economic meaning — the value operand's dimension survives; the byte-count
    // operand (stack top) is the constant.
    #[test]
    fn signextend_preserves_value_dim() {
        assert_eq!(step_dim(0x0b, &[price(), generic()]), TaintDim::Price);
        assert_eq!(step_dim(0x0b, &[generic(), generic()]), TaintDim::Generic);
    }

    // Construct a Ctx as push_ctx would leave it right after a CALL: caller memory
    // saved, callee selector + retOffset/retLen recorded.
    fn call_ctx(selector: [u8; 4], ret_offset: usize, ret_len: usize, caller_mem_len: usize) -> Ctx {
        Ctx {
            mem: vec![TaintDim::Generic; caller_mem_len],
            mem_prov: Vec::new(),
            storage: std::collections::HashMap::new(),
            stack: Vec::new(),
            input_data: Vec::new(),
            input_prov: Vec::new(),
            shared_storage: false,
            tainted_record_idx: None,
            callee: EVMAddress::repeat_byte(0x22),
            callee_selector: selector,
            ret_offset,
            ret_len,
        }
    }

    // THE RETURN-DATA SEAM (finding ⑥). Pre-fix, tag_oracle_return tagged the callee's
    // memory which pop_ctx immediately discarded, so a reflexive price never reached the
    // caller. This drives the real on_return path: after the CALL boundary, the Price
    // dim must land in the CALLER's memory at retOffset (legacy path) AND populate the
    // returndata shadow buffer (RETURNDATACOPY path).
    #[test]
    fn reflexive_return_survives_call_boundary() {
        let mut mw = CmpLinearityTaint::new();
        let mut h = host();
        let mut st = EVMFuzzState::default();

        // State just after `CALL vault.getPricePerFullShare()`, retOffset 0x80 / 32B.
        mw.ctxs.push(call_ctx(GET_PRICE_PER_FULL_SHARE_SEL, 0x80, 0x20, 0xa0));
        mw.mem = vec![TaintDim::Generic; 32]; // callee frame — pop_ctx discards it

        let ret = Bytes::from(vec![0u8; 32]);
        let mut interp = interp_with(0x00, 0);
        unsafe { mw.on_return(&mut interp, &mut h, &mut st, &ret); }

        // Caller memory at retOffset must now be Price (legacy CALL retOffset copy).
        assert_eq!(
            mw.mem.get(0x80).copied(),
            Some(TaintDim::Price),
            "reflexive price must land in caller memory at retOffset across the call boundary"
        );
        // And the returndata shadow must hold Price for the RETURNDATACOPY path.
        assert_eq!(mw.ret_dims.first().copied(), Some(TaintDim::Price));
    }

    // A non-reflexive, non-oracle return must NOT leak a dim across the boundary, and
    // must clear any stale returndata shadow.
    #[test]
    fn plain_return_does_not_leak_dim() {
        let mut mw = CmpLinearityTaint::new();
        let mut h = host();
        let mut st = EVMFuzzState::default();
        mw.ret_dims = vec![TaintDim::Price; 32]; // stale from a previous call
        mw.ctxs.push(call_ctx([0xde, 0xad, 0xbe, 0xef], 0x80, 0x20, 0xa0));

        let ret = Bytes::from(vec![0u8; 32]);
        let mut interp = interp_with(0x00, 0);
        unsafe { mw.on_return(&mut interp, &mut h, &mut st, &ret); }

        assert!(mw.ret_dims.is_empty(), "returndata shadow must be cleared for a plain return");
        assert_eq!(mw.mem.get(0x80).copied(), Some(TaintDim::Generic), "no dim may leak to caller");
    }

    // ── 017 Phase 2 — Cross-CALL provenance routing ──────────────────────────
    //
    // An attacker arg authored at the top level must keep its ORIGIN bit as it
    // rides through memory (MSTORE) and across a CALL boundary into the callee's
    // calldata, rather than the callee re-minting a fresh local bit from its own
    // argument layout. Pre-Phase-2 the callee's CALLDATALOAD invented `1<<arg_idx`
    // in its own coordinate system, so a single execution was N disconnected
    // provenance islands.
    #[test]
    fn provenance_crosses_call_boundary() {
        let mut mw = CmpLinearityTaint::new();
        let mut h = host();
        let mut st = EVMFuzzState::default();

        // Caller MSTOREs an attacker-authored value (top-level arg bit 3) at memory
        // offset 4 — where the callee's arg0 lands (calldata offset 4, after the
        // 4-byte selector). Shadow stack seeds only the value TB; on_step's
        // length-resync appends the offset slot to match the real 2-deep stack.
        let attacker = TB { t: true, nl: false, provenance: 1u64 << 3, dim: TaintDim::Generic, ts_seen: false };
        mw.mem = vec![TaintDim::Generic; 0x40];
        mw.stack = vec![attacker];
        let mut mstore = interp_with(0x52, 0);
        let _ = mstore.stack.push(EVMU256::from(0xdeadu64)); // value operand (peek1)
        let _ = mstore.stack.push(EVMU256::from(4u64));      // dest offset (peek0)
        unsafe { mw.on_step(&mut mstore, &mut h, &mut st); }
        assert_eq!(
            mw.mem_prov.get(4).copied(),
            Some(1u64 << 3),
            "MSTORE must stamp the value's provenance into the memory shadow"
        );

        // Forward that memory window into a callee frame exactly as push_ctx does
        // (input_prov = write_input_prov over the argOffset..argLen window), then
        // enter the callee: its memory shadow starts fresh.
        let mut ctx = call_ctx([0xaa, 0xbb, 0xcc, 0xdd], 0, 0, 0);
        ctx.input_prov = mw.write_input_prov(0, 0x40);
        mw.ctxs.push(ctx);
        mw.mem.clear();
        mw.mem_prov.clear();

        // Callee CALLDATALOAD(arg0 @ offset 4) must inherit the ORIGIN bit 3, NOT a
        // locally re-minted arg-0 bit (1<<0).
        let mut cdl = interp_with(0x35, 0);
        let _ = cdl.stack.push(EVMU256::from(4u64));
        unsafe { mw.on_step(&mut cdl, &mut h, &mut st); }
        let out = *mw.stack.last().expect("CALLDATALOAD result");
        assert_eq!(out.provenance, 1u64 << 3, "callee must inherit the origin arg-3 bit across the CALL boundary");
        assert!(out.t, "inherited provenance implies tainted");
    }

    // The origin anchor: at the top frame (input_prov empty) CALLDATALOAD still
    // mints `1<<arg_idx` from the local calldata layout. This is the byte-identical
    // depth-0 path that keeps every single-contract exploit and Phase-1 test intact.
    #[test]
    fn depth_zero_still_mints() {
        let mut mw = CmpLinearityTaint::new();
        let mut h = host();
        let mut st = EVMFuzzState::default();

        // Origin frame: calldata dim-tainted at arg index 2 (offset 4 + 2*32 = 0x44),
        // but NO inherited provenance (input_prov left empty).
        let mut ctx = call_ctx([0xaa, 0xbb, 0xcc, 0xdd], 0, 0, 0);
        ctx.input_data = vec![TaintDim::Generic; 0x44 + 32];
        for b in 0x44..0x44 + 32 {
            ctx.input_data[b] = TaintDim::Balance; // any non-Generic dim → dim_tainted
        }
        mw.ctxs.push(ctx);

        let mut cdl = interp_with(0x35, 0);
        let _ = cdl.stack.push(EVMU256::from(0x44u64));
        unsafe { mw.on_step(&mut cdl, &mut h, &mut st); }
        let out = *mw.stack.last().expect("CALLDATALOAD result");
        assert_eq!(out.provenance, 1u64 << 2, "depth-0 must mint the origin arg-2 bit");
        assert!(out.t, "dim-tainted origin calldata is tainted");
    }

    // Fail-closed: forwarding untainted bytes (input_prov all zero, input_data all
    // Generic) must NOT fabricate a provenance bit. The inherit branch only fires
    // when a real origin bit was carried; clean plumbing stays clean.
    #[test]
    fn clean_calldata_no_inherit() {
        let mut mw = CmpLinearityTaint::new();
        let mut h = host();
        let mut st = EVMFuzzState::default();

        let mut ctx = call_ctx([0xaa, 0xbb, 0xcc, 0xdd], 0, 0, 0);
        ctx.input_data = vec![TaintDim::Generic; 0x40];
        ctx.input_prov = vec![0u64; 0x40];
        mw.ctxs.push(ctx);

        let mut cdl = interp_with(0x35, 0);
        let _ = cdl.stack.push(EVMU256::from(4u64));
        unsafe { mw.on_step(&mut cdl, &mut h, &mut st); }
        let out = *mw.stack.last().expect("CALLDATALOAD result");
        assert_eq!(out.provenance, 0, "clean forwarded calldata must not fabricate a provenance bit");
        assert!(!out.t, "clean forwarded calldata must not be tainted");
    }

    // MCOPY (EIP-5656) must carry the dim shadow memory→memory (struct/array copies),
    // like RETURNDATACOPY. Stack (top→bottom): destOffset, srcOffset, length.
    #[test]
    fn mcopy_carries_dim() {
        let mut mw = CmpLinearityTaint::new();
        let mut h = host();
        let mut st = EVMFuzzState::default();
        mw.mem = vec![TaintDim::Generic; 0x80];
        for i in 0x20..0x40 {
            mw.mem[i] = TaintDim::Price; // a Price word sitting at src
        }
        let mut interp = interp_with(0x5e, 0);
        let _ = interp.stack.push(EVMU256::from(0x20u64)); // length (bottom)
        let _ = interp.stack.push(EVMU256::from(0x20u64)); // srcOffset
        let _ = interp.stack.push(EVMU256::from(0x40u64)); // destOffset (top)
        mw.stack = vec![generic(), generic(), generic()];
        unsafe { mw.on_step(&mut interp, &mut h, &mut st); }
        assert_eq!(mw.mem[0x40], TaintDim::Price, "MCOPY must carry the dim to dest");
        assert_eq!(mw.mem[0x20], TaintDim::Price, "source region unchanged");
    }

    // The RETURNDATACOPY path (modern solc): copy the returndata dim shadow into memory
    // at destOffset. Stack (top→bottom) is destOffset, offset, length.
    #[test]
    fn returndatacopy_carries_price_dim() {
        let mut mw = CmpLinearityTaint::new();
        let mut h = host();
        let mut st = EVMFuzzState::default();
        mw.ret_dims = vec![TaintDim::Price; 32]; // as if just returned from a reflexive read

        let mut interp = interp_with(0x3e, 0);
        let _ = interp.stack.push(EVMU256::from(32u64)); // length (bottom)
        let _ = interp.stack.push(EVMU256::ZERO); // offset into returndata
        let _ = interp.stack.push(EVMU256::from(0x40u64)); // destOffset (top)
        mw.stack = vec![generic(), generic(), generic()];
        unsafe { mw.on_step(&mut interp, &mut h, &mut st); }

        assert_eq!(
            mw.mem.get(0x40).copied(),
            Some(TaintDim::Price),
            "RETURNDATACOPY must carry the returndata dim into memory"
        );
        // Beyond the copied 32 bytes stays Generic.
        assert_eq!(mw.mem.get(0x60).copied().unwrap_or(TaintDim::Generic), TaintDim::Generic);
    }

    fn host() -> FuzzHost<QueueScheduler<EVMFuzzState>> {
        let mut h = FuzzHost::new(QueueScheduler::new(), "work_dir".to_string());
        h.evmstate = EVMState::new();
        h
    }

    // Minimal interpreter positioned at a single opcode `op`, with `n` dummy
    // values on the REAL stack so on_step's length-resync (cmp_linearity.rs:530)
    // does not truncate the seeded shadow stack.
    fn interp_with(op: u8, n: usize) -> Interpreter {
        let addr = EVMAddress::repeat_byte(0x11);
        let bc = revm_interpreter::bytecode::Bytecode::new_raw(revm_primitives::Bytes::from(vec![op]));
        let input = revm_interpreter::interpreter::InputsImpl {
            target_address: addr,
            bytecode_address: Some(addr),
            caller_address: addr,
            input: revm_interpreter::CallInput::Bytes(revm_primitives::Bytes::new()),
            call_value: EVMU256::ZERO,
        };
        let mut interp = Interpreter::new(
            revm_interpreter::interpreter::SharedMemory::new(),
            revm_interpreter::interpreter::ExtBytecode::new(bc),
            input,
            false,
            revm_primitives::hardfork::SpecId::PRAGUE,
            10_000_000_000,
        );
        for i in 0..n {
            let _ = interp.stack.push(EVMU256::from(i as u64 + 1));
        }
        interp
    }

    // Apply one opcode over a shadow stack seeded with `inputs`, return the dim of
    // the resulting top-of-stack.
    fn step_dim(op: u8, inputs: &[TB]) -> TaintDim {
        let mut mw = CmpLinearityTaint::new();
        mw.stack = inputs.to_vec();
        let mut interp = interp_with(op, inputs.len());
        let mut h = host();
        let mut st = EVMFuzzState::default();
        unsafe { mw.on_step(&mut interp, &mut h, &mut st); }
        mw.stack.last().expect("shadow result").dim
    }

    fn balance() -> TB {
        TB { t: true, nl: false, provenance: 0, dim: TaintDim::Balance, ts_seen: false }
    }

    #[test]
    fn mul_preserves_price_dim() {
        // price * 1e18  (MUL 0x02, linear: one operand tainted) → dim survives.
        assert_eq!(step_dim(0x02, &[price(), generic()]), TaintDim::Price);
    }

    #[test]
    fn div_price_over_scalar_preserves_price() {
        // THE FIX: a Price value (oracle answer / stored price) normalized by a
        // constant keeps Price. Numerator is top-of-stack, so seed [scalar, price].
        // Pre-fix this returned Generic (DIV was `nonlinear!`); post-fix → Price.
        assert_eq!(step_dim(0x04, &[generic(), price()]), TaintDim::Price);
    }

    #[test]
    fn div_same_dimension_is_dimensionless() {
        // price / price is a genuine dimensionless ratio — Generic is correct, and
        // we must NOT invent a Price here.
        assert_eq!(step_dim(0x04, &[price(), price()]), TaintDim::Generic);
    }

    #[test]
    fn div_balance_over_balance_stays_generic() {
        // Honest boundary: an AMM spot price is reserveA/reserveB = balance/balance.
        // The "price" meaning is emergent, not present in the operands — so the fix
        // does NOT fabricate Price from two balances. Price must be seeded upstream
        // (tag_oracle_return / SLOAD of a stored price), not synthesized by DIV.
        assert_eq!(step_dim(0x04, &[balance(), balance()]), TaintDim::Generic);
    }

    #[test]
    fn oracle_price_decimal_normalization_survives() {
        // Realistic end-to-end: an oracle answer (Price) decimal-normalized as
        // (answer * 1e8) / 1e18, driven opcode-by-opcode through the real engine.
        // Pre-fix the trailing DIV wiped Price → Generic (secant probes /64); the
        // carve-out keeps Price → secant probes /256 as intended.
        let mut mw = CmpLinearityTaint::new();
        let mut h = host();
        let mut st = EVMFuzzState::default();

        // MUL: [answer:Price, 1e8:Generic] → product:Price
        mw.stack = vec![price(), generic()];
        let mut m = interp_with(0x02, 2);
        unsafe { mw.on_step(&mut m, &mut h, &mut st); }
        assert_eq!(mw.stack.last().unwrap().dim, TaintDim::Price, "MUL should keep Price");

        // DIV: product(Price) / 1e18(Generic). Numerator (product) is on top; push
        // the Generic divisor last so the real stack has 2 operands.
        mw.stack.push(generic());
        let mut d = interp_with(0x04, 2);
        unsafe { mw.on_step(&mut d, &mut h, &mut st); }

        assert_eq!(
            mw.stack.last().unwrap().dim,
            TaintDim::Price,
            "normalized oracle price must reach the secant as Price (/256), not Generic (/64)"
        );
    }

    fn timestamp() -> TB {
        TB { t: true, nl: false, provenance: 0, dim: TaintDim::Timestamp, ts_seen: true }
    }

    fn step_ts_seen(op: u8, inputs: &[TB]) -> bool {
        let mut mw = CmpLinearityTaint::new();
        mw.stack = inputs.to_vec();
        let mut interp = interp_with(op, inputs.len());
        let mut h = host();
        let mut st = EVMFuzzState::default();
        unsafe { mw.on_step(&mut interp, &mut h, &mut st); }
        mw.stack.last().expect("shadow result").ts_seen
    }

    #[test]
    fn ts_seen_linear_or_merge() {
        assert_eq!(step_dim(0x01, &[timestamp(), price()]), TaintDim::Price);
        assert!(step_ts_seen(0x01, &[timestamp(), price()]), "ts_seen must survive linear merge with Price");
    }

    #[test]
    fn ts_seen_linear_or_merge_both_ts_seen() {
        assert!(step_ts_seen(0x01, &[timestamp(), timestamp()]), "both-ts_seen must stay true");
    }

    #[test]
    fn ts_seen_nonlinear_reset() {
        assert!(!step_ts_seen(0x19, &[timestamp(), generic()]), "nonlinear op must reset ts_seen");
    }

    #[test]
    fn ts_seen_mul_preserves() {
        assert!(step_ts_seen(0x02, &[timestamp(), generic()]), "MUL preserves ts_seen when timestamp present");
        assert!(step_ts_seen(0x02, &[generic(), timestamp()]), "MUL preserves ts_seen on either side");
    }

    #[test]
    fn ts_seen_sub_linear_merge() {
        assert!(step_ts_seen(0x03, &[timestamp(), generic()]), "SUB preserves ts_seen");
    }

    #[test]
    fn ts_seen_div_preserves_when_numerator() {
        let ts_dim = step_dim(0x04, &[generic(), timestamp()]);
        let ts_flag = step_ts_seen(0x04, &[generic(), timestamp()]);
        assert_eq!(ts_dim, TaintDim::Timestamp, "Timestamp/scalar DIV keeps Timestamp");
        assert!(ts_flag, "DIV preserves ts_seen from numerator");
    }

    #[test]
    fn accumulator_probe_delta_formula() {
        let base = 1000u64;
        let price_delta = |x1: u64| (x1 / 256).max(base / 1000);
        let generic_delta = |x1: u64| (x1 / 64).max(base / 1000);
        assert_eq!(price_delta(25600), 100, "/256 of 25600");
        assert_eq!(generic_delta(25600), 400, "/64 of 25600");
        assert!(price_delta(25600) < generic_delta(25600), "Accumulator probe must be coarser than Generic");
        assert_eq!(price_delta(0), 1, "floor = 1");
    }
}

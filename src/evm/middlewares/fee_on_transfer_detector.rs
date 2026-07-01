use std::any::Any;
use std::clone::Clone;
use std::fmt::Debug;

use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::{interpreter_types::Jumps, Interpreter};

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    slot_detector::{compute_mapping_storage_slot, get_cached_balance_slot},
    types::{as_u64, convert_u256_to_h160, EVMAddress, EVMFuzzState, EVMU256},
    vm::is_reverted_or_control_leak,
};

/// transfer(address,uint256)
const SEL_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
/// transferFrom(address,address,uint256)
const SEL_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];

/// One pending CALL frame. We push exactly one entry per CALL-family opcode and
/// pop exactly one per `on_return`, mirroring `value_capture.rs` so the local
/// stack stays in lockstep with revm's strictly-nested call/return invocations.
#[derive(Clone, Debug)]
enum Pending {
    /// A `transfer`/`transferFrom` CALL whose recipient balance slot we could read.
    Transfer {
        /// Call depth at the CALL opcode; must equal `host.call_depth` at the
        /// matching `on_return` (guards against the rare depth>1024 desync).
        depth: u64,
        token: EVMAddress,
        recipient: EVMAddress,
        balance_slot: u64,
        claimed: EVMU256,
        /// Recipient balance read at the CALL opcode (pre-transfer).
        pre: EVMU256,
    },
    /// Any other CALL — tracked only to keep the stack balanced.
    Other,
}

/// Inline fee-on-transfer detector.
///
/// Brackets a single ERC-20 `transfer`/`transferFrom` CALL: at the CALL opcode it
/// snapshots the recipient's balance slot, and when that frame returns it re-reads
/// the slot and records `(token, recipient, claimed, actual)` into
/// `EVMState::fee_observations`. The `FeeOnTransferOracle` reads those observations.
///
/// This replaces the old post-hoc whole-transaction balance diff, which could not
/// tell a transit/pass-through recipient (received then forwarded in a *later* call)
/// from a 100%-fee token. A per-frame measurement is structurally immune to that:
/// forwarding is a separate call and cannot be folded into one transfer's delta.
#[derive(Clone, Debug, Default)]
pub struct FeeOnTransferDetector {
    stack: Vec<Pending>,
}

impl FeeOnTransferDetector {
    pub fn new() -> Self {
        Self { stack: Vec::new() }
    }
}

/// Read a recipient's token balance directly from EVM state storage.
/// Returns `None` when the slot is not loaded — unmeasurable is NOT a zero balance,
/// and inventing a zero here is exactly what produced the old phantom "100% fee".
fn read_balance<SC>(
    host: &FuzzHost<SC>,
    token: &EVMAddress,
    recipient: &EVMAddress,
    balance_slot: u64,
) -> Option<EVMU256>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    let slot = compute_mapping_storage_slot(*recipient, EVMU256::from(balance_slot));
    host.evmstate
        .state
        .get(token)
        .and_then(|acct| acct.get(&slot))
        .copied()
}

impl<SC> Middleware<SC> for FeeOnTransferDetector
where
    SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {
        let opcode = interp.bytecode.opcode();
        // Keep the stack balanced for every CALL-family opcode (same set as
        // value_capture). Only plain CALL (0xf1) can mutate token balances, so only
        // it is a fee candidate; the rest are pushed as `Other`.
        if !matches!(opcode, 0xf1 | 0xf2 | 0xf4 | 0xfa) {
            return;
        }

        // Only CALL (0xf1) carries [gas, addr, value, args_offset, args_len, ...].
        // For the other call types we can't have a value-bearing token transfer.
        if opcode != 0xf1 {
            self.stack.push(Pending::Other);
            return;
        }

        let stack_len = interp.stack.len();
        if stack_len < 5 {
            // Malformed CALL: revm will revert the frame at the opcode without
            // invoking host.call, so no on_return fires — do NOT push (stay balanced).
            return;
        }

        let target = convert_u256_to_h160(interp.stack.peek(1).unwrap());
        let value = interp.stack.peek(2).unwrap();
        let arg_offset = as_u64(interp.stack.peek(3).unwrap()) as usize;
        let arg_len = as_u64(interp.stack.peek(4).unwrap()) as usize;

        // ERC-20 transfers carry no ETH value. A non-zero value also means this CALL
        // could take the underfunded early-return path that skips on_return — which we
        // must never push, or the stack desyncs. So require value == 0.
        if value != EVMU256::ZERO {
            self.stack.push(Pending::Other);
            return;
        }

        // Read calldata from interpreter memory (bounds-checked, like value_capture).
        let mut selector = [0u8; 4];
        if arg_len >= 4 && interp.memory.len() >= arg_offset + 4 {
            selector.copy_from_slice(&interp.memory.slice_len(arg_offset, 4));
        }

        let (recipient, claimed) = match selector {
            SEL_TRANSFER if arg_len >= 68 && interp.memory.len() >= arg_offset + 68 => {
                // transfer(to, amount): to @ [4..36], amount @ [36..68]
                let to = EVMAddress::from_slice(&interp.memory.slice_len(arg_offset + 16, 20));
                let amt = EVMU256::from_be_slice(&interp.memory.slice_len(arg_offset + 36, 32));
                (to, amt)
            }
            SEL_TRANSFER_FROM if arg_len >= 100 && interp.memory.len() >= arg_offset + 100 => {
                // transferFrom(from, to, amount): to @ [36..68], amount @ [68..100]
                let to = EVMAddress::from_slice(&interp.memory.slice_len(arg_offset + 48, 20));
                let amt = EVMU256::from_be_slice(&interp.memory.slice_len(arg_offset + 68, 32));
                (to, amt)
            }
            _ => {
                self.stack.push(Pending::Other);
                return;
            }
        };

        // Skip dust / zero-value transfers — no fee to measure.
        if claimed == EVMU256::ZERO {
            self.stack.push(Pending::Other);
            return;
        }

        // Resolve the token's balance mapping slot. Unknown slot → unmeasurable → skip.
        let Some(balance_slot) = get_cached_balance_slot(&target) else {
            self.stack.push(Pending::Other);
            return;
        };

        // Snapshot the recipient's pre-transfer balance. Absent slot → unmeasurable → skip.
        let Some(pre) = read_balance(host, &target, &recipient, balance_slot) else {
            self.stack.push(Pending::Other);
            return;
        };

        self.stack.push(Pending::Transfer {
            depth: host.call_depth,
            token: target,
            recipient,
            balance_slot,
            claimed,
            pre,
        });
    }

    unsafe fn on_return(
        &mut self,
        _interp: &mut Interpreter,
        host: &mut FuzzHost<SC>,
        _state: &mut EVMFuzzState,
        _ret: &Bytes,
    ) {
        let Some(pending) = self.stack.pop() else {
            return;
        };
        let Pending::Transfer {
            depth,
            token,
            recipient,
            balance_slot,
            claimed,
            pre,
        } = pending
        else {
            return;
        };

        // Depth guard: at the matching on_return, call_depth is back to the value it
        // had at the CALL opcode. A mismatch means a rare desync (depth>1024) — skip
        // recording rather than risk comparing the wrong frame's balances.
        if depth != host.call_depth {
            return;
        }

        // Only a successful transfer moves tokens; a revert leaves the balance unchanged
        // and would otherwise look like a 100% fee.
        let call_success = host
            .last_call_result
            .map(|r| !is_reverted_or_control_leak(&r))
            .unwrap_or(false);
        if !call_success {
            return;
        }

        // Re-read the recipient's balance post-transfer. Absent now → unmeasurable → skip.
        let Some(post) = read_balance(host, &token, &recipient, balance_slot) else {
            return;
        };

        let actual = post.saturating_sub(pre);
        host.evmstate
            .fee_observations
            .push((token, recipient, claimed, actual));
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::FeeOnTransferDetector
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

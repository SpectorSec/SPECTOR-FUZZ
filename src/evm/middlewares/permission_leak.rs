use std::{
    any,
    collections::HashSet,
};

use libafl::schedulers::Scheduler;
use revm_interpreter::{interpreter_types::Jumps, Interpreter};
use serde::{Deserialize, Serialize};

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::{EVMAddress, EVMFuzzState, EVMU256},
};

/// Feature 019 Phase A — Causal Identity Engine, Permission-Leak half.
///
/// The post-hoc `FunctionOracle` (o_func) fires on `{privileged selector} ∧
/// {unauthorized caller} ∧ {¬reverted}` with **no materiality check**. That makes
/// `DAI.burn(0x0, 0)` — a call that succeeds trivially and mutates nothing — look
/// identical to a real unauthorized mint. The result is the live `burn(0)` false
/// positive on the yDAI run.
///
/// The missing signal is *materiality*, and it exists **only during execution**: at
/// an `SSTORE` opcode the pre-image (`host.evmstate.state[addr][slot]`) is still the
/// old value, so `pre ≠ new` reveals whether the store actually changed state. That
/// delta is destroyed by the transaction boundary — post-hoc you cannot tell a
/// no-op store from one that wrote back the same value. This is the Information-
/// Availability-Law justification for an inline `on_step` middleware (same shape as
/// `ReentrancyTracer` for interleaving and `FeeOnTransferDetector` for per-frame
/// deltas): `on_step` runs *before* the opcode, so the pre-image is readable.
///
/// It records, per execution, the contracts that had a **material sink** — an
/// `SSTORE` with `pre ≠ new`, or a `CALL` carrying non-zero ETH value. The
/// `FunctionOracle` then gates on that: a privileged call by an unauthorized caller
/// is a leak only if the privileged contract had a material sink this tx. Adding the
/// gate can only *suppress* fires (no-op calls); a genuine unauthorized mint always
/// changes state, so there is no false-negative risk.
#[derive(Serialize, Debug, Clone, Default)]
pub struct PermissionLeakTracer;

impl PermissionLeakTracer {
    pub fn new() -> Self {
        Self
    }
}

/// Per-execution materiality evidence, carried on `EVMState` next to
/// `reentrancy_metadata`. `#[serde(skip)]` on the carrier gives it the same
/// per-execution reset (state is restored from the input at the top of `execute`,
/// vm.rs:1453) that `reentrancy_metadata`/`fee_observations` rely on.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PermissionLeakData {
    /// (contract, slot) pairs whose `SSTORE` wrote a value differing from the
    /// pre-image this execution — a material storage mutation.
    pub material_writes: HashSet<(EVMAddress, EVMU256)>,
    /// Contracts that executed a `CALL` carrying non-zero ETH value — a material
    /// value move (e.g. an unauthorized `withdraw` that forwards ETH without an
    /// on-contract `SSTORE`).
    pub value_moves: HashSet<EVMAddress>,
    /// Subset of `material_writes` the accumulated taint bus attributes to attacker
    /// calldata (`arg_slot_provenance != 0` or `tainted_storage.tainted`).
    ///
    /// This is **best-effort causal confirmation**, NOT a gate input: the taint bus
    /// is populated by `cmp_linearity` on a *separate* reexecution pass
    /// (feedbacks.rs:138), so for an input that pass has not yet visited the bits are
    /// simply absent. Requiring taint here would false-negative those inputs. The
    /// materiality *delta* (`pre ≠ new`) is the gate; taint enriches the evidence.
    pub tainted_material: HashSet<(EVMAddress, EVMU256)>,
}

impl PermissionLeakData {
    /// True iff `contract` had any material sink (storage delta or value move) this
    /// execution. The `FunctionOracle` materiality gate reads exactly this.
    pub fn contract_material(&self, contract: &EVMAddress) -> bool {
        self.value_moves.contains(contract) || self.material_writes.iter().any(|(c, _)| c == contract)
    }
}

impl<SC> Middleware<SC> for PermissionLeakTracer
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {
        match interp.bytecode.opcode() {
            // SSTORE — materiality by storage delta. EVM stack top is [slot, value];
            // mirrors cmp_linearity's SSTORE peek layout (slot @ peek 0, value @ peek 1).
            0x55 | 0x5d => {
                if interp.stack.len() < 2 {
                    return;
                }
                let slot = interp.stack.peek(0).unwrap();
                let new_val = interp.stack.peek(1).unwrap();
                let addr = interp.input.target_address;

                // on_step fires BEFORE the opcode executes, so evmstate.state still holds
                // the pre-image. Absent slot → pre is ZERO (revm cold-loads on access; a
                // genuine mint writes a non-zero delta regardless). A write-back of the
                // same value (e.g. `balances[0x0] -= 0` in burn(0,0)) is pre == new → not
                // material → suppressed.
                let pre = host
                    .evmstate
                    .state
                    .get(&addr)
                    .and_then(|acct| acct.get(&slot))
                    .copied()
                    .unwrap_or(EVMU256::ZERO);
                if pre == new_val {
                    return;
                }

                // Best-effort causal confirmation from the accumulated taint bus (read
                // before the mutable metadata borrow so the immutable borrows end first).
                let tainted = host
                    .arg_slot_provenance
                    .get(&(addr, slot))
                    .map(|p| *p != 0)
                    .unwrap_or(false)
                    || host
                        .tainted_storage
                        .get(&(addr, slot))
                        .map(|p| p.tainted)
                        .unwrap_or(false);

                let meta = &mut host.evmstate.permission_leak_metadata;
                meta.material_writes.insert((addr, slot));
                if tainted {
                    meta.tainted_material.insert((addr, slot));
                }
            }
            // CALL — materiality by non-zero ETH value move. Stack is
            // [gas, addr, value, ...]; value @ peek 2 (mirrors FeeOnTransferDetector).
            0xf1 => {
                if interp.stack.len() < 3 {
                    return;
                }
                let value = interp.stack.peek(2).unwrap();
                if value != EVMU256::ZERO {
                    let addr = interp.input.target_address;
                    host.evmstate.permission_leak_metadata.value_moves.insert(addr);
                }
            }
            _ => {}
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::PermissionLeak
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    //! Drives the real `on_step` opcode dispatch (not a reimplementation) over a
    //! minimal interpreter + host, mirroring the `cmp_linearity` test harness.
    use super::*;
    use crate::evm::vm::EVMState;
    use libafl::schedulers::QueueScheduler;

    /// The interpreter's `target_address` (interp_at seeds it as 0x11..11).
    fn target() -> EVMAddress {
        EVMAddress::repeat_byte(0x11)
    }

    fn host() -> FuzzHost<QueueScheduler<EVMFuzzState>> {
        let mut h = FuzzHost::new(QueueScheduler::new(), "work_dir".to_string());
        h.evmstate = EVMState::new();
        h
    }

    /// Minimal interpreter positioned at opcode `op` with an empty real stack.
    fn interp_at(op: u8) -> Interpreter {
        let addr = target();
        let bc = revm_interpreter::bytecode::Bytecode::new_raw(revm_primitives::Bytes::from(vec![op]));
        let input = revm_interpreter::interpreter::InputsImpl {
            target_address: addr,
            bytecode_address: Some(addr),
            caller_address: addr,
            input: revm_interpreter::CallInput::Bytes(revm_primitives::Bytes::new()),
            call_value: EVMU256::ZERO,
        };
        Interpreter::new(
            revm_interpreter::interpreter::SharedMemory::new(),
            revm_interpreter::interpreter::ExtBytecode::new(bc),
            input,
            false,
            revm_primitives::hardfork::SpecId::PRAGUE,
            10_000_000_000,
        )
    }

    /// Run one SSTORE writing `new` to slot 7 whose pre-image is `pre`. When
    /// `tainted`, seed the accumulated taint bus for that slot. EVM SSTORE stack is
    /// [slot, value] with slot on top → push value first (peek 1), slot second (peek 0).
    fn run_sstore(pre: u64, new: u64, tainted: bool) -> FuzzHost<QueueScheduler<EVMFuzzState>> {
        let addr = target();
        let slot = EVMU256::from(7u64);
        let mut h = host();
        h.evmstate.state.entry(addr).or_default().insert(slot, EVMU256::from(pre));
        if tainted {
            h.arg_slot_provenance.insert((addr, slot), 1u64 << 2);
        }
        let mut interp = interp_at(0x55);
        let _ = interp.stack.push(EVMU256::from(new)); // peek(1) = new value
        let _ = interp.stack.push(slot); // peek(0) = slot
        let mut mw = PermissionLeakTracer::new();
        let mut st = EVMFuzzState::default();
        unsafe {
            mw.on_step(&mut interp, &mut h, &mut st);
        }
        h
    }

    /// Run one CALL carrying ETH `value`. CALL stack is [gas, addr, value, ...] with
    /// gas on top → push value first (peek 2), addr (peek 1), gas last (peek 0).
    fn run_call(value: u64) -> FuzzHost<QueueScheduler<EVMFuzzState>> {
        let mut h = host();
        let mut interp = interp_at(0xf1);
        let _ = interp.stack.push(EVMU256::from(value)); // peek(2) = value
        let _ = interp.stack.push(EVMU256::from(0u64)); // peek(1) = addr
        let _ = interp.stack.push(EVMU256::from(21000u64)); // peek(0) = gas
        let mut mw = PermissionLeakTracer::new();
        let mut st = EVMFuzzState::default();
        unsafe {
            mw.on_step(&mut interp, &mut h, &mut st);
        }
        h
    }

    /// The `burn(0x0, 0)` shape: an SSTORE that writes back the same value. The delta
    /// is zero, so nothing is recorded and the oracle gate stays closed.
    #[test]
    fn burn_zero_is_not_material() {
        let h = run_sstore(100, 100, false);
        assert!(
            !h.evmstate.permission_leak_metadata.contract_material(&target()),
            "a no-op SSTORE (pre == new) must not count as material"
        );
        assert!(h.evmstate.permission_leak_metadata.material_writes.is_empty());
    }

    /// A real mint: the balance slot changes (pre != new) and the taint bus attributes
    /// it to attacker calldata → recorded material AND tainted-confirmed.
    #[test]
    fn tainted_privileged_sstore_is_material() {
        let h = run_sstore(100, 150, true);
        let slot = EVMU256::from(7u64);
        assert!(
            h.evmstate.permission_leak_metadata.contract_material(&target()),
            "an SSTORE with pre != new must be recorded as material"
        );
        assert!(
            h.evmstate
                .permission_leak_metadata
                .tainted_material
                .contains(&(target(), slot)),
            "a provenance bit on the bus must mark the material write attacker-tainted"
        );
    }

    /// Materiality gates on the delta alone: a real state change with an empty taint
    /// bus (input not yet reexecuted by cmp_linearity) is still material — the taint
    /// set is best-effort and stays empty without fabricating a bit.
    #[test]
    fn material_delta_without_taint_still_material() {
        let h = run_sstore(0, 42, false);
        assert!(
            h.evmstate.permission_leak_metadata.contract_material(&target()),
            "the delta gates materiality even when the taint bus is empty"
        );
        assert!(
            h.evmstate.permission_leak_metadata.tainted_material.is_empty(),
            "absent taint bus must not fabricate a tainted_material entry"
        );
    }

    /// The fail-closed property the oracle depends on: with no sink observed at all,
    /// `contract_material` is false for every contract, so a no-op privileged call is
    /// suppressed rather than fired.
    #[test]
    fn materiality_absent_fails_closed() {
        let h = host();
        assert!(!h.evmstate.permission_leak_metadata.contract_material(&target()));
    }

    /// An unauthorized `withdraw` that forwards ETH with no on-contract SSTORE is still
    /// material via the value-CALL path.
    #[test]
    fn value_call_is_material() {
        let h = run_call(1);
        assert!(
            h.evmstate.permission_leak_metadata.contract_material(&target()),
            "a CALL forwarding non-zero ETH value must be material"
        );
    }

    /// A value-0 CALL (the ordinary ERC-20 case) is not a value move.
    #[test]
    fn zero_value_call_not_material() {
        let h = run_call(0);
        assert!(
            !h.evmstate.permission_leak_metadata.contract_material(&target()),
            "a value-0 CALL is not a material value move"
        );
    }
}

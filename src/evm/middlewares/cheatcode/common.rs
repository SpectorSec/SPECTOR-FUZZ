use std::{clone::Clone, collections::HashMap, fmt::Debug, sync::Arc};

use alloy_primitives::Address;
use alloy_sol_types::SolValue;
use bytes::Bytes;
use foundry_cheatcodes::Vm::{self, CallerMode};
use libafl::schedulers::Scheduler;
use revm_interpreter::bytecode::Bytecode;
use crate::evm::types::Env;
use revm_primitives::{hardfork::SpecId, U256};

use super::Cheatcode;
use crate::evm::{
    host::FuzzHost,
    types::{EVMAddress, EVMFuzzState},
    vm::EVMState,
};

/// Prank information.
#[derive(Clone, Debug, Default)]
pub struct Prank {
    /// Address of the contract that initiated the prank
    pub old_caller: EVMAddress,
    /// Address of `tx.origin` when the prank was initiated
    pub old_origin: Option<EVMAddress>,
    /// The address to assign to `msg.sender`
    pub new_caller: EVMAddress,
    /// The address to assign to `tx.origin`
    pub new_origin: Option<EVMAddress>,
    /// Whether the prank stops by itself after the next call
    pub single_call: bool,
    /// The depth at which the prank was called
    pub depth: u64,
}

/// Records storage slots reads and writes.
#[derive(Clone, Debug, Default)]
pub struct RecordAccess {
    /// Storage slots reads.
    pub reads: HashMap<EVMAddress, Vec<U256>>,
    /// Storage slots writes.
    pub writes: HashMap<EVMAddress, Vec<U256>>,
}

/// Cheat VmCalls
impl<SC> Cheatcode<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    /// Gets the address for a given private key.
    #[inline]
    pub fn addr(&self, args: Vm::addrCall) -> Option<Vec<u8>> {
        let Vm::addrCall { privateKey } = args;
        let address: Address = privateKey.to_be_bytes::<{ U256::BYTES }>()[..20].try_into().unwrap();
        Some(address.abi_encode())
    }

    /// Sets `block.timestamp`.
    #[inline]
    pub fn warp(&self, env: &mut Env, args: Vm::warpCall) -> Option<Vec<u8>> {
        env.block.timestamp = args.newTimestamp;
        None
    }

    /// Sets `block.height`.
    #[inline]
    pub fn roll(&self, env: &mut Env, args: Vm::rollCall) -> Option<Vec<u8>> {
        env.block.number = args.newHeight;
        None
    }

    /// Sets `block.basefee`.
    #[inline]
    pub fn fee(&self, env: &mut Env, args: Vm::feeCall) -> Option<Vec<u8>> {
        env.block.basefee = args.newBasefee.saturating_to::<u64>();
        None
    }

    /// Sets `block.difficulty`.
    /// Not available on EVM versions from Paris onwards. Use `prevrandao`
    /// instead.
    #[inline]
    pub fn difficulty(&self, env: &mut Env, args: Vm::difficultyCall) -> Option<Vec<u8>> {
        if env.cfg.spec < SpecId::MERGE {
            env.block.difficulty = args.newDifficulty;
        }
        None
    }

    /// Sets `block.prevrandao` (bytes32 variant).
    /// Not available on EVM versions before Paris. Use `difficulty` instead.
    #[inline]
    pub fn prevrandao0(&self, env: &mut Env, args: Vm::prevrandao_0Call) -> Option<Vec<u8>> {
        if env.cfg.spec >= SpecId::MERGE {
            env.block.prevrandao = Some(args.newPrevrandao.0.into());
        }
        None
    }

    /// Sets `block.prevrandao` (uint256 variant).
    /// Not available on EVM versions before Paris. Use `difficulty` instead.
    #[inline]
    pub fn prevrandao1(&self, env: &mut Env, args: Vm::prevrandao_1Call) -> Option<Vec<u8>> {
        if env.cfg.spec >= SpecId::MERGE {
            env.block.prevrandao = Some(args.newPrevrandao.to_be_bytes::<32>().into());
        }
        None
    }

    /// Sets `block.chainid`.
    #[inline]
    pub fn chain_id(&self, env: &mut Env, args: Vm::chainIdCall) -> Option<Vec<u8>> {
        if args.newChainId <= U256::from(u64::MAX) {
            env.cfg.chain_id = args.newChainId.saturating_to::<u64>();
        }
        None
    }

    /// Sets `tx.gasprice`.
    #[inline]
    pub fn tx_gas_price(&self, env: &mut Env, args: Vm::txGasPriceCall) -> Option<Vec<u8>> {
        env.tx.gas_price = args.newGasPrice.saturating_to::<u128>();
        None
    }

    /// Sets `block.coinbase`.
    #[inline]
    pub fn coinbase(&self, env: &mut Env, args: Vm::coinbaseCall) -> Option<Vec<u8>> {
        env.block.beneficiary = args.newCoinbase;
        None
    }

    /// Loads a storage slot from an address.
    #[inline]
    pub fn load(&self, state: &EVMState, args: Vm::loadCall) -> Option<Vec<u8>> {
        let Vm::loadCall { target, slot } = args;

        Some(
            state
                .sload(target, slot.into())
                .unwrap_or_default()
                .abi_encode(),
        )
    }

    /// Stores a value to an address' storage slot.
    #[inline]
    pub fn store(&self, state: &mut EVMState, args: Vm::storeCall) -> Option<Vec<u8>> {
        let Vm::storeCall { target, slot, value } = args;
        state.sstore(target, slot.into(), value.into());
        None
    }

    /// Sets an address' code.
    #[inline]
    pub fn etch(&self, host: &mut FuzzHost<SC>, args: Vm::etchCall) -> Option<Vec<u8>> {
        let Vm::etchCall {
            target,
            newRuntimeBytecode,
        } = args;
        let bytecode = Bytecode::new_legacy(newRuntimeBytecode);

        // set code but don't invoke middlewares
        host.code.insert(
            target,
            Arc::new(bytecode),
        );
        None
    }

    /// Sets an address' balance.
    #[inline]
    pub fn deal(&self, state: &mut EVMState, args: Vm::dealCall) -> Option<Vec<u8>> {
        let Vm::dealCall { account, newBalance } = args;
        state.set_balance(account, newBalance);
        None
    }

    /// Reads the current `msg.sender` and `tx.origin` from state and reports if
    /// there is any active caller modification.
    #[inline]
    pub fn read_callers(
        &self,
        prank: &Option<Prank>,
        default_sender: &EVMAddress,
        default_origin: &EVMAddress,
    ) -> Option<Vec<u8>> {
        let (mut mode, mut sender, mut origin) = (CallerMode::None, default_sender, default_origin);

        if let Some(prank) = prank {
            mode = if prank.single_call {
                CallerMode::Prank
            } else {
                CallerMode::RecurrentPrank
            };
            sender = &prank.new_caller;
            if let Some(ref new_origin) = prank.new_origin {
                origin = new_origin;
            }
        }

        Some((mode, Address::from(sender.0), Address::from(origin.0)).abi_encode_params())
    }

    /// Records all storage reads and writes.
    #[inline]
    pub fn record(&mut self) -> Option<Vec<u8>> {
        self.accesses = Some(RecordAccess::default());
        None
    }

    /// Gets all accessed reads and write slot from a `vm.record` session, for a
    /// given address.
    #[inline]
    pub fn accesses(&mut self, args: Vm::accessesCall) -> Option<Vec<u8>> {
        let Vm::accessesCall { target } = args;
        let target = target;

        let result = self
            .accesses
            .as_mut()
            .map(|accesses| {
                (
                    &accesses.reads.entry(target).or_default()[..],
                    &accesses.writes.entry(target).or_default()[..],
                )
            })
            .unwrap_or_default();
        Some(result.abi_encode_params())
    }

    /// Record all the transaction logs.
    #[inline]
    pub fn record_logs(&mut self) -> Option<Vec<u8>> {
        self.recorded_logs = Some(Default::default());
        None
    }

    /// Gets all the recorded logs.
    #[inline]
    pub fn get_recorded_logs(&mut self) -> Option<Vec<u8>> {
        let result = self.recorded_logs.replace(Default::default()).unwrap_or_default();
        Some(result.abi_encode())
    }

    /// Sets the *next* call's `msg.sender` to be the input address.
    #[inline]
    pub fn prank0(
        &mut self,
        host: &mut FuzzHost<SC>,
        old_caller: &EVMAddress,
        args: Vm::prank_0Call,
    ) -> Option<Vec<u8>> {
        let Vm::prank_0Call { msgSender } = args;
        // call_depth was incremented before dispatch; subtract 1 to match the
        // test-frame depth where apply_prank is checked (before increment).
        host.prank = Some(Prank::new(
            *old_caller,
            None,
            msgSender,
            None,
            true,
            host.call_depth - 1,
        ));

        None
    }

    /// Sets the *next* call's `msg.sender` to be the input address,
    /// and the `tx.origin` to be the second input.
    #[inline]
    pub fn prank1(
        &mut self,
        host: &mut FuzzHost<SC>,
        old_caller: &EVMAddress,
        old_origin: &EVMAddress,
        args: Vm::prank_1Call,
    ) -> Option<Vec<u8>> {
        let Vm::prank_1Call { msgSender, txOrigin } = args;
        host.prank = Some(Prank::new(
            *old_caller,
            Some(*old_origin),
            msgSender,
            Some(txOrigin),
            true,
            host.call_depth - 1,
        ));

        None
    }

    /// Sets all subsequent calls' `msg.sender` to be the input address until
    /// `stopPrank` is called.
    #[inline]
    pub fn start_prank0(
        &mut self,
        host: &mut FuzzHost<SC>,
        old_caller: &EVMAddress,
        args: Vm::startPrank_0Call,
    ) -> Option<Vec<u8>> {
        let Vm::startPrank_0Call { msgSender } = args;
        host.prank = Some(Prank::new(
            *old_caller,
            None,
            msgSender,
            None,
            false,
            host.call_depth - 1,
        ));

        None
    }

    /// Sets all subsequent calls' `msg.sender` to be the input address until
    /// `stopPrank` is called, and the `tx.origin` to be the second input.
    #[inline]
    pub fn start_prank1(
        &mut self,
        host: &mut FuzzHost<SC>,
        old_caller: &EVMAddress,
        old_origin: &EVMAddress,
        args: Vm::startPrank_1Call,
    ) -> Option<Vec<u8>> {
        let Vm::startPrank_1Call { msgSender, txOrigin } = args;
        host.prank = Some(Prank::new(
            *old_caller,
            Some(*old_origin),
            msgSender,
            Some(txOrigin),
            false,
            host.call_depth - 1,
        ));

        None
    }

    /// Resets subsequent calls' `msg.sender` to be `address(this)`.
    #[inline]
    pub fn stop_prank(&mut self, host: &mut FuzzHost<SC>) -> Option<Vec<u8>> {
        let _ = host.prank.take();
        None
    }

    /// Label an address in test traces.
    #[inline]
    pub fn label(&mut self, args: Vm::labelCall) -> Option<Vec<u8>> {
        let Vm::labelCall { account, newLabel } = args;
        self.labels.insert(account, newLabel);
        None
    }

    /// Gets the label of an address in test traces.
    #[inline]
    pub fn get_label(&self, args: Vm::getLabelCall) -> Option<Vec<u8>> {
        let Vm::getLabelCall { account } = args;
        let result = self.labels.get(&account).cloned()?;
        Some(result.abi_encode())
    }

    /// Computes the address a contract would be deployed at with the CREATE
    /// opcode given the deployer address and current nonce.
    /// Pure computation: keccak256(rlp([deployer, nonce]))[12..]
    #[inline]
    pub fn compute_create_address(&self, args: Vm::computeCreateAddressCall) -> Option<Vec<u8>> {
        let Vm::computeCreateAddressCall { deployer, nonce } = args;
        let nonce_u64: u64 = nonce.saturating_to();
        let created: Address = deployer.create(nonce_u64);
        Some(created.abi_encode())
    }

    /// Computes the address a contract would be deployed at with CREATE2
    /// given a deployer, salt, and initcode hash.
    #[inline]
    pub fn compute_create2_address0(&self, args: Vm::computeCreate2Address_0Call) -> Option<Vec<u8>> {
        let Vm::computeCreate2Address_0Call { salt, initCodeHash, deployer } = args;
        let created: Address = deployer.create2(salt, initCodeHash);
        Some(created.abi_encode())
    }

    /// Computes the CREATE2 address using the default CREATE2 deployer
    /// (0x4e59b44847b379578588920cA78FbF26c0B4956C).
    #[inline]
    pub fn compute_create2_address1(&self, args: Vm::computeCreate2Address_1Call) -> Option<Vec<u8>> {
        let Vm::computeCreate2Address_1Call { salt, initCodeHash } = args;
        // Standard CREATE2 factory address (Nick's method).
        let factory = Address::from([
            0x4e, 0x59, 0xb4, 0x48, 0x47, 0xb3, 0x79, 0x57, 0x85, 0x88,
            0x92, 0x0c, 0xa7, 0x8f, 0xbf, 0x26, 0xc0, 0xb4, 0x95, 0x6c,
        ]);
        let created: Address = factory.create2(salt, initCodeHash);
        Some(created.abi_encode())
    }

    /// Returns the nonce of an account.
    /// In the fork state, nonces are not separately tracked; new attacker
    /// addresses always start at 0, which matches every real exploit PoC.
    #[inline]
    pub fn get_nonce0(&self, args: Vm::getNonce_0Call) -> Option<Vec<u8>> {
        let Vm::getNonce_0Call { account: _ } = args;
        Some(0u64.abi_encode())
    }
}

impl Prank {
    /// Create a new prank.
    pub fn new(
        old_caller: EVMAddress,
        old_origin: Option<EVMAddress>,
        new_caller: EVMAddress,
        new_origin: Option<EVMAddress>,
        single_call: bool,
        depth: u64,
    ) -> Prank {
        Prank {
            old_caller,
            old_origin,
            new_caller,
            new_origin,
            single_call,
            depth,
        }
    }
}

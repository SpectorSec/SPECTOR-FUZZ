use core::ops::Range;
use std::{
    any::Any,
    cell::RefCell,
    cmp::min,
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    fmt::Debug,
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::Deref,
    rc::Rc,
    sync::Arc,
};

use bytes::Bytes;
/// EVM executor implementation
use itertools::Itertools;
use libafl::schedulers::Scheduler;
use revm_interpreter::{
    interpreter::{ExtBytecode, InputsImpl, SharedMemory},
    interpreter_types::{Jumps, ReturnData as ReturnDataTr},
    CallInput, InstructionResult, Interpreter, Stack,
};
use revm_interpreter::bytecode::Bytecode;
use revm_primitives::{hardfork::SpecId, Bytes as PrimBytes};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{debug, error};

use super::{input::EVMInput, middlewares::reentrancy::ReentrancyData, types::EVMFuzzState};
use crate::{evm::tokens::SwapData, generic_vm::vm_state};
#[allow(unused_imports)]
use crate::{
    evm::{
        bytecode_analyzer,
        host::{FuzzHost, CMP_MAP, COVERAGE_NOT_CHANGED, JMP_MAP, READ_MAP, STATE_CHANGE, WRITE_MAP},
        input::{ConciseEVMInput, EVMInputT, EVMInputTy},
        middlewares::middleware::{Middleware, MiddlewareType},
        onchain::flashloan::FlashloanData,
        types::{float_scale_to_u512, EVMAddress, EVMU256, EVMU512},
        vm::Constraint::{NoLiquidation, Value},
    },
    generic_vm::{
        vm_executor::{ExecutionResult, GenericVM, MAP_SIZE},
        vm_state::VMStateT,
    },
    input::{ConciseSerde, VMInputT},
    invoke_middlewares,
    state::{HasCaller, HasCurrentInputIdx, HasItyState},
    state_input::StagedVMState,
};

pub const MEM_LIMIT: u64 = 500 * 1024;
const MAX_POST_EXECUTION: usize = 10;

/// Get the token context from the flashloan middleware,
/// which contains uniswap pairs of that token
#[macro_export]
macro_rules! get_token_ctx {
    ($flashloan_mid: expr, $token: expr) => {
        $flashloan_mid
            .flashloan_oracle
            .deref()
            .borrow()
            .known_tokens
            .borrow()
            .get(&$token)
            .expect(format!("unknown token : {:?}", $token).as_str())
    };
}

/// Determine whether a call is successful
#[macro_export]
macro_rules! is_call_success {
    ($ret: expr) => {
        $ret == revm_interpreter::InstructionResult::Return ||
            $ret == revm_interpreter::InstructionResult::Stop ||
            $ret == revm_interpreter::InstructionResult::SelfDestruct ||
            // control-leak is signalled via static flags + Revert, treat as success for token accounting
            ($ret == revm_interpreter::InstructionResult::Revert && unsafe {
                crate::evm::host::CONTROL_LEAK_DETECTED ||
                crate::evm::host::ARBITRARY_CALL_DETECTED ||
                crate::evm::host::UNBOUNDED_STATIC_CALL_DETECTED
            })
    };
}

/// A post execution constraint
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Constraint {
    Caller(EVMAddress),
    Contract(EVMAddress),
    Value(EVMU256),
    NoLiquidation,
    MustStepNow,
}

/// A post execution context
/// When control is leaked, we dump the current execution context. This context
/// includes all information needed to continue subsequent execution (e.g.,
/// stack, pc, memory, etc.) Post execution context is attached to VM state if
/// control is leaked.
///
/// When EVM input has `step` set to true, then we continue execution from the
/// post execution context available. If `step` is false, then we conduct
/// reentrancy (i.e., don't need to continue execution from the post execution
/// context but we execute the input directly
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SinglePostExecution {
    /// All continuation info
    /// Instruction pointer (byte offset into bytecode).
    pub program_counter: usize,
    /// Memory snapshot (raw bytes).
    pub memory: Vec<u8>,
    /// Stack snapshot.
    pub stack: Vec<EVMU256>,
    /// Is interpreter call static.
    pub is_static: bool,
    /// Calldata bytes.
    pub input: Vec<u8>,
    /// Bytecode address (code_address).
    pub code_address: EVMAddress,
    /// Contract address (target_address).
    pub address: EVMAddress,
    /// Caller of the EVM.
    pub caller: EVMAddress,
    /// Value sent to contract.
    pub value: EVMU256,

    /// Post execution related information
    /// Output Length
    pub output_len: usize,
    /// Output Offset
    pub output_offset: usize,
}

impl Hash for SinglePostExecution {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.program_counter.hash(state);
        self.memory.hash(state);
        self.stack.hash(state);
        self.is_static.hash(state);
        self.input.hash(state);
        self.code_address.hash(state);
        self.address.hash(state);
        self.caller.hash(state);
        self.value.hash(state);
        self.output_len.hash(state);
        self.output_offset.hash(state);
    }
}

impl SinglePostExecution {
    fn get_interpreter(&self, bytecode: Arc<Bytecode>) -> Interpreter {
        let mut ext_bytecode = ExtBytecode::new((*bytecode).clone());
        ext_bytecode.absolute_jump(self.program_counter);

        let mut mem = SharedMemory::new_with_memory_limit(MEM_LIMIT);
        if !self.memory.is_empty() {
            mem.resize(self.memory.len());
            mem.set(0, &self.memory);
        }

        let interp_input = InputsImpl {
            target_address: self.address,
            bytecode_address: Some(self.code_address),
            caller_address: self.caller,
            input: CallInput::Bytes(PrimBytes::copy_from_slice(&self.input)),
            call_value: self.value,
        };

        let mut interp = Interpreter::new(
            mem,
            ext_bytecode,
            interp_input,
            self.is_static,
            SpecId::PRAGUE,
            u64::MAX,
        );

        for v in &self.stack {
            let _ = interp.stack.push(*v);
        }

        interp
    }

    pub fn from_interp(interp: &Interpreter, (out_offset, out_len): (usize, usize)) -> Self {
        let input_bytes = match &interp.input.input {
            CallInput::Bytes(b) => b.to_vec(),
            CallInput::SharedBuffer(_) => vec![],
        };
        Self {
            program_counter: interp.bytecode.pc(),
            memory: interp.memory.context_memory().to_vec(),
            stack: interp.stack.data().clone(),
            is_static: interp.runtime_flag.is_static,
            input: input_bytes,
            code_address: interp.input.bytecode_address.unwrap_or(interp.input.target_address),
            address: interp.input.target_address,
            caller: interp.input.caller_address,
            value: interp.input.call_value,
            output_len: out_len,
            output_offset: out_offset,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PostExecutionCtx {
    pub constraints: Vec<Constraint>,
    pub pes: Vec<SinglePostExecution>,

    pub must_step: bool,
}

impl Hash for PostExecutionCtx {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for pe in &self.pes {
            pe.hash(state);
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct EVMState {
    /// State of the EVM, which is mapping of EVMU256 slot to EVMU256 value for
    /// each contract
    pub state: HashMap<EVMAddress, HashMap<EVMU256, EVMU256>>,

    /// Balance of addresses
    pub balance: HashMap<EVMAddress, EVMU256>,

    /// Observed return values from contract calls (for parameter routing)
    pub observed_values: HashMap<String, Vec<EVMU256>>,

    /// Post execution context
    /// If control leak happens, we add the post execution context to the VM
    /// state, which contains all information needed to continue execution.
    ///
    /// There can be more than one [`PostExecutionCtx`] when the control is
    /// leaked again on the incomplete state (i.e., double+ reentrancy)
    pub post_execution: Vec<PostExecutionCtx>,

    /// Flashloan information
    /// (e.g., how much flashloan is taken, and how much tokens are liquidated)
    #[serde(skip)]
    pub flashloan_data: FlashloanData,

    /// Is bug() call in Solidity hit?
    #[serde(skip)]
    pub bug_hit: bool,
    /// selftdestruct() call in Solidity hit?
    #[serde(skip)]
    pub self_destruct: HashSet<(EVMAddress, usize)>,
    /// bug type call in solidity type
    #[serde(skip)]
    pub typed_bug: HashSet<(String, (EVMAddress, usize))>,
    #[serde(skip)]
    pub arbitrary_calls: HashSet<(EVMAddress, EVMAddress, usize)>,
    #[serde(skip)]
    pub arbitrary_transfers: HashSet<(EVMAddress, usize)>,
    // integer overflow in sol
    #[serde(skip)]
    pub integer_overflow: HashSet<(EVMAddress, usize, &'static str)>,
    #[serde(skip)]
    pub reentrancy_metadata: ReentrancyData,
    #[serde(skip)]
    pub swap_data: SwapData,
    /// ERC-721 / ERC-1155 Transfer events: (token_contract, from, to, token_id)
    #[serde(skip)]
    pub nft_transfers: Vec<(EVMAddress, EVMAddress, EVMAddress, revm_primitives::B256)>,
    /// ERC-20 Transfer events: (token_contract, from, to, value)
    #[serde(skip)]
    pub erc20_transfers: Vec<(EVMAddress, EVMAddress, EVMAddress, EVMU256)>,
    /// ERC-20 Approval events: (token_contract, owner, spender, value)
    #[serde(skip)]
    pub erc20_approvals: Vec<(EVMAddress, EVMAddress, EVMAddress, EVMU256)>,
}

pub trait EVMStateT {
    fn get_constraints(&self) -> Vec<Constraint>;
}

impl EVMStateT for EVMState {
    fn get_constraints(&self) -> Vec<Constraint> {
        match self.post_execution.last() {
            Some(i) => i.constraints.clone(),
            None => vec![],
        }
    }
}

impl VMStateT for EVMState {
    /// Calculate the hash of the VM state
    fn get_hash(&self) -> u64 {
        let mut s = DefaultHasher::new();
        for i in self.post_execution.iter() {
            i.hash(&mut s);
        }
        for i in self.state.iter().sorted_by_key(|k| k.0) {
            i.0 .0.hash(&mut s);
            for j in i.1.iter() {
                j.0.hash(&mut s);
                j.1.hash(&mut s);
            }
        }
        s.finish()
    }

    /// Check whether current state has post execution context
    /// This can also used to check whether a state is intermediate state (i.e.,
    /// not yet finished execution)
    fn has_post_execution(&self) -> bool {
        !self.post_execution.is_empty()
    }

    /// Get length needed for return data length of the call that leads to
    /// control leak
    fn get_post_execution_needed_len(&self) -> usize {
        self.post_execution.last().unwrap().pes.first().unwrap().output_len
    }

    /// Get the PC of last post execution context
    fn get_post_execution_pc(&self) -> usize {
        match self.post_execution.last() {
            Some(i) => i.pes.first().unwrap().program_counter,
            None => 0,
        }
    }

    /// Get amount of post execution context
    fn get_post_execution_len(&self) -> usize {
        self.post_execution.len()
    }

    /// Get flashloan information
    #[cfg(feature = "full_trace")]
    fn get_flashloan(&self) -> String {
        format!(
            "earned: {:?}, owed: {:?}",
            self.flashloan_data.earned, self.flashloan_data.owed
        )
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }

    fn is_subset_of(&self, other: &Self) -> bool {
        self.state.iter().all(|(k, v)| {
            other
                .state
                .get(k)
                .map_or(false, |v2| v.iter().all(|(k, v)| v2.get(k).map_or(false, |v2| v == v2)))
        })
    }

    fn get_swap_data(&self) -> HashMap<String, vm_state::SwapInfo> {
        self.swap_data.to_generic()
    }
}

impl EVMState {
    /// Create a new EVM state, containing empty state, no post execution
    /// context
    pub(crate) fn new() -> Self {
        Default::default()
    }

    /// Get all storage slots of a specific contract
    pub fn get(&self, address: &EVMAddress) -> Option<&HashMap<EVMU256, EVMU256>> {
        self.state.get(address)
    }

    /// Get all storage slots of a specific contract (mutable)
    pub fn get_mut(&mut self, address: &EVMAddress) -> Option<&mut HashMap<EVMU256, EVMU256>> {
        self.state.get_mut(address)
    }

    /// Insert all storage slots of a specific contract
    pub fn insert(&mut self, address: EVMAddress, storage: HashMap<EVMU256, EVMU256>) {
        self.state.insert(address, storage);
    }

    /// Get balance of a specific address
    pub fn get_balance(&self, address: &EVMAddress) -> Option<&EVMU256> {
        self.balance.get(address)
    }

    /// Set balance of a specific address
    pub fn set_balance(&mut self, address: EVMAddress, balance: EVMU256) {
        self.balance.insert(address, balance);
    }

    /// Loads a storage slot from an address.
    pub fn sload(&self, address: EVMAddress, slot: EVMU256) -> Option<EVMU256> {
        self.state.get(&address).and_then(|slots| slots.get(&slot).cloned())
    }

    /// Stores a value to an address' storage slot.
    pub fn sstore(&mut self, address: EVMAddress, slot: EVMU256, value: EVMU256) {
        self.state.entry(address).or_default().insert(slot, value);
    }
}

/// Is current EVM execution fast call
pub static mut IS_FAST_CALL: bool = false;

/// Is current EVM execution fast call (static)
/// - Fast call is a call that does not change the state of the contract
pub static mut IS_FAST_CALL_STATIC: bool = false;

/// EVM executor, wrapper of revm
#[derive(Debug, Clone)]
pub struct EVMExecutor<VS, CI, SC>
where
    VS: VMStateT,
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    /// Host providing the blockchain environment (e.g., writing/reading
    /// storage), needed by revm
    pub host: FuzzHost<SC>,
    /// [Depreciated] Deployer address
    pub deployer: EVMAddress,
    /// Known arbitrary (caller,pc)
    pub _known_arbitrary: HashSet<(EVMAddress, usize)>,
    phandom: PhantomData<(EVMInput, VS, CI)>,
}

pub fn is_reverted_or_control_leak(ret: &InstructionResult) -> bool {
    !matches!(
        *ret,
        InstructionResult::Return | InstructionResult::Stop | InstructionResult::SelfDestruct
    )
}

/// Execution result that may have control leaked
/// Contains raw information of revm output and execution
#[derive(Clone, Debug)]
pub struct IntermediateExecutionResult {
    /// Output of the execution
    pub output: Bytes,
    /// The new state after execution
    pub new_state: EVMState,
    /// Program counter after execution
    pub pc: usize,
    /// Return value after execution
    pub ret: InstructionResult,
    /// Stack after execution
    pub stack: Vec<EVMU256>,
    /// Memory after execution
    pub memory: Vec<u8>,
}

macro_rules! init_host {
    ($host:expr) => {
        $host.current_self_destructs = vec![];
        $host.current_arbitrary_calls = vec![];
        $host.current_arbitrary_transfers = vec![];
        $host.call_count = 0;
        $host.jumpi_trace = 37;
        $host.current_typed_bug = vec![];
        $host.randomness = vec![9];
        $host.transient_storage = HashMap::new();
        // Uncomment the next line if middleware is needed.
        // $host.add_middlewares(middleware.clone());
    };
}

macro_rules! execute_call_single {
    ($caller:expr, $address:expr, $value:expr, $host:expr, $state:expr, $by: expr) => {{
        let code = $host.code.get($address).expect("no code").clone();
        let interp_input = InputsImpl {
            target_address: *$address,
            bytecode_address: Some(*$address),
            caller_address: $caller,
            input: CallInput::Bytes(PrimBytes::copy_from_slice($by.as_ref())),
            call_value: $value,
        };
        let mut interp = Interpreter::new(
            SharedMemory::new_with_memory_limit(MEM_LIMIT),
            ExtBytecode::new((*code).clone()),
            interp_input,
            false,
            SpecId::PRAGUE,
            1e10 as u64,
        );
        let ret = $host.run_inspect(&mut interp, $state);
        (interp.return_data.buffer().to_vec(), is_call_success!(ret))
    }};
}

impl<VS, CI, SC> EVMExecutor<VS, CI, SC>
where
    VS: Default + VMStateT + 'static,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
    SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
{
    pub fn fast_call_(
        &mut self,
        address: EVMAddress,
        data: Bytes,
        vm_state: &mut EVMState,
        state: &mut EVMFuzzState,
        value: EVMU256,
        from: EVMAddress,
    ) -> (Bytes, InstructionResult) {
        unsafe {
            IS_FAST_CALL = true;
        }
        let code = self.host.code.get(&address).unwrap_or_else(|| panic!("no code {:?}", address)).clone();
        let interp_input = InputsImpl {
            target_address: address,
            bytecode_address: Some(address),
            caller_address: from,
            input: CallInput::Bytes(PrimBytes::copy_from_slice(data.as_ref())),
            call_value: value,
        };
        self.host.evmstate = vm_state.clone();
        let mut interp = Interpreter::new(
            SharedMemory::new_with_memory_limit(MEM_LIMIT),
            ExtBytecode::new((*code).clone()),
            interp_input,
            false,
            SpecId::PRAGUE,
            1e10 as u64,
        );
        let ret = self.host.run_inspect(&mut interp, state);
        *vm_state = self.host.evmstate.clone();
        unsafe {
            IS_FAST_CALL = false;
        }
        (Bytes::from(interp.return_data.buffer().to_vec()), ret)
    }

    /// Create a new EVM executor given a host and deployer address
    pub fn new(fuzz_host: FuzzHost<SC>, deployer: EVMAddress) -> Self {
        Self {
            host: fuzz_host,
            deployer,
            _known_arbitrary: Default::default(),
            phandom: PhantomData,
        }
    }

    /// Execute from a specific program counter and context
    ///
    /// `call_ctx` is the context of the call (e.g., caller address, callee
    /// address, etc.) `vm_state` is the VM state to execute on
    /// `data` is the input (function hash + serialized ABI args)
    /// `input` is the additional input information (e.g., access pattern, etc.)
    ///     If post execution context exists, then this is the return buffer of
    /// the call that leads     to control leak. This is like we are fuzzing
    /// the subsequent execution wrt the return     buffer of the control
    /// leak call. `post_exec` is the post execution context to use, if any
    ///     If `post_exec` is `None`, then the execution is from the beginning,
    /// otherwise it is from     the post execution context.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_from_pc(
        &mut self,
        caller: EVMAddress,
        address: EVMAddress,
        value: EVMU256,
        vm_state: &EVMState,
        data: Bytes,
        input: &EVMInput,
        post_exec: Option<SinglePostExecution>,
        state: &mut EVMFuzzState,
        cleanup: bool,
    ) -> IntermediateExecutionResult {
        // Initial setups
        if cleanup {
            self.host.coverage_changed = false;
            self.host.bug_hit = false;
            self.host.current_typed_bug = vec![];
            self.host.jumpi_trace = 37;
            self.host.current_self_destructs = vec![];
            self.host.current_arbitrary_calls = vec![];
            self.host.current_arbitrary_transfers = vec![];
            self.host.transient_storage = HashMap::new();
            self.host.expected_emits.clear();
            self.host.expected_revert = None;
            self.host.expected_calls.clear();
            self.host.assert_msg = None;
            self.host.prank = None;
            self.host.call_depth = 0;
            // Initially, there is no state change
            unsafe {
                STATE_CHANGE = false;
            }
        }

        self.host.evmstate = vm_state.clone();
        self.host.env = input.get_vm_env().clone();
        self.host.is_staleness_test = input.get_vm_env().is_staleness_test;
        if self.host.initial_block_timestamp.is_none() && !input.get_vm_env().is_staleness_test {
            self.host.initial_block_timestamp = Some(input.get_vm_env().block.timestamp);
        }
        self.host.env.tx.caller = if input.get_origin().is_zero() {
            input.get_caller()
        } else {
            input.get_origin() // vm.prank; concolic
        };
        self.host.access_pattern = input.get_access_pattern().clone();
        self.host.call_count = 0;
        self.host.randomness = input.get_randomness();
        let mut repeats = input.get_repeat();

        // Get the bytecode
        let bytecode = match self.host.code.get(&address) {
            Some(i) => i.clone(),
            None => {
                debug!("no code @ {:?}, did you forget to deploy?", address);
                return IntermediateExecutionResult {
                    output: Bytes::new(),
                    new_state: EVMState::new(),
                    pc: 0,
                    ret: InstructionResult::Revert,
                    stack: Default::default(),
                    memory: Default::default(),
                };
            }
        };

        // Create the interpreter
        let mut interp = if let Some(ref post_exec_ctx) = post_exec {
            // Restore interpreter from post-execution context (control-leak step)
            repeats = 1;
            let mut interp = post_exec_ctx.get_interpreter(bytecode);
            // Feed the fuzzer's data as the return buffer (skip 4-byte selector)
            let ret_buf = PrimBytes::copy_from_slice(&data[4..]);
            let target_len = min(post_exec_ctx.output_len, ret_buf.len());
            let copy_data = ret_buf.slice(..target_len);
            interp.memory.set(post_exec_ctx.output_offset, &copy_data);
            interp.return_data.set_buffer(ret_buf);
            interp
        } else {
            // Fresh interpreter from the beginning
            let interp_input = InputsImpl {
                target_address: address,
                bytecode_address: Some(address),
                caller_address: caller,
                input: CallInput::Bytes(PrimBytes::copy_from_slice(data.as_ref())),
                call_value: value,
            };
            Interpreter::new(
                SharedMemory::new_with_memory_limit(MEM_LIMIT),
                ExtBytecode::new((*bytecode).clone()),
                interp_input,
                false,
                SpecId::PRAGUE,
                1e10 as u64,
            )
        };

        // Execute the contract for `repeats` times or until revert
        let mut r = InstructionResult::Stop;
        for _v in 0..repeats - 1 {
            r = self.host.run_inspect(&mut interp, state);
            interp.stack.data_mut().clear();
            // re-point bytecode to start
            interp.bytecode.absolute_jump(0);
            if !is_call_success!(r) {
                break;
            }
        }
        if is_call_success!(r) {
            r = self.host.run_inspect(&mut interp, state);
        }

        // Build the result
        let mut result = IntermediateExecutionResult {
            output: Bytes::from(interp.return_data.buffer().to_vec()),
            new_state: self.host.evmstate.clone(),
            pc: interp.bytecode.pc(),
            ret: r,
            stack: interp.stack.data().clone(),
            memory: interp.memory.context_memory().to_vec(),
        };

        // Capture top-level return values if value capture is enabled and execution succeeded
        let is_value_capture_enabled = self.host.middlewares_enabled && {
            let mws = self.host.middlewares.read().unwrap();
            mws.iter().any(|mw| mw.borrow().get_type() == MiddlewareType::ValueCapture)
        };

        if is_value_capture_enabled && !is_reverted_or_control_leak(&r) && result.output.len() >= 32 {
            let calldata = &data;
            let mut selector = [0u8; 4];
            if calldata.len() >= 4 {
                selector.copy_from_slice(&calldata[0..4]);
            }
            let key = format!("{:?}_{}_return", input.get_contract(), hex::encode(selector));
            let mut values_to_add = Vec::new();
            for chunk in result.output.chunks_exact(32) {
                let val = EVMU256::from_be_bytes::<32>(chunk.try_into().unwrap());
                values_to_add.push(val);
            }
            if !values_to_add.is_empty() {
                let observed = &mut result.new_state.observed_values;
                let list = observed.entry(key).or_default();
                for val in values_to_add {
                    if !list.contains(&val) {
                        list.push(val);
                    }
                }
                if list.len() > 10 {
                    let drain_idx = list.len() - 10;
                    list.drain(0..drain_idx);
                }
            }
        }

        // [todo] remove this
        unsafe {
            if self.host.coverage_changed {
                COVERAGE_NOT_CHANGED = 0;
            } else {
                COVERAGE_NOT_CHANGED += 1;
            }
        }

        // hack to record txn value
        if let Some(ref m) = self.host.flashloan_middleware {
            m.deref()
                .borrow_mut()
                .analyze_call(input, &mut result.new_state.flashloan_data)
        }

        result
    }

    /// Execute a transaction, wrapper of [`EVMExecutor::execute_from_pc`]
    fn execute_abi(
        &mut self,
        input: &EVMInput,
        state: &mut EVMFuzzState,
    ) -> ExecutionResult<EVMAddress, EVMAddress, VS, Vec<u8>, CI> {
        // Get necessary info from input
        let mut vm_state = unsafe { input.get_state().as_any().downcast_ref::<EVMState>().unwrap().clone() };
        self.host.nested_actions = input.get_nested_actions();

        // check balance
        #[cfg(feature = "real_balance")]
        {
            let tx_value = input.get_txn_value().unwrap_or_default();
            if tx_value > EVMU256::ZERO {
                let caller_balance = *vm_state.get_balance(&input.get_caller()).unwrap_or(&EVMU256::ZERO);
                let contract_balance = *vm_state.get_balance(&input.get_contract()).unwrap_or(&EVMU256::ZERO);
                if !state.has_caller(&input.get_caller()) {
                    if caller_balance < tx_value {
                        return ExecutionResult {
                            output: vec![],
                            reverted: true,
                            new_state: StagedVMState::new_uninitialized(),
                            additional_info: None,
                        };
                    }
                    vm_state.set_balance(input.get_caller(), caller_balance - tx_value);
                }

                vm_state.set_balance(input.get_contract(), contract_balance + tx_value);
            }
        }

        let r;
        let mut is_step = input.is_step();
        let mut data = Bytes::from(input.to_bytes());
        // use direct data (mostly used for debugging) if there is no data
        if data.is_empty() {
            data = Bytes::from(input.get_direct_data());
        }

        let mut cleanup = true;

        loop {
            unsafe {
                invoke_middlewares!(
                    &mut self.host,
                    None,
                    state,
                    before_execute,
                    is_step,
                    &mut data,
                    &mut vm_state
                );
            }
            // Execute the transaction
            let exec_res = if is_step {
                let post_exec = vm_state.post_execution.pop().unwrap().clone();
                let mut local_res = None;
                for mut pe in post_exec.pes {
                    // we need push the output of CALL instruction
                    let _ = pe.stack.push(EVMU256::from(1));
                    let (pe_caller, pe_address, pe_value) = (pe.caller, pe.address, pe.value);
                    let res =
                        self.execute_from_pc(pe_caller, pe_address, pe_value, &vm_state, data, input, Some(pe), state, cleanup);
                    data = Bytes::from([vec![0; 4], res.output.to_vec()].concat());
                    local_res = Some(res);
                    if is_reverted_or_control_leak(&local_res.as_ref().unwrap().ret) {
                        break;
                    }
                    cleanup = false;
                }
                local_res.unwrap()
            } else {
                let caller = input.get_caller();
                let value = input.get_txn_value().unwrap_or(EVMU256::ZERO);
                let contract_address = input.get_contract();
                self.execute_from_pc(
                    caller,
                    contract_address,
                    value,
                    &vm_state,
                    data,
                    input,
                    None,
                    state,
                    cleanup,
                )
            };
            let need_step = !exec_res.new_state.post_execution.is_empty() &&
                exec_res.new_state.post_execution.last().unwrap().must_step;
            if (exec_res.ret == InstructionResult::Return || exec_res.ret == InstructionResult::Stop) && need_step {
                is_step = true;
                data = Bytes::from([vec![0; 4], exec_res.output.to_vec()].concat());
                // we dont need to clean up bug info and state info
                cleanup = false;
            } else {
                r = Some(exec_res);
                break;
            }
        }
        let mut r = r.unwrap();
        let (is_control_leak, is_arbitrary_call, is_unbounded_static) = unsafe {
            (
                crate::evm::host::CONTROL_LEAK_DETECTED,
                crate::evm::host::ARBITRARY_CALL_DETECTED,
                crate::evm::host::UNBOUNDED_STATIC_CALL_DETECTED,
            )
        };
        if is_control_leak || is_arbitrary_call || is_unbounded_static {
            if r.new_state.post_execution.len() + 1 > MAX_POST_EXECUTION {
                return ExecutionResult {
                    output: r.output.to_vec(),
                    reverted: true,
                    new_state: StagedVMState::new_uninitialized(),
                    additional_info: None,
                };
            }
            let leak_ctx = self.host.leak_ctx.clone();
            let constraints = if is_arbitrary_call {
                let (arb_caller, arb_target, arb_value) = unsafe {
                    (
                        EVMAddress::from(crate::evm::host::ARBITRARY_CALL_CALLER),
                        EVMAddress::from(crate::evm::host::ARBITRARY_CALL_TARGET),
                        crate::evm::host::ARBITRARY_CALL_VALUE,
                    )
                };
                vec![
                    Constraint::Caller(arb_caller),
                    Constraint::Contract(arb_target),
                    Value(arb_value),
                    NoLiquidation,
                ]
            } else if is_unbounded_static {
                vec![Constraint::MustStepNow]
            } else {
                vec![]
            };
            r.new_state.post_execution.push(PostExecutionCtx {
                pes: leak_ctx,
                must_step: is_arbitrary_call,
                constraints,
            });
        }

        r.new_state.typed_bug = HashSet::from_iter(
            vm_state
                .typed_bug
                .iter()
                .cloned()
                .chain(self.host.current_typed_bug.iter().cloned()),
        );
        r.new_state.self_destruct = HashSet::from_iter(
            vm_state
                .self_destruct
                .iter()
                .cloned()
                .chain(self.host.current_self_destructs.iter().cloned()),
        );
        r.new_state.arbitrary_calls = HashSet::from_iter(
            vm_state
                .arbitrary_calls
                .iter()
                .cloned()
                .chain(self.host.current_arbitrary_calls.iter().cloned()),
        );
        r.new_state.arbitrary_transfers = HashSet::from_iter(
            vm_state
                .arbitrary_transfers
                .iter()
                .cloned()
                .chain(self.host.current_arbitrary_transfers.iter().cloned()),
        );

        r.new_state.integer_overflow = HashSet::from_iter(
            vm_state
                .integer_overflow
                .iter()
                .cloned()
                .chain(self.host.current_integer_overflow.iter().cloned()),
        );

        ExecutionResult {
            output: r.output.to_vec(),
            reverted: !matches!(
                r.ret,
                InstructionResult::Return |
                    InstructionResult::Stop |
                    InstructionResult::SelfDestruct
            ) && !is_control_leak && !is_arbitrary_call && !is_unbounded_static,
            new_state: StagedVMState::new_with_state(
                VMStateT::as_any(&r.new_state).downcast_ref::<VS>().unwrap().clone(),
            ),
            additional_info: if is_control_leak {
                Some(vec![self.host.call_count as u8])
            } else {
                None
            },
        }
    }

    pub fn reexecute_with_middleware(
        &mut self,
        input: &EVMInput,
        state: &mut EVMFuzzState,
        middleware: Rc<RefCell<dyn Middleware<SC>>>,
    ) {
        self.host.add_middlewares(middleware.clone());
        self.execute(input, state);
        self.host.remove_middlewares(middleware);
    }

    fn _fast_call_inner(
        &mut self,
        data: &[(EVMAddress, EVMAddress, Bytes, EVMU256)],
        vm_state: &EVMState,
        state: &mut EVMFuzzState,
    ) -> (Vec<(Vec<u8>, bool)>, EVMState) {
        self.host.evmstate = vm_state.clone();

        init_host!(self.host);
        let res = data
            .iter()
            .map(|(caller, address, by, value)| {
                execute_call_single!(*caller, address, *value, self.host, state, by)
            })
            .collect::<Vec<(Vec<u8>, bool)>>();
        (res, self.host.evmstate.clone())
    }

    fn _fast_call_inner_no_value(
        &mut self,
        data: &[(EVMAddress, EVMAddress, Bytes)],
        vm_state: &EVMState,
        state: &mut EVMFuzzState,
    ) -> (Vec<(Vec<u8>, bool)>, EVMState) {
        self.host.evmstate = vm_state.clone();

        init_host!(self.host);
        let res = data
            .iter()
            .map(|(caller, address, by)| {
                execute_call_single!(*caller, address, EVMU256::ZERO, self.host, state, by)
            })
            .collect::<Vec<(Vec<u8>, bool)>>();
        (res, self.host.evmstate.clone())
    }
}

pub static mut IN_DEPLOY: bool = false;
pub static mut SETCODE_ONLY: bool = false;

impl<VS, CI, SC> GenericVM<VS, Bytecode, Bytes, EVMAddress, EVMAddress, EVMU256, Vec<u8>, EVMInput, EVMFuzzState, CI>
    for EVMExecutor<VS, CI, SC>
where
    VS: VMStateT + Default + 'static,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
    SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
{
    /// Deploy a contract
    fn deploy(
        &mut self,
        code: Bytecode,
        constructor_args: Option<Bytes>,
        deployed_address: EVMAddress,
        state: &mut EVMFuzzState,
    ) -> Option<EVMAddress> {
        debug!("deployer = 0x{} ", hex::encode(self.deployer));
        let calldata = PrimBytes::copy_from_slice(constructor_args.unwrap_or_default().as_ref());
        let interp_input = InputsImpl {
            target_address: deployed_address,
            bytecode_address: Some(deployed_address),
            caller_address: self.deployer,
            input: CallInput::Bytes(calldata),
            call_value: EVMU256::ZERO,
        };
        // disable middleware for deployment
        unsafe {
            IN_DEPLOY = true;
        }
        let mut interp = Interpreter::new(
            SharedMemory::new_with_memory_limit(MEM_LIMIT),
            ExtBytecode::new(code),
            interp_input,
            false,
            SpecId::PRAGUE,
            1e10 as u64,
        );
        let mut dummy_state = EVMFuzzState::default();
        let r = self.host.run_inspect(&mut interp, &mut dummy_state);
        unsafe {
            IN_DEPLOY = false;
        }
        if r != InstructionResult::Return {
            println!("DEPLOY FAILED: {:?}", r);
            error!("deploy failed: {:?}", r);
            return None;
        }
        let runtime_bytes: PrimBytes = interp.return_data.buffer().clone();
        let mut contract_code = Bytecode::new_raw(runtime_bytes);
        bytecode_analyzer::add_analysis_result_to_state(&contract_code, state);
        unsafe {
            invoke_middlewares!(
                &mut self.host,
                Some(&mut interp),
                state,
                on_insert,
                &mut contract_code,
                deployed_address
            );
        }
        self.host.set_code(deployed_address, contract_code, state);
        Some(deployed_address)
    }

    /// Execute an input (can be transaction or borrow)
    fn execute(
        &mut self,
        input: &EVMInput,
        state: &mut EVMFuzzState,
    ) -> ExecutionResult<EVMAddress, EVMAddress, VS, Vec<u8>, CI> {
        use super::host::clear_branch_status;
        clear_branch_status();
        match input.get_input_type() {
            // buy (borrow because we have infinite ETH) tokens with ETH using uniswap
            EVMInputTy::Borrow => {
                let token = input.get_contract();
                let token_ctx = {
                    let flashloan_mid = self.host.flashloan_middleware.as_ref().unwrap().deref().borrow();
                    let flashloan_oracle = flashloan_mid.flashloan_oracle.deref().borrow();
                    flashloan_oracle
                        .known_tokens
                        .borrow()
                        .get(&token)
                        .unwrap_or_else(|| panic!("unknown token : {:?}", token))
                        .clone()
                };
                self.host.evmstate = VMStateT::as_any(input.get_state())
                    .downcast_ref::<EVMState>()
                    .unwrap()
                    .clone();
                match token_ctx.buy(
                    input.get_txn_value().unwrap(),
                    input.get_caller(),
                    state,
                    self,
                    input.get_randomness().as_slice(),
                ) {
                    Some(()) => ExecutionResult {
                        output: vec![],
                        reverted: false,
                        new_state: StagedVMState::new_with_state(
                            VMStateT::as_any(&self.host.evmstate.clone())
                                .downcast_ref::<VS>()
                                .unwrap()
                                .clone(),
                        ),
                        additional_info: None,
                    },
                    None => ExecutionResult {
                        // we don't have enough liquidity to buy the token
                        output: vec![],
                        reverted: true,
                        new_state: StagedVMState::new_with_state(
                            VMStateT::as_any(input.get_state())
                                .downcast_ref::<VS>()
                                .unwrap()
                                .clone(),
                        ),
                        additional_info: None,
                    },
                }
            }
            EVMInputTy::Liquidate => {
                unreachable!("liquidate should be handled by middleware");
            }
            EVMInputTy::ABI => self.execute_abi(input, state),
            EVMInputTy::ArbitraryCallBoundedAddr => self.execute_abi(input, state),
        }
    }

    /// Execute a static call
    fn fast_static_call(
        &mut self,
        data: &[(EVMAddress, Bytes)],
        vm_state: &VS,
        state: &mut EVMFuzzState,
    ) -> Vec<Vec<u8>> {
        unsafe {
            IS_FAST_CALL_STATIC = true;
            self.host.evmstate = vm_state.as_any().downcast_ref::<EVMState>().unwrap().clone();
            self.host.transient_storage = HashMap::new();
            self.host.current_self_destructs = vec![];
            self.host.current_arbitrary_calls = vec![];
            self.host.current_arbitrary_transfers = vec![];
            self.host.call_count = 0;
            self.host.jumpi_trace = 37;
            self.host.current_typed_bug = vec![];
            self.host.randomness = vec![9];
        }

        let res = data
            .iter()
            .map(|(address, by)| {
                let code = self.host.code.get(address).expect("no code").clone();
                let interp_input = InputsImpl {
                    target_address: *address,
                    bytecode_address: Some(*address),
                    caller_address: EVMAddress::default(),
                    input: CallInput::Bytes(PrimBytes::copy_from_slice(by.as_ref())),
                    call_value: EVMU256::ZERO,
                };
                let mut interp = Interpreter::new(
                    SharedMemory::new_with_memory_limit(MEM_LIMIT),
                    ExtBytecode::new((*code).clone()),
                    interp_input,
                    true,
                    SpecId::PRAGUE,
                    1e10 as u64,
                );
                let ret = self.host.run_inspect(&mut interp, state);
                if is_call_success!(ret) {
                    interp.return_data.buffer().to_vec()
                } else {
                    vec![]
                }
            })
            .collect::<Vec<Vec<u8>>>();

        unsafe {
            IS_FAST_CALL_STATIC = false;
        }
        res
    }

    /// Execute a static call
    fn fast_call(
        &mut self,
        data: &[(EVMAddress, EVMAddress, Bytes)],
        vm_state: &VS,
        state: &mut EVMFuzzState,
    ) -> (Vec<(Vec<u8>, bool)>, VS) {
        unsafe {
            // IS_FAST_CALL = true;
            self.host.evmstate = vm_state.as_any().downcast_ref::<EVMState>().unwrap().clone();
        }
        init_host!(self.host);

        // self.host.add_middlewares(middleware.clone());

        let res = data
            .iter()
            .map(|(caller, address, by)| {
                let res = execute_call_single!(*caller, address, EVMU256::ZERO, self.host, state, by);
                if let Some((_, _, r)) = self.host.check_assert_result() {
                    return (r.to_vec(), false);
                }
                res
            })
            .collect::<Vec<(Vec<u8>, bool)>>();

        (res, unsafe {
            self.host.evmstate.as_any().downcast_ref::<VS>().unwrap().clone()
        })
    }

    fn get_jmp(&self) -> &'static mut [u8; MAP_SIZE] {
        unsafe { &mut JMP_MAP }
    }

    fn get_read(&self) -> &'static mut [bool; MAP_SIZE] {
        unsafe { &mut READ_MAP }
    }

    fn get_write(&self) -> &'static mut [u8; MAP_SIZE] {
        unsafe { &mut WRITE_MAP }
    }

    fn get_cmp(&self) -> &'static mut [EVMU256; MAP_SIZE] {
        unsafe { &mut CMP_MAP }
    }

    fn state_changed(&self) -> bool {
        unsafe { STATE_CHANGE }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashMap, path::Path, rc::Rc};

    use bytes::Bytes;
    use libafl::prelude::StdScheduler;
    use libafl_bolts::tuples::tuple_list;
    use revm_interpreter::bytecode::Bytecode;
    use tracing::debug;

    use crate::{
        evm::{
            host::{FuzzHost, JMP_MAP},
            input::{ConciseEVMInput, EVMInput, EVMInputTy, NestedAction},
            mutator::AccessPattern,
            types::{fixed_address, generate_random_address, EVMFuzzState, EVMU256, Env},
            vm::{EVMExecutor, EVMState},
        },
        generic_vm::vm_executor::{GenericVM, MAP_SIZE},
        state::FuzzState,
        state_input::StagedVMState,
    };

    #[test]
    fn test_fuzz_executor() {
        let mut state: EVMFuzzState = FuzzState::new(0);
        let path = Path::new("work_dir");
        if !path.exists() {
            std::fs::create_dir(path).unwrap();
        }
        let mut evm_executor: EVMExecutor<EVMState, ConciseEVMInput, StdScheduler<EVMFuzzState>> = EVMExecutor::new(
            FuzzHost::new(StdScheduler::new(), "work_dir".to_string()),
            generate_random_address(&mut state),
        );
        tuple_list!();
        let _vm_state = EVMState::new();

        /*
        contract main {
            function process(uint8 a) public {
                require(a < 2, "2");
            }
        }
        */
        let deployment_bytecode = hex::decode("608060405234801561001057600080fd5b506102ad806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c806390b6e33314610030575b600080fd5b61004a60048036038101906100459190610123565b610060565b60405161005791906101e9565b60405180910390f35b606060028260ff16106100a8576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161009f90610257565b60405180910390fd5b6040518060400160405280600f81526020017f48656c6c6f20436f6e74726163747300000000000000000000000000000000008152509050919050565b600080fd5b600060ff82169050919050565b610100816100ea565b811461010b57600080fd5b50565b60008135905061011d816100f7565b92915050565b600060208284031215610139576101386100e5565b5b60006101478482850161010e565b91505092915050565b600081519050919050565b600082825260208201905092915050565b60005b8381101561018a57808201518184015260208101905061016f565b83811115610199576000848401525b50505050565b6000601f19601f8301169050919050565b60006101bb82610150565b6101c5818561015b565b93506101d581856020860161016c565b6101de8161019f565b840191505092915050565b6000602082019050818103600083015261020381846101b0565b905092915050565b7f3200000000000000000000000000000000000000000000000000000000000000600082015250565b600061024160018361015b565b915061024c8261020b565b602082019050919050565b6000602082019050818103600083015261027081610234565b905091905056fea264697066735822122025c2570c6b62c0201c750ff809bdc45aad0eae99133699dec80912878b9cc33064736f6c634300080f0033").unwrap();

        let deployment_loc = evm_executor
            .deploy(
                Bytecode::new_raw(revm_primitives::Bytes::from(deployment_bytecode)),
                None,
                generate_random_address(&mut state),
                &mut FuzzState::new(0),
            )
            .unwrap();

        debug!("deployed to address: {:?}", deployment_loc);

        let function_hash = hex::decode("90b6e333").unwrap();

        let input_0 = EVMInput {
            caller: generate_random_address(&mut state),
            contract: deployment_loc,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            liquidation_percent: 0,
            direct_data: Bytes::from(
                [
                    function_hash.clone(),
                    hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                ]
                .concat(),
            ),
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
            swap_data: HashMap::new(),
            nested_actions: Vec::new(),
        };

        let mut state = FuzzState::new(0);

        // process(0)
        let execution_result_0 = evm_executor.execute(&input_0, &mut state);
        let mut know_map: Vec<u8> = vec![0; MAP_SIZE];

        for i in 0..MAP_SIZE {
            know_map[i] = unsafe { JMP_MAP[i] };
            unsafe { JMP_MAP[i] = 0 };
        }
        assert!(!execution_result_0.reverted);

        // process(5)

        let input_5 = EVMInput {
            caller: generate_random_address(&mut state),
            contract: deployment_loc,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            liquidation_percent: 0,
            direct_data: Bytes::from(
                [
                    function_hash.clone(),
                    hex::decode("0000000000000000000000000000000000000000000000000000000000000005").unwrap(),
                ]
                .concat(),
            ),
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
            swap_data: HashMap::new(),
            nested_actions: Vec::new(),
        };

        let execution_result_5 = evm_executor.execute(&input_5, &mut state);

        // checking cmp map about coverage
        let mut cov_changed = false;
        for i in 0..MAP_SIZE {
            let hit = unsafe { JMP_MAP[i] };
            if hit != know_map[i] && hit != 0 {
                debug!("jmp_map[{}] = known: {}; new: {}", i, know_map[i], hit);
                unsafe { JMP_MAP[i] = 0 };
                cov_changed = true;
            }
        }
        assert!(cov_changed);
        assert!(cov_changed);
        assert!(execution_result_5.reverted);
    }

    #[test]
    fn test_attacker_contract_callbacks() {
        let mut state: EVMFuzzState = FuzzState::new(0);
        let path = Path::new("work_dir");
        if !path.exists() {
            std::fs::create_dir(path).unwrap();
        }
        let mut evm_executor: EVMExecutor<EVMState, ConciseEVMInput, StdScheduler<EVMFuzzState>> = EVMExecutor::new(
            FuzzHost::new(StdScheduler::new(), "work_dir".to_string()),
            generate_random_address(&mut state),
        );
        tuple_list!();

        // 1. Deploy CallbackTest contract
        let callback_test_bytecode = hex::decode("6101b680600c6000396000f3608060405234801561000f575f80fd5b506004361061003f575f3560e01c80633f09775e14610043578063507976da14610063578063b4d401d714610076575b5f80fd5b5f5461004f9060ff1681565b604051901515815260200160405180910390f35b6100745f805460ff19166001179055565b005b604080515f6024820181905260448201819052606482018190526080608483015260a48083018290528351808403909101815260c490920183526020820180516001600160e01b0316630a85bd0160e11b9081179091529251610074939233916100e09190610169565b5f604051808303815f865af19150503d805f8114610119576040519150601f19603f3d011682016040523d82523d5f602084013e61011e565b606091505b50509050806101655760405162461bcd60e51b815260206004820152600f60248201526e10d85b1b189858dac819985a5b1959608a1b604482015260640160405180910390fd5b5050565b5f82518060208501845e5f92019182525091905056fea2646970667358221220391c3dc473772be67d9285292f5d55e3b4cf18c62d4efd5e85836e678a51511264736f6c634300081a0033").unwrap();
        
        let callback_test_addr = evm_executor
            .deploy(
                Bytecode::new_raw(revm_primitives::Bytes::from(callback_test_bytecode)),
                None,
                generate_random_address(&mut state),
                &mut FuzzState::new(0),
            )
            .unwrap();

        // 2. Set code and balance on the attacker address
        let attacker_addr = fixed_address("e1A425f1AC34A8a441566f93c82dD730639c8510");
        let attacker_bytecode_hex = "608060405260043610610073575f3560e01c8063bc197c811161004d578063bc197c8114610126578063f23a6e6114610145578063fa461e3314610164578063fadc6f3d146101835761007a565b8063150b7a02146100845780638da5cb5b146100c1578063920f5c84146100f75761007a565b3661007a57005b6100826101a6565b005b34801561008f575f80fd5b506100a361009e3660046104e2565b61026c565b6040516001600160e01b031990911681526020015b60405180910390f35b3480156100cc575f80fd5b505f546100df906001600160a01b031681565b6040516001600160a01b0390911681526020016100b8565b348015610102575f80fd5b5061011661011136600461058b565b610287565b60405190151581526020016100b8565b348015610131575f80fd5b506100a3610140366004610668565b610392565b348015610150575f80fd5b506100a361015f366004610724565b6103b0565b34801561016f575f80fd5b5061008261017e366004610796565b6103cc565b34801561018e575f80fd5b506101976103da565b6040516100b8939291906107e4565b5f806101b06103da565b5090925090506001600160a01b03821615610268575f826001600160a01b0316826040516101de919061082f565b5f604051808303815f865af19150503d805f8114610217576040519150601f19603f3d011682016040523d82523d5f602084013e61021c565b606091505b50509050806102665760405162461bcd60e51b815260206004820152601260248201527114dd1859d9590818d85b1b0819985a5b195960721b604482015260640160405180910390fd5b505b5050565b5f6102756101a6565b50630a85bd0160e11b95945050505050565b5f6102906101a6565b5f5b89811015610381578a8a828181106102ac576102ac610845565b90506020020160208101906102c19190610859565b6001600160a01b031663095ea7b3338989858181106102e2576102e2610845565b905060200201358c8c868181106102fb576102fb610845565b9050602002013561030c9190610879565b6040516001600160e01b031960e085901b1681526001600160a01b03909216600483015260248201526044016020604051808303815f875af1158015610354573d5f803e3d5ffd5b505050506040513d601f19601f82011682018060405250810190610378919061089e565b50600101610292565b5060019a9950505050505050505050565b5f61039b6101a6565b5063bc197c8160e01b98975050505050505050565b5f6103b96101a6565b5063f23a6e6160e01b9695505050505050565b6103d46101a6565b50505050565b5f805461270f54909160609180820361040757505060408051602081019091525f80825293909250839150565b806001600160401b0381111561041f5761041f6108bd565b6040519080825280601f01601f191660200182016040528015610449576020820181803683370190505b5092505f5b8181101561047757602080820461271001548583018201526104709082610879565b905061044e565b5092939192505f919050565b80356001600160a01b0381168114610499575f80fd5b919050565b5f8083601f8401126104ae575f80fd5b5081356001600160401b038111156104c4575f80fd5b6020830191508360208285010111156104db575f80fd5b9250929050565b5f805f805f608086880312156104f6575f80fd5b6104ff86610483565b945061050d60208701610483565b93506040860135925060608601356001600160401b0381111561052e575f80fd5b61053a8882890161049e565b969995985093965092949392505050565b5f8083601f84011261055b575f80fd5b5081356001600160401b03811115610571575f80fd5b6020830191508360208260051b85010111156104db575f80fd5b5f805f805f805f805f60a08a8c0312156105a3575f80fd5b89356001600160401b038111156105b8575f80fd5b6105c48c828d0161054b565b909a5098505060208a01356001600160401b038111156105e2575f80fd5b6105ee8c828d0161054b565b90985096505060408a01356001600160401b0381111561060c575f80fd5b6106188c828d0161054b565b909650945061062b905060608b01610483565b925060808a01356001600160401b03811115610645575f80fd5b6106518c828d0161049e565b915080935050809150509295985092959850929598565b5f805f805f805f8060a0898b03121561067f575f80fd5b61068889610483565b975061069660208a01610483565b965060408901356001600160401b038111156106b0575f80fd5b6106bc8b828c0161054b565b90975095505060608901356001600160401b038111156106da575f80fd5b6106e68b828c0161054b565b90955093505060808901356001600160401b03811115610704575f80fd5b6107108b828c0161049e565b999c989b5096995094979396929594505050565b5f805f805f8060a08789031215610739575f80fd5b61074287610483565b955061075060208801610483565b9450604087013593506060870135925060808701356001600160401b03811115610778575f80fd5b61078489828a0161049e565b979a9699509497509295939492505050565b5f805f80606085870312156107a9575f80fd5b843593506020850135925060408501356001600160401b038111156107cc575f80fd5b6107d88782880161049e565b95989497509550505050565b60018060a01b0384168152606060208201525f83518060608401528060208601608085015e5f608082850101526080601f19601f830116840101915050826040830152949350505050565b5f82518060208501845e5f920191825250919050565b634e487b7160e01b5f52603260045260245ffd5b5f60208284031215610869575f80fd5b61087282610483565b9392505050565b8082018082111561089857634e487b7160e01b5f52601160045260245ffd5b92915050565b5f602082840312156108ae575f80fd5b81518015158114610872575f80fd5b634e487b7160e01b5f52604160045260245ffdfea26469706673582212204aed32947684c442253e6dcea8ce62e068df49e6268b7e16d0abaf30ea8eeed864736f6c634300081a0033";
        let attacker_bytecode = hex::decode(attacker_bytecode_hex).unwrap();
        
        evm_executor.host.set_code(
            attacker_addr,
            Bytecode::new_raw(revm_primitives::Bytes::from(attacker_bytecode)),
            &mut state,
        );
        evm_executor.host.evmstate.set_balance(attacker_addr, EVMU256::from(10000000000000000000_u128));
        // 3. Construct input targeting CallbackTest.triggerCallback()
        // with a NestedAction targeting CallbackTest.flagReentered()
        let trigger_callback_hash = hex::decode("b4d401d7").unwrap();
        let flag_reentered_hash = hex::decode("507976da").unwrap();
        
        let nested_action = NestedAction {
            target: callback_test_addr,
            calldata: bytes::Bytes::from(flag_reentered_hash),
            value: EVMU256::ZERO,
        };

        let input = EVMInput {
            caller: attacker_addr,
            contract: callback_test_addr,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            liquidation_percent: 0,
            direct_data: Bytes::from(trigger_callback_hash),
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
            swap_data: HashMap::new(),
            nested_actions: vec![nested_action],
        };

        // 4. Execute the call
        let result = evm_executor.execute(&input, &mut state);
        assert!(!result.reverted, "Execution of triggerCallback() reverted: {:?}", result);

        // 5. Verify reentered flag is set to true on CallbackTest
        // Let's call CallbackTest.reentered() (selector 3f09775e)
        // Carry forward the execution state so reentered = true persists
        let reentered_hash = hex::decode("3f09775e").unwrap();
        let mut input_query = EVMInput {
            caller: attacker_addr,
            contract: callback_test_addr,
            data: None,
            sstate: result.new_state,
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            liquidation_percent: 0,
            direct_data: Bytes::from(reentered_hash),
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
            swap_data: HashMap::new(),
            nested_actions: Vec::new(),
        };

        let query_result = evm_executor.execute(&input_query, &mut state);
        assert!(!query_result.reverted, "Querying reentered reverted");

        // Decode return data. It should be a 32-byte word with value 1 (true)
        let mut expected_output = vec![0; 32];
        expected_output[31] = 1;
        assert_eq!(query_result.output, expected_output);
    }

    #[test]
    fn test_warp_delta_sync_for_oracle_staleness() {
        let mut state: EVMFuzzState = FuzzState::new(0);
        let path = Path::new("work_dir");
        if !path.exists() {
            std::fs::create_dir(path).unwrap();
        }
        let mut evm_executor: EVMExecutor<EVMState, ConciseEVMInput, StdScheduler<EVMFuzzState>> = EVMExecutor::new(
            FuzzHost::new(StdScheduler::new(), "work_dir".to_string()),
            generate_random_address(&mut state),
        );
        tuple_list!();

        // 1. Deploy mock oracle contract exposing latestRoundData (0xfeaf968c)
        // bytecode for a simple contract returning:
        // roundId = 0, answer = 0, startedAt = 1000, updatedAt = 1000, answeredInRound = 0
        // Selector 0xfeaf968c
        let mock_oracle_bytecode = hex::decode("601180600b6000396000f36103e86040526103e860605260a06000f3").unwrap();
        let mock_oracle_addr = evm_executor
            .deploy(
                Bytecode::new_raw(revm_primitives::Bytes::from(mock_oracle_bytecode)),
                None,
                generate_random_address(&mut state),
                &mut FuzzState::new(0),
            )
            .unwrap();

        // Register code in host
        evm_executor.host.set_code(
            mock_oracle_addr,
            Bytecode::new_raw(revm_primitives::Bytes::from(hex::decode("6103e86040526103e860605260a06000f3").unwrap())),
            &mut state,
        );

        // 2. Deploy caller contract
        let caller_bytecode = hex::decode("603b80600b6000396000f37ffeaf968c0000000000000000000000000000000000000000000000000000000000000060805260003560a060006004608084620f4240fa5060a06000f3").unwrap();
        let caller_addr = evm_executor
            .deploy(
                Bytecode::new_raw(revm_primitives::Bytes::from(caller_bytecode)),
                None,
                generate_random_address(&mut state),
                &mut FuzzState::new(0),
            )
            .unwrap();

        evm_executor.host.set_code(
            caller_addr,
            Bytecode::new_raw(revm_primitives::Bytes::from(hex::decode("7ffeaf968c0000000000000000000000000000000000000000000000000000000060805260003560a060006004608084620f4240fa5060a06000f3").unwrap())),
            &mut state,
        );

        // 3. Call caller contract Y with X in calldata, with warping
        let mut calldata = vec![0; 32];
        calldata[12..32].copy_from_slice(mock_oracle_addr.as_slice());

        let mut env = Env::default();
        env.block.timestamp = EVMU256::from(2000);
        env.is_staleness_test = false;

        let input = EVMInput {
            caller: generate_random_address(&mut state),
            contract: caller_addr,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env,
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            liquidation_percent: 0,
            direct_data: Bytes::from(calldata.clone()),
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
            swap_data: HashMap::new(),
            nested_actions: Vec::new(),
        };

        // Explicitly set initial block timestamp on the executor's host
        evm_executor.host.initial_block_timestamp = Some(EVMU256::from(1000));

        let res = evm_executor.execute(&input, &mut state);
        assert!(!res.reverted);
        assert_eq!(res.output.len(), 160);

        // Parse round data: updatedAt is the 4th slot (offset 96..128)
        let updated_at = EVMU256::try_from_be_slice(&res.output[96..128]).unwrap();
        assert_eq!(updated_at, EVMU256::from(2000), "updatedAt must be adjusted by warp delta (1000)");

        // 4. Call again with is_staleness_test = true. Output should NOT be synced, returned as original 1000.
        let mut env_stale = Env::default();
        env_stale.block.timestamp = EVMU256::from(2000);
        env_stale.is_staleness_test = true;

        let input_stale = EVMInput {
            caller: generate_random_address(&mut state),
            contract: caller_addr,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: env_stale,
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            liquidation_percent: 0,
            direct_data: Bytes::from(calldata),
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
            swap_data: HashMap::new(),
            nested_actions: Vec::new(),
        };

        let res_stale = evm_executor.execute(&input_stale, &mut state);
        assert!(!res_stale.reverted);
        assert_eq!(res_stale.output.len(), 160);

        let updated_at_stale = EVMU256::try_from_be_slice(&res_stale.output[96..128]).unwrap();
        assert_eq!(updated_at_stale, EVMU256::from(1000), "updatedAt must not be adjusted when is_staleness_test is true");
    }
}
 

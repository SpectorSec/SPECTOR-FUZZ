use bytes::Bytes;
use crypto::{digest::Digest, sha3::Sha3};
use libafl::prelude::HasRand;
use libafl_bolts::bolts_prelude::{Rand, RomuDuoJrRand};
use primitive_types::H160;
use revm_context::{BlockEnv, CfgEnv, TxEnv};
use revm_interpreter::bytecode::Bytecode;
use revm_primitives::{hardfork::SpecId, ruint::aliases::U512, Address, U256};
use serde::{Deserialize, Serialize};

/// SpecId re-export for callers that previously used `revm_primitives::SpecId`
pub use revm_primitives::hardfork::SpecId as EVMSpecId;

/// Shim that mirrors the old `revm_primitives::Env` { cfg, block, tx } API.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Env {
    pub cfg: CfgEnv,
    pub block: BlockEnv,
    pub tx: TxEnv,
}

/// Common generic types for EVM fuzzing
use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::{
    evm::{
        mutator::FuzzMutator,
        scheduler::PowerABIScheduler,
        vm::{EVMExecutor, EVMState},
    },
    executor::FuzzExecutor,
    generic_vm::vm_executor::ExecutionResult,
    oracle::OracleCtx,
    scheduler::SortedDroppingScheduler,
    state::{FuzzState, InfantStateState},
    state_input::StagedVMState,
};

pub type EVMAddress = Address;
pub type EVMU256 = U256;
pub type EVMU512 = U512;
pub type EVMFuzzState = FuzzState<EVMInput, EVMState, EVMAddress, EVMAddress, Vec<u8>, ConciseEVMInput>;
pub type EVMOracleCtx<'a> = OracleCtx<
    'a,
    EVMState,
    EVMAddress,
    Bytecode,
    Bytes,
    EVMAddress,
    EVMU256,
    Vec<u8>,
    EVMInput,
    EVMFuzzState,
    ConciseEVMInput,
    EVMQueueExecutor,
>;
pub type EVMFuzzMutator<'a> = FuzzMutator<
    EVMState,
    EVMAddress,
    EVMAddress,
    SortedDroppingScheduler<InfantStateState<EVMAddress, EVMAddress, EVMState, ConciseEVMInput>>,
    ConciseEVMInput,
>;

pub type EVMInfantStateState = InfantStateState<EVMAddress, EVMAddress, EVMState, ConciseEVMInput>;

pub type EVMStagedVMState = StagedVMState<EVMAddress, EVMAddress, EVMState, ConciseEVMInput>;

pub type EVMExecutionResult = ExecutionResult<EVMAddress, EVMAddress, EVMState, Vec<u8>, ConciseEVMInput>;

pub type EVMFuzzExecutor<OT> = FuzzExecutor<
    EVMState,
    EVMAddress,
    Bytecode,
    Bytes,
    EVMAddress,
    EVMU256,
    Vec<u8>,
    EVMInput,
    EVMFuzzState,
    OT,
    ConciseEVMInput,
>;

pub type EVMQueueExecutor = EVMExecutor<EVMState, ConciseEVMInput, PowerABIScheduler<EVMFuzzState>>;

/// convert array of 20x u8 to H160
pub fn convert_h160(v: [u8; 20]) -> H160 {
    v.into()
}

/// convert U256 to H160 by taking the last 20 bytes
pub fn convert_u256_to_h160(v: EVMU256) -> EVMAddress {
    let data: [u8; 32] = v.to_be_bytes();
    EVMAddress::from_slice(&data[12..32])
}

/// multiply a float by 10^decimals and convert to U512
pub fn float_scale_to_u512(v: f64, decimals: u32) -> U512 {
    // todo(@shou) make this sound
    let mut temp = v;
    for _ in 0..decimals {
        temp *= 10.0;
    }
    U512::from(temp as u64)
}

/// Generate a random H160 address.
pub fn generate_random_address<S>(s: &mut S) -> EVMAddress
where
    S: HasRand,
{
    let mut bytes = [0u8; 20];
    for chunk in bytes.chunks_mut(8) {
        let val = s.rand_mut().next().to_le_bytes();
        chunk.copy_from_slice(&val[..chunk.len()]);
    }
    EVMAddress::from(bytes)
}

/// Generate a fixed H160 address from a hex string.
pub fn fixed_address(s: &str) -> EVMAddress {
    let mut address = EVMAddress::ZERO;
    address.0.copy_from_slice(&hex::decode(s).unwrap());
    address
}

/// Check is EVMU256 is zero
pub fn is_zero(v: EVMU256) -> bool {
    v == EVMU256::ZERO
}

/// As u64
pub fn as_u64(v: EVMU256) -> u64 {
    v.as_limbs()[0]
}

/// Convert big endian bytes to u64
pub fn bytes_to_u64(v: &[u8]) -> u64 {
    let mut data: [u8; 8] = [0; 8];
    data.copy_from_slice(v);
    u64::from_be_bytes(data)
}

/// EVMAddress to checksum address
pub fn checksum(address: &EVMAddress) -> String {
    let address = hex::encode(address);

    let address_hash = {
        let mut hasher = Sha3::keccak256();
        hasher.input(address.as_bytes());
        hasher.result_str()
    };

    address
        .char_indices()
        .fold(String::from("0x"), |mut acc, (index, address_char)| {
            // this cannot fail since it's Keccak256 hashed
            let n = u16::from_str_radix(&address_hash[index..index + 1], 16).unwrap();

            if n > 7 {
                // make char uppercase if ith character is 9..f
                acc.push_str(&address_char.to_uppercase().to_string())
            } else {
                // already lowercased
                acc.push(address_char)
            }

            acc
        })
}

#[cfg(test)]
mod tests {
    use crate::evm::types::{as_u64, EVMU256};

    #[test]
    fn test_as_u64() {
        assert_eq!(as_u64(EVMU256::from(100)), 100)
    }
}

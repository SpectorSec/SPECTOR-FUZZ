// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ERC-20 where the balance mapping is at slot 6 (not the usual slot 0).
// Uses fixed-size types for deterministic storage layout:
//   slot 0: balances (mapping) — shift to slot 6 by padding
//   slot 1-5: padding
//   slot 6: _balances
//
// The slot detector must find slot 6 and pre-seed balances there.
contract NonStandardSlotERC20 {
    mapping(address => uint256) public _balances;  // slot 0 (but see below)
    uint256[5] __paddings;                          // slots 1-5
    // _balances actually ends up at slot 0, not 6!

    // Actually, let's use assembly to force storage at slot 6
    function balanceOf(address account) public view returns (uint256) {
        uint256 val;
        assembly {
            mstore(0, account)
            mstore(32, 6)          // slot 6
            val := sload(keccak256(0, 64))
        }
        return val;
    }

    function mint(address to, uint256 amount) public {
        assembly {
            mstore(0, to)
            mstore(32, 6)
            let slot := keccak256(0, 64)
            sstore(slot, add(sload(slot), amount))
        }
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        assembly {
            mstore(0, caller())
            mstore(32, 6)
            let senderSlot := keccak256(0, 64)
            let senderBal := sload(senderSlot)
            if lt(senderBal, amount) { revert(0, 0) }
            sstore(senderSlot, sub(senderBal, amount))

            mstore(0, to)
            mstore(32, 6)
            sstore(keccak256(0, 64), add(sload(keccak256(0, 64)), amount))
        }
        return true;
    }

    function totalSupply() public pure returns (uint256) { return type(uint256).max; }
    function name() public pure returns (string memory) { return "NonStandardSlot"; }
    function symbol() public pure returns (string memory) { return "NSS"; }
    function decimals() public pure returns (uint8) { return 18; }
}

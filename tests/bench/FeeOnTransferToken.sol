// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Token that takes a 0.1% fee on every transfer (like STA / PAXG).
// Tests the fee-on-transfer oracle: the fuzzer must account for the
// discrepancy between transfer amount and actual balance change.
contract FeeOnTransferToken {
    string public name = "Fee Token";
    string public symbol = "FEE";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    uint256 public constant FEE_NUM = 1;
    uint256 public constant FEE_DENOM = 1000;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        uint256 fee = amount * FEE_NUM / FEE_DENOM;
        uint256 net = amount - fee;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += net;
        balanceOf[address(0)] += fee;
        emit Transfer(msg.sender, to, net);
        return true;
    }
}

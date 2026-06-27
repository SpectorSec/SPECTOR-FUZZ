// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Mock staking contract with time-based reward accumulation.
/// Used by the Temporal Pre-condition Skimming integration test.
/// The exploit pattern:
///   1. Prime: deposit() — user stakes tokens
///   2. Warp(N blocks): rewards accumulate off-screen (rewardRate * elapsed)
///   3. Exploit: claim() — user claims based on stale state divergence
///   With --temporal-skimming: the planner inserts a warp between deposit and
///   claim, exposing the reward divergence. Without: single-transaction campaign
///   cannot reproduce the multi-block reward accumulation.
contract TemporalSkimMock {
    uint256 public rewardRate = 1 ether;
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public lastUpdateBlock;

    event Deposited(address indexed user, uint256 amount);
    event Claimed(address indexed user, uint256 reward);

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        lastUpdateBlock[msg.sender] = block.number;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Claim rewards accrued since last deposit.
    /// The reward depends on block.number - lastUpdateBlock, which changes
    /// across the warp boundary.
    function claim() external returns (uint256) {
        uint256 elapsed = block.number - lastUpdateBlock[msg.sender];
        uint256 reward = deposits[msg.sender] * rewardRate * elapsed / 1e18;
        deposits[msg.sender] = 0;
        emit Claimed(msg.sender, reward);
        return reward;
    }
}

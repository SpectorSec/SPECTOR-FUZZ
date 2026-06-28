// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
/// Self-priming accrual: reward grows from a constructor-set start block, needs NO
/// deposit. Isolates the warp-secant from campaign funding/sequencing so it can be
/// validated live. rate=7 (not 1) => df/d(warp)=7, a real accrual test the naive
/// "warp = abs_diff" gets 7x wrong; the secant must recover the factor.
contract AccrualSelfPrimedMock {
    uint256 public immutable start;
    uint256 public constant RATE = 7;
    uint256 public constant THRESHOLD = 35000; // flip at elapsed = 5000 blocks
    bool public jackpotHit;
    constructor() { start = block.number; }
    function claimJackpot() external {
        uint256 reward = (block.number - start) * RATE;
        require(reward >= THRESHOLD, "not accrued"); // temporal threshold the secant aims
        jackpotHit = true;
    }
    function ping() external {} // 2nd function so generic recognition fires
}

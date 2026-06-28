// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Mock whose payout is gated by a TIME-DEPENDENT THRESHOLD comparison —
/// the fixture that validates the Application C snapshot-secant (Feature 008).
///
/// `deposit(amount)` credits a fuzzable stake via CALLDATA (no msg.value, so no
/// flashloan/value funding is needed for the campaign to make stake > 0). The
/// reward keeps the MULTIPLICATION (stake · rate · elapsed) so this is a real
/// accrual test: df/d(elapsed) = stake·rate/1e18, NOT 1 — the secant must
/// recover that factor empirically, which a naive "warp = abs_diff" cannot.
///
/// Validation signal: BRANCH COVERAGE. The secant must drive `block.number` far
/// enough that `reward >= THRESHOLD` flips, entering the jackpot branch
/// (`jackpotHit = true`). No external call / value transfer (that path trips a
/// pre-existing revm-41 shared-memory OOB unrelated to this feature).
contract AccrualThresholdMock {
    uint256 public constant THRESHOLD = 1000 ether;
    uint256 public rewardRate = 1 ether; // per block, per unit stake / 1e18

    mapping(address => uint256) public stake;
    mapping(address => uint256) public lastUpdateBlock;
    bool public jackpotHit; // observable success flag (post-threshold branch)

    event Deposited(address indexed user, uint256 amount);
    event JackpotClaimed(address indexed user, uint256 reward);

    /// @notice Credit a fuzzable stake (calldata arg — no value needed).
    function deposit(uint256 amount) external {
        stake[msg.sender] += amount;
        lastUpdateBlock[msg.sender] = block.number;
        emit Deposited(msg.sender, amount);
    }

    /// @notice Linear-in-time reward gated by a threshold the secant aims at.
    function claimJackpot() external {
        uint256 elapsed = block.number - lastUpdateBlock[msg.sender];
        uint256 reward = stake[msg.sender] * rewardRate * elapsed / 1e18;
        // CMP_MAP target: distance to flip = THRESHOLD - reward (while failing).
        require(reward >= THRESHOLD, "not accrued");

        // Crossing the require = the secant found the right warp. Mark it.
        jackpotHit = true;
        stake[msg.sender] = 0;
        emit JackpotClaimed(msg.sender, reward);
    }
}

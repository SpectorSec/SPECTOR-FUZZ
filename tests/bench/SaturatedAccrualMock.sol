// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Mock whose reward accrues linearly but SATURATES at a cap. This
/// fixture validates the snapshot-secant's FLAT-GRADIENT self-diagnosis
/// (Feature 008, Checkpoint 8.5c): once `elapsed` exceeds `MAX_BLOCKS`, warping
/// further does not change `reward`, so the secant must measure a flat gradient
/// (D1 == D2 across the probe) and ABORT — it must NOT keep warping uselessly.
///
/// THRESHOLD is deliberately set ABOVE the maximum achievable reward, so the
/// gate can never flip via time. Expected behaviour:
///   - The secant probes block.number, observes that past the cap the distance
///     no longer moves (dd == 0), and gives up on time as the lever.
///   - No exploit is reported via this path, and no unbounded warping occurs.
///
/// Validation is behavioural (no found-bug, no warp blow-up), so check it via
/// run logs / iteration counts rather than an oracle hit.
contract SaturatedAccrualMock {
    uint256 public constant MAX_BLOCKS = 100; // accrual cap
    uint256 public constant THRESHOLD = 1_000_000 ether; // intentionally unreachable
    uint256 public rewardRate = 1 ether;

    mapping(address => uint256) public deposits;
    mapping(address => uint256) public lastUpdateBlock;
    bool public jackpotHit; // must stay false — proves flat-gradient self-diagnosis

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        lastUpdateBlock[msg.sender] = block.number;
    }

    function claimJackpot() external {
        uint256 elapsed = block.number - lastUpdateBlock[msg.sender];
        // Saturation: past MAX_BLOCKS, reward stops growing — gradient goes flat.
        uint256 capped = elapsed > MAX_BLOCKS ? MAX_BLOCKS : elapsed;
        uint256 reward = deposits[msg.sender] * rewardRate * capped / 1e18;
        require(reward >= THRESHOLD, "not accrued"); // unreachable: capped reward < THRESHOLD

        jackpotHit = true; // must NEVER be reached — secant should self-diagnose flat gradient
        deposits[msg.sender] = 0;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Mock contract with an onlyRouter-style access control guard.
/// Used by the Ghost Identities integration test to verify that the
/// fuzzer can spoof protocol contract identities (confused deputy).
/// - With --ghost-identities: the mutator discovers the router address
///   and injects vm.prank(router), reaching withdraw().
/// - Without --ghost-identities: only whale EOAs are used, so the
///   onlyRouter guard blocks withdraw() and the fuzzer cannot reach it.
contract GhostRouterMock {
    /// The only address authorized to call withdraw().
    address public immutable router;

    event Withdrawn(address indexed caller, uint256 amount);

    constructor(address _router) {
        router = _router;
    }

    /// @notice Guarded function — only the router address may call this.
    /// If an unauthorized caller reaches this without reverting, it is
    /// a permission leak (primitive 4).
    function withdraw(uint256 amount) external {
        require(msg.sender == router, "GhostRouterMock: only router");
        emit Withdrawn(msg.sender, amount);
    }

    /// @notice Public function — no access control, always reachable.
    function deposit() external pure returns (string memory) {
        return "deposited";
    }
}

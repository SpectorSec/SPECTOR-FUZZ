// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

/// Simple counter where the invariant "value > 0" can be violated by drain().
contract Counter {
    uint256 public value = 100;

    function drain() external {
        value = 0;
    }

    function invariant_value_positive() external view {
        require(value > 0, "invariant violated: value is zero");
    }
}

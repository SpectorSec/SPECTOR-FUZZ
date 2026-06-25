// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ValueCaptureMock {
    function getValues(uint256 x) external pure returns (uint256, uint256) {
        return (x + 100, x + 200);
    }
}

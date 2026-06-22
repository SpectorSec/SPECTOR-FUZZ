// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../../solidity_utils/lib.sol";

contract Overflow {
    uint256 public val1;
    uint256 public val2;

    function addToA(uint256 amount) external {
        uint256 old = val1;
        unchecked { val1 += amount; }
        if (val1 < old) bug();
    }

    function sub(uint256 amount) external {
        uint256 old = val2;
        unchecked { val2 -= amount; }
        if (val2 > old) bug();
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Minimal reentrancy-vulnerable contract mimicking the Barley Finance
// flash() -> deposit() pattern. The flash() function transfers tokens
// and calls back before checking repayment. Calling deposit() inside
// the callback re-deposits tokens into the contract, satisfying the
// balance check -- letting the attacker profit.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface ICallback {
    function onFlash(bytes calldata data) external;
}

contract ReentrancyFlash {
    address public token;

    event Deposit(address indexed user, uint256 amount);

    constructor(address _token) {
        token = _token;
    }

    function flash(uint256 amount, bytes calldata data) external {
        uint256 before = IERC20(token).balanceOf(address(this));
        require(IERC20(token).transfer(msg.sender, amount), "xfer out");

        // VULNERABILITY: callback before repayment check
        ICallback(msg.sender).onFlash(data);

        require(IERC20(token).balanceOf(address(this)) >= before, "not repaid");
    }

    function deposit(uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        emit Deposit(msg.sender, amount);
    }

    function name() public pure returns (string memory) { return "ReentrancyFlash"; }
    function symbol() public pure returns (string memory) { return "RFL"; }
}

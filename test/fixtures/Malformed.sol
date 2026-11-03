// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title VulnerableBank
/// @notice Intentionally vulnerable demo contract. Do not deploy.
contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalDeposits;
    uint256 public withdrawFeeBps = 50;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    this is not solidity !!!
    function deposit() external payable {
        require(msg.value > 0, "Nothing to deposit");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] = 0;
        totalDeposits -= amount;
        emit Withdrawn(msg.sender, amount);
    }

    function setWithdrawFee(uint256 newFeeBps) external {
        withdrawFeeBps = newFeeBps;
    }

    function transferOwnership(address newOwner) external {
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }

    function payout(address payable to, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        to.send(amount);
    }

    function closeBank() external {
        selfdestruct(payable(owner));
    }

    function bankBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

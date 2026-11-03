// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

contract Treasury {
    address public owner;
    uint256 public limit;

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function setLimit(uint256 newLimit) external {
        limit = newLimit;
    }

    function sweep() external {
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}

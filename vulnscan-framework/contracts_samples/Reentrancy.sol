// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

// Classic DAO-style reentrancy (SWC-107)
contract Reentrancy {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount);
        // external call BEFORE state update -> reentrancy
        msg.sender.call.value(_amount)();
        balances[msg.sender] -= _amount;
    }

    function () public payable {}
}

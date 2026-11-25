// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
// Reentrancy victim (SWC-107): external call before state update, no guard.
contract VulnerableBank {
    mapping(address => uint) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint bal = balances[msg.sender];
        require(bal > 0, "no balance");
        (bool ok, ) = msg.sender.call{value: bal}("");   // <-- reentrant point
        require(ok, "send failed");
        balances[msg.sender] = 0;                         // state update AFTER call
    }
    function totalBalance() external view returns (uint) { return address(this).balance; }
}

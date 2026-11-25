// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

// tx.origin authentication (SWC-115) + access control
contract TxOrigin {
    address owner;
    constructor() public { owner = msg.sender; }
    function transferTo(address dest, uint amount) public {
        require(tx.origin == owner); // phishable
        dest.transfer(amount);
    }
}

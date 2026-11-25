// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

// Unchecked low-level call return value (SWC-104)
contract UncheckedCall {
    function ping(address dst) public {
        dst.call(bytes4(keccak256("ping()"))); // return value ignored
    }
    function sendFunds(address dst, uint amount) public {
        dst.send(amount); // return value of send ignored
    }
}

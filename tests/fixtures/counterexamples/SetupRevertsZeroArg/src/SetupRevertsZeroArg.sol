// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract SetupRevertsZeroArg {
    bool public broken;
    function breakInvariant() external { broken = true; }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {SetupOnlyOwner} from "./src/SetupOnlyOwner.sol";

contract Setup {
    function run() external returns (address target) {
        target = address(new SetupOnlyOwner(address(0xA11CE)));
    }
}


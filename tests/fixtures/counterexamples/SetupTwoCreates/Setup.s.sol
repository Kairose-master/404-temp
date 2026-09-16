// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Dummy, SetupTwoCreates} from "./src/SetupTwoCreates.sol";
contract Setup {
    function run() external returns (address target) {
        new Dummy();
        target = address(new SetupTwoCreates());
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Helper, SetupHelperAfter} from "./src/SetupHelperAfter.sol";
contract Setup {
    function run() external returns (address target) {
        target = address(new SetupHelperAfter());
        new Helper();
    }
}

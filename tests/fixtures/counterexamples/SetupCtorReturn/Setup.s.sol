// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {SetupCtorReturn} from "./src/SetupCtorReturn.sol";
contract Setup {
    SetupCtorReturn private t;
    constructor() { t = new SetupCtorReturn(); }
    function run() external returns (address target) { target = address(t); }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
import {SetupRevertsZeroArg} from "./src/SetupRevertsZeroArg.sol";

contract Setup {
    function run() external returns (address) {
        SetupRevertsZeroArg target = new SetupRevertsZeroArg();
        // A manual constructor deployment would appear exploitable, but this
        // declared initial state never exists: the whole Setup transaction reverts.
        revert("SETUP_REVERT_SENTINEL");
    }
}

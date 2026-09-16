// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IMirageTokenView {
    function balanceOf(address who) external view returns (uint256);
}

interface IApprovalMirageView {
    function victim() external view returns (address);
    function token() external view returns (address);
    function INITIAL_BALANCE() external view returns (uint256);
}

contract Invariants {
    function victimBalanceIntact(address target) public view returns (bool) {
        IApprovalMirageView t = IApprovalMirageView(target);
        return IMirageTokenView(t.token()).balanceOf(t.victim()) == t.INITIAL_BALANCE();
    }

    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {
        if (!victimBalanceIntact(target)) return (false, "victimBalanceIntact");
        return (true, "");
    }
}


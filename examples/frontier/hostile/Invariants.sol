// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IDesk {
    function owner() external view returns (address);
    function admin() external view returns (address);
    function totalDeposits() external view returns (uint256);
}

/// ownerUnchanged — slot-padded hijack is the only way to flip owner.
/// houseAlive     — lottery drain or sweep is the only way to empty seed.
/// customerFunds  — CEI withdraw must keep this; sweep is what breaks it.
contract Invariants {
    function ownerUnchanged(address t) public view returns (bool) {
        return IDesk(t).owner() == IDesk(t).admin();
    }

    function houseAlive(address t) public view returns (bool) {
        return t.balance >= 1 ether;
    }

    function customerFunds(address t) public view returns (bool) {
        return t.balance >= IDesk(t).totalDeposits();
    }

    function checkAll(address t) external view returns (bool, string memory) {
        if (!ownerUnchanged(t)) return (false, "ownerUnchanged");
        if (!houseAlive(t)) return (false, "houseAlive");
        if (!customerFunds(t)) return (false, "customerFunds");
        return (true, "");
    }
}

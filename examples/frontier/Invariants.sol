// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IDual {
    function reserve0() external view returns (uint256);
    function reserve1() external view returns (uint256);
}

/// Two predicates, two labels.
///
///   ammBacked     — swap0to1 must preserve this. An arb that extracts ETH
///                   and still backs reserves is INTENDED_PATH, not a bug.
///   vaultSolvent  — seed/2 vault float must remain. Reentrant withdraw
///                   is the only honest-user-impossible way to break it.
///
/// checkAll reports the first failure. A theft that also empties the AMM
/// will trip vaultSolvent first (the one we grade as THEFT).
contract Invariants {
    uint256 constant SEED = 10 ether;

    function ammBacked(address t) public view returns (bool) {
        return t.balance >= IDual(t).reserve0() + IDual(t).reserve1();
    }

    function vaultSolvent(address t) public view returns (bool) {
        return t.balance >= SEED / 2;
    }

    function checkAll(address t) external view returns (bool, string memory) {
        if (!vaultSolvent(t)) return (false, "vaultSolvent");
        if (!ammBacked(t)) return (false, "ammBacked");
        return (true, "");
    }
}

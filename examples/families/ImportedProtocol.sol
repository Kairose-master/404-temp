// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: imported_protocol.
/// Bug: lending + AMM live in *other files* (or other deploys). This unit
/// only holds the interfaces and public refs. World/extra_sources must load
/// siblings; the exploit discovers pool()/lending() via auto-getters.
/// Invariant: deskSolvent.

interface IPool {
    function swap(uint256) external payable;
}

interface ILendingPool {
    function borrow(uint256) external payable;
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract ProtocolDesk {
    IERC20 public token;
    IPool public pool;
    ILendingPool public lending;

    constructor(address t, address p, address l) payable {
        token = IERC20(t);
        pool = IPool(p);
        lending = ILendingPool(l);
    }

    function borrow(uint256 n) external payable {
        lending.borrow{value: msg.value}(n);
        token.transfer(msg.sender, n);
    }
}

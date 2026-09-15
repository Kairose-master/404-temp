// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Canonical source: examples/frontier/DualSurface.sol
/// swap0to1 = intended path. withdraw = CEI theft. Same ETH pot.
contract DualSurface {
    uint256 public reserve0;
    uint256 public reserve1;
    mapping(address => uint256) public deposits;

    event Swapped(address indexed who, uint256 amountIn, uint256 amountOut);
    event Deposited(address indexed who, uint256 amount);
    event Withdrawn(address indexed who, uint256 amount);

    constructor() payable {
        uint256 seed = msg.value;
        require(seed >= 4, "seed");
        reserve0 = seed / 4;
        reserve1 = seed / 4;
    }

    function getPrice() public view returns (uint256) {
        return (reserve1 * 1e18) / reserve0;
    }

    function swap0to1() external payable {
        require(msg.value > 0, "zero");
        uint256 out = (msg.value * reserve1) / (reserve0 + msg.value);
        require(out > 0 && out < reserve1, "empty");
        reserve0 += msg.value;
        reserve1 -= out;
        (bool ok, ) = msg.sender.call{value: out}("");
        require(ok, "swap pay");
        emit Swapped(msg.sender, msg.value, out);
    }

    function deposit() external payable {
        require(msg.value > 0, "zero");
        deposits[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw() external {
        uint256 bal = deposits[msg.sender];
        require(bal > 0, "no balance");
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "vault pay");
        deposits[msg.sender] = 0;
        emit Withdrawn(msg.sender, bal);
    }

    receive() external payable {}
}

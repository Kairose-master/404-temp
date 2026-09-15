// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// DualSurface — one protocol, two economic surfaces.
///
/// This is the worked example for docs/FRONTIER.md.
///
///   swap0to1()   INTENDED_PATH  constant-product trade. Attacker can
///                               leave with more ETH. Invariants still hold.
///                               Profit-only agents (Verite/SCONE/A1) call
///                               this an exploit. It is the protocol.
///
///   withdraw()   THEFT          CEI-broken vault on the *same* ETH pot.
///                               Reenter before the debit, drain seed float
///                               and then the AMM reserves. vaultSolvent
///                               breaks. This one is a bug.
///
/// The point is not "here is a vault bug". It is that **the same contract
/// produces both labels**, so a revenue-only oracle cannot tell them apart
/// without the invariant. Engine classification:
///   classify(broken, Δ) → THEFT | GRIEF | INTENDED_PATH | NONE
///
/// Seed (constructor msg.value, default 10 ether) is split:
///   1/4 → reserve0, 1/4 → reserve1, 1/2 → vault float.
contract DualSurface {
    // ── AMM (designed extraction) ────────────────────────────────────────
    uint256 public reserve0;
    uint256 public reserve1;

    // ── Vault (unintended extraction) ────────────────────────────────────
    mapping(address => uint256) public deposits;

    event Swapped(address indexed who, uint256 amountIn, uint256 amountOut);
    event Deposited(address indexed who, uint256 amount);
    event Withdrawn(address indexed who, uint256 amount);

    constructor() payable {
        uint256 seed = msg.value;
        require(seed >= 4, "seed");
        reserve0 = seed / 4;
        reserve1 = seed / 4;
        // remainder is unallocated vault float; honest deposit/withdraw
        // never spends it.
    }

    function getPrice() public view returns (uint256) {
        return (reserve1 * 1e18) / reserve0;
    }

    /// @notice Constant-product swap. This is the protocol.
    /// Sending `msg.value` into reserve0 pays out `out` from reserve1.
    /// `ammBacked` is preserved: the vault float is untouched.
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

    /// @notice CEI violation. Debit happens *after* the external call.
    /// A reentrant `withdraw` reads the stale mapping and drains the pot
    /// (vault float, then AMM reserves). That is theft.
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

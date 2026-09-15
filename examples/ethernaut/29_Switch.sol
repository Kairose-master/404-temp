// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L29 · Switch — 고정 오프셋(68) 셀렉터 검사를 calldata 배치로 우회
contract Switch {
    bool public switchOn;
    bytes4 public offSelector = bytes4(keccak256("turnSwitchOff()"));
    modifier onlyThis() { require(msg.sender == address(this), "Only the contract can call this"); _; }
    modifier onlyOff() {
        bytes32[1] memory selector;
        assembly { calldatacopy(selector, 68, 4) }
        require(selector[0] == offSelector, "Can only call this function while the switch is off");
        _;
    }
    function flipSwitch(bytes memory _data) public onlyOff {
        (bool success, ) = address(this).call(_data);
        require(success, "call failed :(");
    }
    function turnSwitchOn() public onlyThis { switchOn = true; }
    function turnSwitchOff() public onlyThis { switchOn = false; }
}

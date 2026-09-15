// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L16 · Preservation — delegatecall 스토리지 충돌(정식 encodePacked+bytes4 constant 형태)
contract Preservation {
    address public timeZone1Library;
    address public timeZone2Library;
    address public owner;
    uint256 storedTime;
    bytes4 constant setTimeSignature = bytes4(keccak256("setTime(uint256)"));
    constructor(address _timeZone1LibraryAddress, address _timeZone2LibraryAddress) {
        timeZone1Library = _timeZone1LibraryAddress;
        timeZone2Library = _timeZone2LibraryAddress;
        owner = msg.sender;
    }
    function setFirstTime(uint256 _timeStamp) public {
        timeZone1Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp));
    }
    function setSecondTime(uint256 _timeStamp) public {
        timeZone2Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp));
    }
}
contract LibraryContract {
    uint256 storedTime;
    function setTime(uint256 _time) public { storedTime = _time; }
}

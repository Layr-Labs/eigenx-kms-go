// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract GetEigenBalance is Script {
    IERC20 public EIGEN_TOKEN = IERC20(0x0011FA2c512063C495f77296Af8d195F33A8Dd38);

    function setUp() public {}

    function run(address addr) public {
        uint256 eigenBalance = EIGEN_TOKEN.balanceOf(addr);
        console.log("Eigen Token Balance:", eigenBalance);

    }
}

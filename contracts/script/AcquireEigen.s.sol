// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract AcquireEigen is Script {
    // sepolia eigen
    IERC20 public EIGEN_TOKEN = IERC20(0x0011FA2c512063C495f77296Af8d195F33A8Dd38);

    function setUp() public {}

    function run(address toAddr) public {
        uint256 fromBalance = EIGEN_TOKEN.balanceOf(msg.sender);
        console.log("Eigen Token Balance:", fromBalance);
        console.log("Wanting to transfer     ", uint256(1000000e18));
        // account should be unlocked when calling script
        vm.startBroadcast();
        EIGEN_TOKEN.transfer(toAddr, 1000000e18); // send 1000 Eigen tokens to the specified address
        vm.stopBroadcast();

        uint256 toAddressBalance = EIGEN_TOKEN.balanceOf(toAddr);
        console.log("Eigen Token Balance of", toAddr, ":", toAddressBalance);

    }
}

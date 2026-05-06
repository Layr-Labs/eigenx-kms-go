// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {IAllocationManager} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import {IKeyRegistrar} from "@eigenlayer-contracts/src/contracts/interfaces/IKeyRegistrar.sol";
import {IPermissionController} from "@eigenlayer-contracts/src/contracts/interfaces/IPermissionController.sol";

import {EigenKMSRegistrar} from "../../src/EigenKMSRegistrar.sol";

contract UpgradeEigenKMSRegistrar is Script {
    // Eigenlayer Core Contracts
    IAllocationManager public ALLOCATION_MANAGER = IAllocationManager(0x42583067658071247ec8CE0A516A58f682002d07);
    IKeyRegistrar public KEY_REGISTRAR = IKeyRegistrar(0xA4dB30D08d8bbcA00D40600bee9F029984dB162a);
    IPermissionController public PERMISSION_CONTROLLER = IPermissionController(0x44632dfBdCb6D3E21EF613B0ca8A6A0c618F5a37);

    function setUp() public {}

    function run(
        address proxy,
        address proxyAdmin
    ) public {
        uint256 avsPrivateKey = vm.envUint("PRIVATE_KEY_AVS");
        address avs = vm.addr(avsPrivateKey);

        console.log("Upgrading EigenKMSRegistrar...");
        console.log("AVS (ProxyAdmin owner):", avs);
        console.log("Proxy:", proxy);
        console.log("ProxyAdmin:", proxyAdmin);

        vm.startBroadcast(avsPrivateKey);

        // Deploy new implementation
        EigenKMSRegistrar newImpl = new EigenKMSRegistrar(ALLOCATION_MANAGER, KEY_REGISTRAR, PERMISSION_CONTROLLER);
        console.log("New implementation deployed to:", address(newImpl));

        // Upgrade proxy to new implementation (no reinitialize call)
        ProxyAdmin(proxyAdmin).upgradeAndCall(
            ITransparentUpgradeableProxy(proxy),
            address(newImpl),
            ""
        );
        console.log("Proxy upgraded successfully");

        vm.stopBroadcast();

        console.log("\n=== Upgrade Summary ===");
        console.log("Proxy (unchanged):", proxy);
        console.log("New Implementation:", address(newImpl));
        console.log("=======================\n");
    }
}

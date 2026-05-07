// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {EigenKMSCommitmentRegistry} from "../../src/EigenKMSCommitmentRegistry.sol";

contract UpgradeEigenKMSCommitmentRegistry is Script {
    function setUp() public {}

    function run(
        address proxy,
        address proxyAdmin
    ) public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY_DEPLOYER");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Upgrading EigenKMSCommitmentRegistry...");
        console.log("Deployer (ProxyAdmin owner):", deployer);
        console.log("Proxy:", proxy);
        console.log("ProxyAdmin:", proxyAdmin);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy new implementation
        EigenKMSCommitmentRegistry newImpl = new EigenKMSCommitmentRegistry();
        console.log("New implementation deployed to:", address(newImpl));

        // Upgrade proxy to new implementation
        ProxyAdmin(proxyAdmin).upgrade(
            ITransparentUpgradeableProxy(proxy),
            address(newImpl)
        );
        console.log("Proxy upgraded successfully");

        vm.stopBroadcast();

        console.log("\n=== Upgrade Summary ===");
        console.log("Proxy (unchanged):", proxy);
        console.log("New Implementation:", address(newImpl));
        console.log("=======================\n");
    }
}
